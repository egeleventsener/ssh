#include "ssh_wrap.h"
#include <libssh2.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #pragma comment(lib, "ws2_32.lib")
#else
  #include <arpa/inet.h>
  #include <netdb.h>
  #include <sys/socket.h>
  #include <unistd.h>
  #define closesocket close
#endif

struct ssh_ctx {
    int sock;
    LIBSSH2_SESSION *sess;
    LIBSSH2_CHANNEL *chan;
};

static ssh_ctx *NET = NULL;

static int tcp_connect(const char *host, int port){
    char portstr[16]; snprintf(portstr, sizeof portstr, "%d", port);
    struct addrinfo hints; memset(&hints, 0, sizeof hints);
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo *res = NULL, *rp = NULL;
    if(getaddrinfo(host, portstr, &hints, &res)!=0) return -1;
    int s = -1;
    for(rp=res; rp; rp=rp->ai_next){
        s = (int)socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if(s < 0) continue;
        if(connect(s, rp->ai_addr, rp->ai_addrlen) == 0) break;
        closesocket(s); s = -1;
    }
    freeaddrinfo(res);
    return s;
}

static void hostkey_fingerprint_sha1(LIBSSH2_SESSION *s, unsigned char out[20]){
    const unsigned char *p = libssh2_hostkey_hash(s, LIBSSH2_HOSTKEY_HASH_SHA1);
    if(!p){ memset(out, 0, 20); return; }
    memcpy(out, p, 20);
}

ssh_ctx* ssh_open(const ssh_opts *o){
#ifdef _WIN32
    WSADATA w; WSAStartup(MAKEWORD(2,2), &w);
#endif
    if(LIBSSH2_INIT_SUCCESS != libssh2_init(0)) return NULL;
    int sock = tcp_connect(o->host, o->port);
    if(sock < 0) { libssh2_exit(); return NULL; }
    LIBSSH2_SESSION *sess = libssh2_session_init();
    if(!sess){ closesocket(sock); libssh2_exit(); return NULL; }
    libssh2_session_set_blocking(sess, 1);
    if(libssh2_session_handshake(sess, sock)){
        libssh2_session_free(sess); closesocket(sock); libssh2_exit();
        return NULL;
    }
    unsigned char fp[20];
    hostkey_fingerprint_sha1(sess, fp);
    static const unsigned char expected_fp[20] = {
        0xf2,0xf2,0x64,0xec,0x92,
        0x28,0x5e,0x81,0x97,0x0a,
        0x45,0x41,0x57,0x59,0x5c,
        0x57,0x63,0xc4,0x73,0xe6
    };
    if(memcmp(fp, expected_fp, 20) != 0){
        fprintf(stderr, "[!] Host key mismatch (SHA1)\n");
        libssh2_session_disconnect(sess, "bad hostkey");
        libssh2_session_free(sess); closesocket(sock); libssh2_exit();
#ifdef _WIN32
        WSACleanup();
#endif
        return NULL;
    }
    int rc = -1;
    if(o->pkey_path){
        rc = libssh2_userauth_publickey_fromfile(sess, o->user,
                                                 NULL, o->pkey_path,
                                                 o->pkey_pass ? o->pkey_pass : "");
    } else if(o->password){
        rc = libssh2_userauth_password(sess, o->user, o->password);
    }
    if(rc){
        fprintf(stderr, "[!] Auth failed\n");
        libssh2_session_disconnect(sess, "auth failed");
        libssh2_session_free(sess); closesocket(sock); libssh2_exit();
#ifdef _WIN32
        WSACleanup();
#endif
        return NULL;
    }
    LIBSSH2_CHANNEL *chan = libssh2_channel_direct_tcpip_ex(
        sess, o->dst_host, o->dst_port, "127.0.0.1", 0);
    if(!chan){
        fprintf(stderr, "[!] Channel open failed\n");
        libssh2_session_disconnect(sess, "no channel");
        libssh2_session_free(sess); closesocket(sock); libssh2_exit();
#ifdef _WIN32
        WSACleanup();
#endif
        return NULL;
    }
    ssh_ctx *ctx = (ssh_ctx*)calloc(1, sizeof *ctx);
    ctx->sock  = sock;
    ctx->sess  = sess;
    ctx->chan  = chan;
    return ctx;
}

void ssh_close(ssh_ctx *c){
    if(!c) return;
    if(c->chan){ libssh2_channel_close(c->chan); libssh2_channel_free(c->chan); }
    if(c->sess){ libssh2_session_disconnect(c->sess, "bye"); libssh2_session_free(c->sess); }
    if(c->sock >= 0) closesocket(c->sock);
    free(c);
    libssh2_exit();
#ifdef _WIN32
    WSACleanup();
#endif
}

ssize_t ssh_send(ssh_ctx *c, const void *buf, size_t n){
    if(!c || !c->chan) return -1;
    return (ssize_t)libssh2_channel_write(c->chan, (const char*)buf, n);
}
ssize_t ssh_recv(ssh_ctx *c, void *buf, size_t n){
    if(!c || !c->chan) return -1;
    return (ssize_t)libssh2_channel_read(c->chan, (char*)buf, n);
}

int net_init_ssh(const ssh_opts *o){
    NET = ssh_open(o);
    return NET ? 0 : -1;
}
void net_close(void){
    ssh_close(NET);
    NET = NULL;
}
ssize_t net_send(const void *buf, size_t n){
    return ssh_send(NET, buf, n);
}
ssize_t net_recv(void *buf, size_t n){
    return ssh_recv(NET, buf, n);
}

ssize_t net_send_all(const void *buf, size_t n){
    const char *p = (const char*)buf;
    size_t left = n;
    while(left > 0){
        ssize_t k = net_send(p, left);
        if(k <= 0) return -1;
        p += k; left -= (size_t)k;
    }
    return (ssize_t)n;
}

ssize_t net_recv_exact(void *buf, size_t n){
    char *p = (char*)buf;
    size_t got = 0;
    while(got < n){
        ssize_t k = net_recv(p + got, n - got);
        if(k < 0) return -1;
        if(k == 0) return 0;
        got += (size_t)k;
    }
    return (ssize_t)got;
}

ssize_t net_recv_line(char *buf, size_t cap){
    size_t i = 0;
    while(i + 1 < cap){
        ssize_t k = net_recv(buf + i, 1);
        if(k < 0) return -1;
        if(k == 0) break;
        if(buf[i] == '\n'){ buf[i+1] = '\0'; return (ssize_t)(i+1); }
        i += 1;
    }
    buf[i] = '\0';
    return (ssize_t)i;
}
