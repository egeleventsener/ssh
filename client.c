#include "delete_directory.h"
#include <stdio.h>
#include <string.h>
#include "ssh_wrap.h"
#include <dirent.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <errno.h>
#include <inttypes.h>


#ifndef PATH_MAX
#define PATH_MAX 4096
#endif
#define BUF_SIZE 1024
#ifdef _WIN32
  #define CLOSESOCK closesocket
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #include <windows.h>
  static void sleep_seconds(unsigned sec) { Sleep(sec * 1000); }
  static void log_sock_err(const char* msg) { fprintf(stderr, "%s (WSAGetLastError=%ld)\n", msg, (long)WSAGetLastError()); }
  #ifndef strncasecmp
  #define strncasecmp _strnicmp
  #endif
#else
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
  #define CLOSESOCK close
  static void sleep_seconds(unsigned sec) { sleep(sec); }
  static void log_sock_err(const char* msg) { perror(msg); }
#endif

static int send_all(int s, const void *b, size_t n){
    const char *p = (const char*)b; size_t off=0;
    while(off<n){ int r = send(s, p+off, (int)(n-off), 0); if(r<=0) return -1; off += (size_t)r; }
    return 0;
}

static int send_file_with_size(FILE *fp, int sock, const char *srcpath){
    long long fsz = 0;
#ifdef _WIN32
    struct _stati64 st; if (_stati64(srcpath, &st)!=0) return -1; fsz = (long long)st.st_size;
#else
    struct stat st; if (stat(srcpath, &st)!=0) return -1; fsz = (long long)st.st_size;
#endif
    char hdr[64]; int m = snprintf(hdr, sizeof(hdr), "SIZE %lld\n", fsz);
    if (m<=0 || send_all(sock, hdr, (size_t)m)<0) return -1;

    char buf[BUF_SIZE]; size_t r;
    while((r=fread(buf,1,sizeof(buf),fp))>0){
        if(send_all(sock, buf, r)<0) return -1;
    }
    return 0;
}

static const char* path_basename(const char* p){
    const char *b = p, *s;
    for (s = p; *s; ++s) if (*s=='/' || *s=='\\') b = s+1;
    return b;
}
static int is_dir_path(const char *p){
    struct stat st;
    return (stat(p, &st) == 0 && S_ISDIR(st.st_mode));
}
static void join_path(char *out, size_t sz, const char *dir, const char *base){
    size_t n = snprintf(out, sz, "%s", dir);
    if (n >= sz) { out[sz-1] = '\0'; return; }
    char sep = (strchr(dir,'\\') && !strchr(dir,'/')) ? '\\' : '/';
    if (n > 0 && out[n-1] != sep) { out[n++] = sep; out[n] = '\0'; }
    strncat(out, base, sz - strlen(out) - 1);
}
static void local_pwd(void){
    char cwd[PATH_MAX];
    if (getcwd(cwd, sizeof(cwd))) printf("%s\n", cwd);
    else perror("pwd");
}
static void local_cd(const char *path){
    if (!path || !*path) { fprintf(stderr, "cd: missing path\n"); return; }
    if (chdir(path) != 0) perror("cd");
}
static void local_ls(void){
    DIR *d = opendir(".");
    if (!d) { perror("ls"); return; }
    struct dirent *e; int count=0;
    while ((e=readdir(d))){
        if (!strcmp(e->d_name,".") || !strcmp(e->d_name,"..")) continue;
        puts(e->d_name); count++;
    }
    if (!count) puts("(empty)");
    closedir(d);
}
static void local_mkdir(const char *name){
    if (!name||!*name){ fprintf(stderr,"mkdir: missing name\n"); return; }
#ifdef _WIN32
    if (mkdir(name)!=0) perror("mkdir");
#else
    if (mkdir(name, 0777)!=0) perror("mkdir");
#endif
}

static void local_rm(const char *path){
    if (!path||!*path){ fprintf(stderr,"rm: missing path\n"); return; }
    if (!strcmp(path,"/")){ fprintf(stderr,"rm: refusing to delete '/'\n"); return; }
    if (delete_directory(path)!=0) fprintf(stderr,"rm: failed\n");
}
static int local_copy_file(const char *src, const char *dst){
    FILE *in=fopen(src,"rb"); if(!in){perror("open src"); return -1;}
    FILE *out=fopen(dst,"wb"); if(!out){perror("open dst"); fclose(in); return -1;}
    char buf[BUF_SIZE]; size_t r;
    while((r=fread(buf,1,sizeof(buf),in))>0){
        if(fwrite(buf,1,r,out)!=r){perror("write dst"); fclose(in); fclose(out); return -1;}
    }
    fclose(in); fclose(out); return 0;
}
static void send_file_chunks(FILE *fp, int sockfd) {
    char data[BUF_SIZE];
    size_t n;
    while ((n = fread(data, 1, sizeof(data), fp)) > 0) {
        ssize_t sent = send(sockfd, data, n, 0);
        if (sent < 0) { perror("send file chunk"); return; }
    }
    if (send(sockfd, "EOF", 3, 0) < 0) perror("send EOF");
}

static const char* path_basename_safe(const char *p){
    const char *s=p,*a=p; for(;*s;++s) if(*s=='/'||*s=='\\') a=s+1; return a;
}
static const char* path_basename_safe(const char *p){
                const char *s=p,*a=p;
                for(;*s;++s) if(*s=='/'||*s=='\\') a=s+1;
                return a;
            }

static int send_file_with_size_net(FILE *fp, const char *src) {
    struct stat st;
    if (stat(src, &st) != 0) return -1;
    int64_t size = (int64_t)st.st_size;

    char sizestr[64];
    int m = snprintf(sizestr, sizeof sizestr, "%" PRId64 "\n", size);
    if (m <= 0) return -1;
    if (net_send_all(sizestr, (size_t)m) < 0) return -1;

    unsigned char buf[64*1024];
    size_t n;
    while ((n = fread(buf, 1, sizeof buf, fp)) > 0) {
        if (net_send_all(buf, n) < 0) return -1;
    }
    return ferror(fp) ? -1 : 0;
}

int main() {
    char buffer[1000];

    ssh_opts o = {
        .host     = "192.168.0.172",   
        .port     = 22,
        .user     = "ege",             
        .password = "211221",
        .pkey_path= NULL, 
        .pkey_pass= NULL,
        .dst_host = "127.0.0.1",       
        .dst_port = 5000               
    };

    if (net_init_ssh(&o) != 0) {
        fprintf(stderr, "SSH baglanti kurulamadi\n");
        return 1;
    }
    printf("Connected over SSH.\n");

    for (;;) {
        printf("\nEnter command: ");
        if (!fgets(buffer, sizeof(buffer), stdin)) break;
        buffer[strcspn(buffer, "\n")] = 0;

        if (!strcmp(buffer, "exit")) { printf("Closing connection...\n"); break; }

        if (!strcmp(buffer, "pwd")) { local_pwd(); continue; }
        if (!strncmp(buffer, "cd ", 3)) { local_cd(buffer+3); continue; }
        if (!strcmp(buffer, "ls")) { local_ls(); continue; }
        if (!strncmp(buffer, "mkdir ", 6)) { local_mkdir(buffer+6); continue; }
        if (!strncmp(buffer, "rm ", 3)) { local_rm(buffer+3); continue; }

        if (!strncmp(buffer, "send_file", 9)) {
            char src[PATH_MAX], mode[16], dest[PATH_MAX];

            if (buffer[9] == ' ' && buffer[10] != '\0') {
                strncpy(src, buffer + 10, sizeof(src)-1); src[sizeof(src)-1] = '\0';
            } else {
                printf("Enter full path of file to send: ");
                if (!fgets(src, sizeof(src), stdin)) { perror("fgets"); continue; }
                src[strcspn(src, "\n")] = 0;
            }

            printf("Target (server/local): ");
            if (!fgets(mode, sizeof(mode), stdin)) { perror("fgets"); continue; }
            mode[strcspn(mode, "\n")] = 0;

            if (!strncasecmp(mode, "local", 5)) {
                printf("Enter destination path on client: ");
                if (!fgets(dest, sizeof(dest), stdin)) { perror("fgets"); continue; }
                dest[strcspn(dest, "\n")] = 0;

                int treat_as_dir = 0;
                size_t dl = strlen(dest);
                if (dl && (dest[dl-1]=='/' || dest[dl-1]=='\\')) treat_as_dir = 1;
                if (!treat_as_dir && is_dir_path(dest)) treat_as_dir = 1;

                char finaldst[PATH_MAX];
                if (treat_as_dir) join_path(finaldst, sizeof(finaldst), dest, path_basename(src));
                else { strncpy(finaldst, dest, sizeof(finaldst)-1); finaldst[sizeof(finaldst)-1] = '\0'; }

                if (local_copy_file(src, finaldst) == 0) printf("Local copy OK: %s\n", finaldst);
                else printf("Local copy FAILED\n");
                continue;
            }

            printf("Enter destination directory on server (e.g., . or uploads): ");
            if (!fgets(dest, sizeof(dest), stdin)) { perror("fgets"); continue; }
            dest[strcspn(dest, "\n")] = 0;

            FILE *fp = fopen(src, "rb");
            if (!fp) { perror("open file"); continue; }

            if (dest[0] != '\0' && !(dest[0]=='.' && dest[1]=='\0')) {
                char scd[PATH_MAX+8];
                int m = snprintf(scd, sizeof(scd), "scd %s", dest);
                if (m > 0) {
                    if (net_send_all(scd, (size_t)m) < 0 || net_send_all("\n", 1) < 0) { perror("send scd"); fclose(fp); continue; }
                }
            }

            if (net_send_all("write_file\n", 11) < 0) { perror("send write_file"); fclose(fp); continue; }

            const char *fname = path_basename(src);
            if (net_send_all(fname, strlen(fname)) < 0 || net_send_all("\n", 1) < 0) {
                perror("send filename"); fclose(fp); continue;
            }
            
            if (send_file_with_size_net(fp, src) < 0) { perror("send file"); fclose(fp); continue; }
            fclose(fp);

            char resp[256] = {0};
            ssize_t r = net_recv(resp, sizeof(resp)-1);
            if (r > 0) { resp[r] = '\0'; printf("Server: %s", resp); }
            continue;
        }

        if (net_send_all(buffer, strlen(buffer)) < 0 || net_send_all("\n", 1) < 0) {
            perror("send"); continue;
        }

        char reply[BUF_SIZE] = {0};
        ssize_t n = net_recv(reply, sizeof(reply)-1);
        if (n > 0) {
            reply[n] = '\0';
            printf("Server: %s", reply);
            if (reply[n-1] != '\n') printf("\n");
        } else if (n == 0) {
            printf("Server disconnected\n");
            break;
        } else {
            perror("recv");
            break;
        }
    }

    net_close();
    return 0;
}
