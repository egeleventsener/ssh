#define _GNU_SOURCE
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include "delete_directory.h"

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

static char BASE_DIR[PATH_MAX] = {0};
static char START_DIR[PATH_MAX] = {0};

static int starts_with(const char* s, const char* p) {
    return strncmp(s, p, strlen(p)) == 0;
}

static int secure_path_in_base(const char* path) {
    char canon[PATH_MAX];
    if (!realpath(path, canon)) return 0;
    size_t b = strlen(BASE_DIR);
    return (strncmp(canon, BASE_DIR, b) == 0) && (canon[b] == '/' || canon[b] == '\0');
}

static int secure_cd(const char *target) {
    if (!target || !*target) return -1;
    char tmp[PATH_MAX];
    if (target[0] == '/') {
        snprintf(tmp, sizeof(tmp), "%s%s", BASE_DIR, target);
    } else {
        if (!getcwd(tmp, sizeof(tmp))) return -1;
        size_t len = strlen(tmp);
        if (len + 1 < sizeof(tmp)) {
            tmp[len] = '/';
            tmp[len+1] = '\0';
        }
        strncat(tmp, target, sizeof(tmp) - strlen(tmp) - 1);
    }
    char canon[PATH_MAX];
    if (!realpath(tmp, canon)) return -1;
    if (!secure_path_in_base(canon)) return -1;
    if (chdir(canon) != 0) return -1;
    return 0;
}

static void send_str(int c, const char* s) {
    send(c, s, strlen(s), 0);
}

static int recv_line(int c, char *buf, size_t bufsz){
    size_t u = 0;
    while (u + 1 < bufsz) {
        char ch; ssize_t r = recv(c, &ch, 1, 0);
        if (r <= 0) return -1;           
        if (ch == '\n') { buf[u] = '\0'; return (int)u; }
        if (ch != '\r') buf[u++] = ch;   
    }
    buf[bufsz-1] = '\0';
    return (int)u;
}

static int recv_n_to_file(int c, const char* fname, long long nbytes){
    FILE *fp = fopen(fname, "wb");
    if (!fp) return -1;
    char buf[4096];
    long long left = nbytes;
    while (left > 0){
        ssize_t r = recv(c, buf, (left > (long long)sizeof(buf)) ? sizeof(buf) : (size_t)left, 0);
        if (r <= 0){ fclose(fp); return -1; }
        if (fwrite(buf,1,(size_t)r,fp)!=(size_t)r){ fclose(fp); return -1; }
        left -= r;
    }
    fclose(fp);
    return 0;
}


static int recv_until_eof_to_file(int c, const char* fname) {
    FILE *fp = fopen(fname, "wb");
    if (!fp) return -1;
    char buf[1024];
    for (;;) {
        ssize_t n = recv(c, buf, sizeof(buf), 0);
        if (n <= 0) { fclose(fp); return -1; }
        if (n == 3 && memcmp(buf, "EOF", 3) == 0) {
            break;
        }
        if (fwrite(buf, 1, n, fp) != (size_t)n) {
            fclose(fp);
            return -1;
        }
    }
    fclose(fp);
    return 0;
}

static void handle_command(int client, char *cmdline) {
    if (strcmp(cmdline, "spwd") == 0) {
        char cwd[PATH_MAX];
        if (getcwd(cwd, sizeof(cwd))) {
            if (starts_with(cwd, BASE_DIR)) {
                const char *rel = cwd + strlen(BASE_DIR);
                if (*rel == '\0') rel = "/";
                dprintf(client, "%s\n", rel);
            } else {
                dprintf(client, "%s\n", cwd);
            }
        } else {
            send_str(client, "pwd fail\n");
        }
        return;
    }
    if (strncmp(cmdline, "scd ", 4) == 0) {
        const char *arg = cmdline + 4;
        if (secure_cd(arg) == 0) send_str(client, "Directory changed\n");
        else send_str(client, "Directory change failed\n");
        return;
    }
    if (strcmp(cmdline, "sls") == 0) {
        DIR *d = opendir(".");
        if (!d) { send_str(client, "ls: cannot open directory\n"); return; }
        struct dirent *e;
        int count = 0;
        while ((e = readdir(d))) {
            if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
            dprintf(client, "%s\n", e->d_name);
            count++;
        }
        closedir(d);
        if (!count) send_str(client, "(empty)\n");
        return;
    }
    if (strncmp(cmdline, "smkdir ", 7) == 0) {
        const char *name = cmdline + 7;
        if (mkdir(name, 0777) == 0) send_str(client, "Directory created\n");
        else send_str(client, "Failed to create directory\n");
        return;
    }
    if (strncmp(cmdline, "srm ", 4) == 0) {
        const char *path = cmdline + 4;
        char canon[PATH_MAX];
        if (!realpath(path, canon) || !secure_path_in_base(canon)) {
            send_str(client, "Failed to delete\n");
            return;
        }
        if (delete_directory(canon) == 0) send_str(client, "Deleted\n");
        else send_str(client, "Failed to delete\n");
        return;
    }
    if (strncmp(cmdline, "srename ", 8) == 0) {
        char tmp[PATH_MAX * 2 + 16];
        strncpy(tmp, cmdline + 8, sizeof(tmp)-1);
        tmp[sizeof(tmp)-1] = '\0';
        char *oldn = strtok(tmp, " \t\r\n");
        char *newn = strtok(NULL, " \t\r\n");
        if (oldn && newn) {
            char c1[PATH_MAX], c2[PATH_MAX];
            if (realpath(oldn, c1) && realpath(newn, c2) &&
                secure_path_in_base(c1) && secure_path_in_base(c2) &&
                rename(c1, c2) == 0) {
                send_str(client, "Renamed\n");
            } else {
                send_str(client, "Rename failed\n");
            }
        } else send_str(client, "Invalid rename command\n");
        return;
    }
    if (strcmp(cmdline, "write_file") == 0) {
        char fname[PATH_MAX];
        if (recv_line(client, fname, sizeof(fname)) < 0 || fname[0] == '\0') {
            send_str(client, "filename error\n");
            return;
        }
        char sizeln[128];
        if (recv_line(client, sizeln, sizeof(sizeln)) < 0) {
            send_str(client, "size error\n");
            return;
        }
        long long fsz = -1;
        if (sscanf(sizeln, "SIZE %lld", &fsz) != 1 || fsz < 0) {
            send_str(client, "bad size\n");
            return;
        }
        if (recv_n_to_file(client, fname, fsz) == 0) send_str(client, "OK\n");
        else send_str(client, "FAIL\n");
        return;
}

    send_str(client, "Unknown command\n");
}

int main(void) {
    if (!getcwd(START_DIR, sizeof(START_DIR))) {
        perror("getcwd"); return 1;
    }
    {
        char canon[PATH_MAX];
        if (realpath(START_DIR, canon)) {
            strncpy(BASE_DIR, canon, sizeof(BASE_DIR)-1);
            BASE_DIR[sizeof(BASE_DIR)-1] = '\0';
        } else {
            strncpy(BASE_DIR, START_DIR, sizeof(BASE_DIR)-1);
            BASE_DIR[sizeof(BASE_DIR)-1] = '\0';
        }
    }
    int srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0) { perror("socket"); return 1; }
    int opt=1; setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(5000);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(srv, (struct sockaddr*)&addr, sizeof(addr)) < 0) { perror("bind"); return 1; }
    if (listen(srv, 8) < 0) { perror("listen"); return 1; }
    printf("Server listening on 0.0.0.0:5000\nBASE_DIR (jail): %s\n", BASE_DIR);
    for (;;) {
        struct sockaddr_in cli; socklen_t cl = sizeof(cli);
        int c = accept(srv, (struct sockaddr*)&cli, &cl);
        if (c < 0) { perror("accept"); continue; }
        printf("Client connected.\n");

        char line[2048];  
        for (;;) {
            int r = recv_line(c, line, sizeof(line));
            if (r <= 0) { printf("Client disconnected.\n"); break; }
            if (line[0] == '\0') { send_str(c, "Empty command\n"); continue; }
            printf("[DBG] cmd='%s'\n", line);
            fflush(stdout);
            handle_command(c, line);   
    }
    close(c);
}

    close(srv);
    return 0;
}