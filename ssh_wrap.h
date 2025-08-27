#pragma once
#include <stddef.h>
#include <stdint.h>

typedef struct ssh_ctx ssh_ctx;

typedef struct {
    const char *host;
    int         port;
    const char *user;
    const char *password;
    const char *pkey_path;
    const char *pkey_pass;
    const char *dst_host;
    int         dst_port;
} ssh_opts;

ssh_ctx* ssh_open(const ssh_opts *opts);
void     ssh_close(ssh_ctx *c);
ssize_t  ssh_send(ssh_ctx *c, const void *buf, size_t n);
ssize_t  ssh_recv(ssh_ctx *c, void *buf, size_t n);

int      net_init_ssh(const ssh_opts *opts);
void     net_close(void);
ssize_t  net_send(const void *buf, size_t n);
ssize_t  net_recv(void *buf, size_t n);

ssize_t  net_send_all(const void *buf, size_t n);
ssize_t  net_recv_exact(void *buf, size_t n);
ssize_t  net_recv_line(char *buf, size_t cap);
