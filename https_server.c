/*
 * https_server.c - minimal TLS/HTTPS server
 *
 * Build:  gcc -o https_server https_server.c -lssl -lcrypto
 * Certs:  openssl req -x509 -newkey rsa:4096 -keyout key.pem \
 *                 -out cert.pem -days 365 -nodes
 * Run:    ./https_server 8443
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#define BACKLOG     10
#define BUFSIZE     4096
#define CERT_FILE   "cert.pem"
#define KEY_FILE    "key.pem"

/* reap dead child processes */
static void sigchld_handler(int s)
{
    (void)s;
    int saved = errno;
    while (waitpid(-1, NULL, WNOHANG) > 0)
        ;
    errno = saved;
}

/* pull IPv4 or IPv6 address out of a sockaddr */
static void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET)
        return &((struct sockaddr_in *)sa)->sin_addr;
    return &((struct sockaddr_in6 *)sa)->sin6_addr;
}

static SSL_CTX *create_ssl_ctx(void)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

    if (SSL_CTX_use_certificate_file(ctx, CERT_FILE, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "cert/key mismatch\n");
        exit(EXIT_FAILURE);
    }

    return ctx;
}

/* send a bare-bones HTTP/1.1 response over TLS */
static void handle_request(SSL *ssl)
{
    char buf[BUFSIZE];
    int  n = SSL_read(ssl, buf, sizeof(buf) - 1);
    if (n <= 0)
        return;
    buf[n] = '\0';

    const char *body =
        "<!DOCTYPE html><html><head><title>hello</title></head>"
        "<body><h1>it works</h1></body></html>\r\n";

    char response[BUFSIZE];
    int  rlen = snprintf(response, sizeof(response),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "\r\n"
        "%s",
        strlen(body), body);

    SSL_write(ssl, response, rlen);
}

int main(int argc, char *argv[])
{
    if (argc != 2) {
        fprintf(stderr, "usage: %s <port>\n", argv[0]);
        return 1;
    }

    SSL_CTX *ctx = create_ssl_ctx();

    struct addrinfo hints = {0};
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags    = AI_PASSIVE;

    struct addrinfo *res;
    int gai;
    if ((gai = getaddrinfo(NULL, argv[1], &hints, &res)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(gai));
        return 1;
    }

    /* bind to the first usable result */
    int sockfd = -1;
    struct addrinfo *p;
    for (p = res; p; p = p->ai_next) {
        sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sockfd < 0) continue;

        int yes = 1;
        setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);

        if (bind(sockfd, p->ai_addr, p->ai_addrlen) < 0) {
            close(sockfd);
            continue;
        }
        break;
    }
    freeaddrinfo(res);

    if (!p) {
        fprintf(stderr, "failed to bind\n");
        return 1;
    }

    if (listen(sockfd, BACKLOG) < 0) {
        perror("listen");
        return 1;
    }

    struct sigaction sa = {0};
    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sigaction(SIGCHLD, &sa, NULL);

    printf("listening on port %s\n", argv[1]);

    for (;;) {
        struct sockaddr_storage client_addr;
        socklen_t addrlen = sizeof client_addr;

        int newfd = accept(sockfd, (struct sockaddr *)&client_addr, &addrlen);
        if (newfd < 0) {
            perror("accept");
            continue;
        }

        char s[INET6_ADDRSTRLEN];
        inet_ntop(client_addr.ss_family,
                  get_in_addr((struct sockaddr *)&client_addr),
                  s, sizeof s);

        if (fork() == 0) {
            close(sockfd);

            SSL *ssl = SSL_new(ctx);
            SSL_set_fd(ssl, newfd);

            if (SSL_accept(ssl) <= 0) {
                ERR_print_errors_fp(stderr);
            } else {
                printf("connection from %s  cipher: %s\n",
                       s, SSL_get_cipher(ssl));
                handle_request(ssl);
            }

            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(newfd);
            SSL_CTX_free(ctx);
            exit(0);
        }

        close(newfd);
    }

    SSL_CTX_free(ctx);
    return 0;
}
