#include <openssl/ssl.h>
#include <openssl/err.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>

int main() {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    const SSL_METHOD *method = TLSv1_2_server_method();

    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    // Load server certificate
    if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    // Load server private key
    if (SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    // Verify private key matches the certificate
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Private key does NOT match the certificate public key\n");
        return 1;
    }

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        return 1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(4433);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        return 1;
    }

    if (listen(sock, 1) < 0) {
        perror("listen");
        return 1;
    }

    printf("Listening on port 4433 for TLS 1.2 connections...\n");

    while (1) {
        int client = accept(sock, NULL, NULL);
        if (client < 0) {
            perror("accept");
            continue;
        }

        SSL *ssl = SSL_new(ctx);
        if (!ssl) {
            ERR_print_errors_fp(stderr);
            close(client);
            continue;
        }

        SSL_set_fd(ssl, client);

        // Enable secure renegotiation by allowing client renegotiation
        SSL_set_options(ssl, SSL_OP_ALLOW_CLIENT_RENEGOTIATION);

        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            SSL_free(ssl);
            close(client);
            continue;
        }

        printf("TLS 1.2 connection established with renegotiation enabled.\n");

        char buf[1024] = {0};
        int len = SSL_read(ssl, buf, sizeof(buf) - 1);
        if (len > 0) {
            printf("Received: %s\n", buf);
            SSL_write(ssl, buf, len);
        }

        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client);
    }

    close(sock);
    SSL_CTX_free(ctx);
    return 0;
}
