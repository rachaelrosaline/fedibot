#include <stdio.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#define MASTODON "rosaline.systems:443"

void conn(SSL *s) {
    int n = SSL_connect(s);
    if(n < 1) {
        char *e;
        fprintf(stderr, "SSL_connect error: ");
        int o = SSL_get_error(s, n);
        unsigned long p;
        switch(o) {
            case SSL_ERROR_NONE:
                fprintf(stderr, "success\n");
                break;
            case SSL_ERROR_ZERO_RETURN:
                fprintf(stderr, "ssl proto closure alert\n");
                break;
            case SSL_ERROR_WANT_READ:
                fprintf(stderr, "awaiting read\n");
                break;
            case SSL_ERROR_WANT_WRITE:
                fprintf(stderr, "awaiting write\n");
                break;
            case SSL_ERROR_WANT_CONNECT:
                fprintf(stderr, "awaiting connect\n");
                break;
            case SSL_ERROR_WANT_ACCEPT:
                fprintf(
                    stderr,
                    "awaiting accept despite using a connect BIO\n"
                );
                break;
            case SSL_ERROR_WANT_X509_LOOKUP:
                fprintf(stderr, "awaiting x509 lookup\n");
                break;
            case SSL_ERROR_SYSCALL:
                p = ERR_get_error();
                if(p == 0) {
                    switch(n) {
                        case 0:
                            fprintf(stderr, "invalid EOF\n");
                            break;
                        case -1:
                            fprintf(stderr, "I/O error\n");
                            break;
                        default:
                            fprintf( stderr, "unreachable error\n");
                    }
                } else {
                    char *s;
                    ERR_error_string(p, s);
                    fprintf(stderr, "%s\n", s);
                }
                break;
            case SSL_ERROR_SSL:
                p = ERR_get_error();
                char *s;
                ERR_error_string(p, s);
                fprintf(stderr, "%s\n", s);
                break;
            default:
                fprintf(stderr, "unknown error\n");
        }
        return;
    }

    n = SSL_shutdown(s);
    if(n < 1) {
        char *e;
        ERR_error_string(SSL_get_error(s, n), e);
        fprintf(stderr, "SSL_shutdown: %s\n", e);
    }
}

void bot(BIO *r, BIO *w, SSL s) {
    char req[1024];
    snprintf(req, 1024, "GET /api/v1/timelines/public HTTP/1.1\r\nHost: rosaline.systems\r\n\r\n");
    BIO_puts(w, req);
    char out[8192];
    BIO_gets(r, out, 8192);
    puts(out);
}

int main() {
    SSL_CTX *c = SSL_CTX_new(TLSv1_2_method());
    BIO *r = BIO_new(BIO_s_connect());
    BIO *w = BIO_new(BIO_s_connect());
    SSL *s = SSL_new(c);

    BIO_set_conn_hostname(r, MASTODON);
    BIO_set_conn_hostname(w, MASTODON);

    SSL_set_bio(s, r, w);

    pid_t f = fork();
    if(f == 0) {
        bot(r, w);
    } else if(f > 0) {
        conn(s);
    } else {
        fprintf(stderr, "unhandled fork() error");
    }

    SSL_free(s);
    SSL_CTX_free(c);
    BIO_free(r);
    BIO_free(w);
}
