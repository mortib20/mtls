#include <stdio.h>      // Standard Input Output
#include <stdlib.h>     // Standard Library
#include <string.h>     // String manipulation
#include <sys/unistd.h> // Unix Standard
#include <sys/types.h>  // Types
#include <sys/socket.h> // Socket
#include <netinet/in.h> // Internet
#include <arpa/inet.h>  // IP conversion
#include <netdb.h>      // Address Information

#include <wolfssl/ssl.h>

#define MTLS_TYPE_SERVER 0
#define MTLS_TYPE_CLIENT 1

#define MTLS_SSL_TYPE_WOLF
#ifdef MTLS_SSL_TYPE_WOLF
typedef WOLFSSL MTLS_SSL;
typedef WOLFSSL_METHOD MTLS_SSL_METHOD;
typedef WOLFSSL_CTX MTLS_SSL_CTX;
#endif

typedef struct
{
    MTLS_SSL_METHOD* ssl_method;
    MTLS_SSL_CTX* ssl_ctx;
    MTLS_SSL* ssl;

    int sockfd;
    int addr_family;
    int socket_type;
} MTLS;

void MTLS_create_ssl(MTLS* mtls, int type)
{
    #ifdef MTLS_SSL_TYPE_WOLF
    wolfSSL_Init();

    if (type == MTLS_TYPE_SERVER)
        mtls->ssl_method = wolfSSLv23_server_method();
    else if (type == MTLS_TYPE_CLIENT)
        mtls->ssl_method = wolfSSLv23_client_method();
    else {
        printf("create_ssl: Wrong type\n");
        exit(EXIT_FAILURE);
    }

    mtls->ssl_ctx = wolfSSL_CTX_new(mtls->ssl_method);
    if (!mtls->ssl_ctx) {
        perror("create_ssl");
        exit(EXIT_FAILURE);
    }

    wolfSSL_CTX_load_system_CA_certs(mtls->ssl_ctx);

    mtls->ssl = wolfSSL_new(mtls->ssl_ctx);
    if (!mtls->ssl) {
        perror("create_ssl");
        exit(EXIT_FAILURE);
    }
    #endif
}

void MTLS_create_socket(MTLS* mtls, int domain, int type, int protocol)
{
    mtls->socket_type = type;
    mtls->sockfd = socket(mtls->addr_family, mtls->socket_type, protocol);
    if (mtls->sockfd == -1) {
        perror("create_socket");
        exit(EXIT_FAILURE);
    }
}

void MTLS_set_ssl_fd(MTLS* mtls, int fd)
{
    #ifdef MTLS_SSL_TYPE_WOLF
    wolfSSL_set_fd(mtls->ssl, mtls->sockfd);
    #endif
}

void MTLS_connect(MTLS* mtls, const char* name, const char* port)
{
    int gaierr;
    struct addrinfo hint, *address, *tempaddress;

    memset(&hint, 0, sizeof(hint));
    hint.ai_family = mtls->addr_family;
    hint.ai_socktype = mtls->socket_type;
    hint.ai_flags = AI_CANONNAME;


    gaierr = getaddrinfo(name, port, &hint, &address);

    if (gaierr != 0) {
        printf("MTLS_connect: %s\n", gai_strerror(gaierr));
        exit(EXIT_FAILURE);
    }

    for (tempaddress = address; tempaddress != NULL; tempaddress = tempaddress->ai_next) {
        if(connect(mtls->sockfd, tempaddress->ai_addr, tempaddress->ai_addrlen) == 0)
            break;

        close(mtls->sockfd);
    }

    freeaddrinfo(address);

    if (tempaddress == NULL) {
        printf("MTLS_connect: Failed to connect to name\n");
        perror("MTLS_connect");
        exit(EXIT_FAILURE);
    }
}

void MTLS_close(MTLS* mtls)
{
    #ifdef MTLS_SSL_TYPE_WOLF
    wolfSSL_shutdown(mtls->ssl);
    #endif
    close(mtls->sockfd);
}

void MTLS_free(MTLS* mtls)
{
    #ifdef MTLS_SSL_TYPE_WOLF
    wolfSSL_CTX_free(mtls->ssl_ctx);
    wolfSSL_Cleanup();
    #endif
}

// Other MTLS functions

MTLS* MTLS_new_tcp_client(int addr_family)
{
    MTLS* mtls = (MTLS*)malloc(sizeof(MTLS));

    mtls->addr_family = AF_INET;

    MTLS_create_socket(mtls, mtls->addr_family, SOCK_STREAM, IPPROTO_TCP);
    MTLS_create_ssl(mtls, MTLS_TYPE_CLIENT);
    MTLS_set_ssl_fd(mtls, mtls->sockfd);

    return mtls;
}

// Main function

int main(int argc, char* argv[])
{
    wolfSSL_Init();
    MTLS* mtls;
    mtls = MTLS_new_tcp_client(AF_INET);

    MTLS_connect(mtls, "example.com", "443");

    wolfSSL_connect(mtls->ssl);

    char* buffer = "GET / HTTP/1.1\nHost: example.com\n\n";

    wolfSSL_write(mtls->ssl, buffer, strlen(buffer));
    wolfSSL_write(mtls->ssl, buffer, strlen(buffer));

    char rec[1023];

    

    wolfSSL_read(mtls->ssl, rec, sizeof(rec));

    printf("%s\n", rec);

    // READ AND WRITE

    MTLS_close(mtls);

    MTLS_free(mtls);
}