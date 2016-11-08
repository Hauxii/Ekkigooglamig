/* A TCP echo server with timeouts.
 *
 * Note that you will not need to use select and the timeout for a
 * tftp server. However, select is also useful if you want to receive
 * from multiple sockets at the same time. Read the documentation for
 * select on how to do this (Hint: Iterate with FD_ISSET()).
 */

#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <glib.h>

#define RSA_SERVER_CERT     "server.crt"
#define RSA_SERVER_KEY      "server.key"


/* This can be used to build instances of GTree that index on
   the address of a connection. */
int sockaddr_in_cmp(const void *addr1, const void *addr2)
{
     const struct sockaddr_in *_addr1 = addr1;
     const struct sockaddr_in *_addr2 = addr2;

     /* If either of the pointers is NULL or the addresses
        belong to different families, we abort. */
     g_assert((_addr1 == NULL) || (_addr2 == NULL) ||
              (_addr1->sin_family != _addr2->sin_family));

     if (_addr1->sin_addr.s_addr < _addr2->sin_addr.s_addr) {
          return -1;
     } else if (_addr1->sin_addr.s_addr > _addr2->sin_addr.s_addr) {
          return 1;
     } else if (_addr1->sin_port < _addr2->sin_port) {
          return -1;
     } else if (_addr1->sin_port > _addr2->sin_port) {
          return 1;
     }
     return 0;
}


/* This can be used to build instances of GTree that index on
   the file descriptor of a connection. */
gint fd_cmp(gconstpointer fd1,  gconstpointer fd2, gpointer G_GNUC_UNUSED data)
{
    return GPOINTER_TO_INT(fd1) - GPOINTER_TO_INT(fd2);
}

//static int server_fd;
static SSL *server_ssl;
//static char rbuf[512];

int main(int argc, char **argv)
{
    struct sockaddr_in server, client;
    int sock;
    int listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    //CHK_ERR(listen_sock, "socket");

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <port>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    const int server_port = strtol(argv[1], NULL, 10);

    /* Initialize OpenSSL */
    SSL_library_init();
    SSL_load_error_strings();
    SSL_CTX *ssl_ctx = SSL_CTX_new(TLSv1_server_method());
    //load certificates
    //

    if(SSL_CTX_use_certificate_file(ssl_ctx, RSA_SERVER_CERT, SSL_FILETYPE_PEM) <= 0){
        printf("error loading crt file\n");
    }
    if(SSL_CTX_use_PrivateKey_file(ssl_ctx, RSA_SERVER_KEY, SSL_FILETYPE_PEM) <= 0){
        printf("error loading key file\n");
    }
    if(!SSL_CTX_check_private_key(ssl_ctx)){
        printf("key and certificate dont match\n");
    }

    /* núlla structið */
    memset(&server, 0, sizeof(server));
    server.sin_family      = AF_INET;
    server.sin_addr.s_addr = htonl(INADDR_ANY);
    server.sin_port        = htons(server_port); 

    //TODO: error check
    if(bind(listen_sock, (struct sockaddr *) &server, sizeof(server)) == -1 ){
        printf("bind failed\n");
    }
    //Receive a TCP connection
    //TODO: error check
    if(listen(listen_sock, 5) == -1){
        printf("listen failed");
    }


    for(;;){
        /* Receive and handle messages. */
        socklen_t client_len = (socklen_t) sizeof(client);
        sock = accept(listen_sock, (struct sockaddr *)&client, &client_len);
        GDateTime *timestamp;
        timestamp = g_date_time_new_now_local();
        char *str = g_date_time_format(timestamp, "It is currently %x %X %z");
        g_print("<%s> : %s:%d connected\n", str, inet_ntoa(client.sin_addr), ntohs(client.sin_port));
        g_date_time_unref(timestamp);
        g_free(str);
        server_ssl = SSL_new(ssl_ctx);

        if(server_ssl){
            SSL_set_fd(server_ssl, sock);
            int err = SSL_accept(server_ssl);
            if(err == -1){
                printf("SSL connection failed (SSL_accept)\n");
            } 
            else{
                err = SSL_write(server_ssl, "Welcome!", 8);
                if(err == -1){
                    printf("ERROR SENDING MESSAGE\n");
                }
            }
        }
    }
    SSL_shutdown(server_ssl);
    close(sock);
    SSL_free(server_ssl);
    SSL_CTX_free(ssl_ctx);



    exit(EXIT_SUCCESS);
}
