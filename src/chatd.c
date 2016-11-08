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

struct user {
    int conn_fd;
    SSL *conn_ssl;
} user;
/* This can be used to build instances of GTree that index on
   the address of a connection. */
int sockaddr_in_cmp(const void *addr1, const void *addr2)
{
     const struct sockaddr_in *_addr1 = addr1;
     const struct sockaddr_in *_addr2 = addr2;

     /* If either of the pointers is NULL or the addresses
        belong to different families, we abort. */
     g_assert((_addr1 != NULL) && (_addr2 != NULL) &&
              (_addr1->sin_family == _addr2->sin_family));

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
int sock;
fd_set rfds;
GTree *userlist;
//static char rbuf[512];

void timestamp(void* ptr){
     struct sockaddr_in *client = (struct sockaddr_in *) ptr;
    GDateTime *timestamp;
    timestamp = g_date_time_new_now_local();
    char *str = g_date_time_format(timestamp, "%x %X");
    g_print("<%s> : %s:%d \n", str, inet_ntoa(client->sin_addr), ntohs(client->sin_port));
    g_date_time_unref(timestamp);
    g_free(str);
}
gboolean update_fd(gpointer key, gpointer user, gpointer ret){
    //get rid of warning
    if(key == NULL){
    }

   int user_fd = ((struct user *) user)->conn_fd;
    int ret_fd = *(int *)ret;
    FD_SET(user_fd, &rfds);
    if(user_fd > ret_fd){
        *(int *)ret = user_fd;
    }
    return FALSE;
}

gboolean get_data_from_users(gpointer key, gpointer user, gpointer ret){
    struct user *curr_user = (struct user *) user;
    fd_set *curr_rfds = (fd_set*) ret;
    if(FD_ISSET(curr_user->conn_fd, curr_rfds)){
        //printf("Tried to read message from user\n");
        char buffer[1024] = {'\0'};
        int bytes = SSL_read(curr_user->conn_ssl, buffer, sizeof(buffer)-1);
        if(bytes <= 0){
            printf("disconnected user: ");
            timestamp((void*)key);
            SSL_shutdown(curr_user->conn_ssl);
            g_tree_remove(userlist, key); 
        }
        else{
            buffer[bytes] = '\0';
            printf("recieved and sent back message: %s", buffer);
            int err = SSL_write(curr_user->conn_ssl, buffer, strlen(buffer));
            if(err == -1){
                printf("ERROR SENDING MESSAGE\n");
            }
        }
        
    }
    return FALSE;
}

int main(int argc, char **argv)
{
    struct sockaddr_in server, *client;
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

    userlist = g_tree_new(sockaddr_in_cmp);

    for(;;){
        struct timeval timeout;
        FD_ZERO(&rfds);
        FD_SET(listen_sock, &rfds);
        timeout.tv_sec = 5;
        timeout.tv_usec = 0;

        int updated_fd = -1;
        g_tree_foreach(userlist, update_fd, &updated_fd);

        int sel = select(((updated_fd > listen_sock) ? updated_fd : listen_sock)+1,&rfds,NULL,NULL,&timeout);

        if(sel == -1){
            printf(" sel was -1\n");
        }
        else if(sel > 0){
            printf(" sel was > 0\n");
            if(FD_ISSET(listen_sock, &rfds)){
                client = g_new0(struct sockaddr_in, 1);
                socklen_t client_len = (socklen_t) sizeof(client);
                sock = accept(listen_sock, (struct sockaddr *)client, &client_len);
               
                printf("connect user: ");
                timestamp((void*)client);
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
                        else{
                            struct user *newconnection = g_new(struct user,1);
                            newconnection->conn_ssl = server_ssl;
                            newconnection->conn_fd = sock;
                            g_tree_insert(userlist, client, newconnection);

                            printf("user added with fd = %d\n", sock);

                        }              
                    }
                } 
                else{
                    printf("SSL connection failed (SSL_new)\n");
                }
            }
            //check for new message requests

            //gtree foreach


        }
        else{
            //maybe check for timeouts
            printf("5 sec interval- sel was something else: %d \n", sel);
        }

        g_tree_foreach(userlist, get_data_from_users, &rfds);
    

    }

    SSL_shutdown(server_ssl);
    close(sock);
    SSL_free(server_ssl);
    SSL_CTX_free(ssl_ctx);

    exit(EXIT_SUCCESS);
}
