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
    char *username;
} user;

struct room {
    char *name;
    GList *members;
} room;
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
GTree *roomList;
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

gboolean send_message_to_all(gpointer key, gpointer user, gpointer message){
    //get rid of warning
    if(key == NULL){
    }
    struct user *curr_user = (struct user *) user;
    int err = SSL_write(curr_user->conn_ssl, message, strlen(message));
    if(err == -1){
        printf("ERROR SENDING MESSAGE\n");
    }
    return FALSE;
}

void send_message(void *user, char *message){
    struct user *curr_user = (struct user *) user; 
    printf("TO SEND: %s\n", message);
    int err = SSL_write(curr_user->conn_ssl, message, strlen(message));
    if(err == -1){
        printf("ERROR SENDING MESSAGE\n");
    }
}

gboolean print_room_users(gpointer username, gpointer data){
    printf("%s\n", (char*)username);
    return FALSE;
}

GString * list_of_users;
gboolean get_userlist(gpointer key, gpointer user, gpointer list){
    //get rid of warning
    if(key == NULL){
    }
    struct user *curr_user = (struct user *) user;
    GString *updated_list = (GString *)list;
    //GString *curr_list = (GString *) list;
    //GString name = g_string_new(curr_user->username);
    g_string_append(updated_list, curr_user->username);
    g_string_append(updated_list, "\n");
    list = updated_list;
    return FALSE;
}

int found = 0;
gboolean search_by_username(gpointer key, gpointer user, gpointer lookup){
    struct user *curr_user = (struct user *) user;
    printf("lookup before: %s\n", lookup);
    if(strncmp(curr_user->username, lookup, strlen(lookup)) == 0){
        //printf("USERNAME EXISTS\n");
        found = 1;
        //char *ret = "exists";
        //lookup = ret;
        //printf("lookup after:%s\n", lookup);
        //return TRUE;
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
            printf("from client: %s\n", buffer);
            if(buffer[0] == '/'){
                printf("Client sent command\n");
                if (strncmp("/who", buffer, 4) == 0){
                    //printf("SERVER: /who\n");
                    list_of_users = g_string_new("List of users:\n");
                    //g_list
                    g_tree_foreach(userlist, get_userlist, list_of_users);
                    //printf("%s", (char *)list_of_users->str);
                    send_message((void *)curr_user, (char *)list_of_users->str);
                    g_string_free(list_of_users, TRUE);
                    //send list of users to client
                }
                if (strncmp("/user", buffer, 5) == 0){
                    //printf("%s\n", strdup(&(buffer[6])));
                    char *new_username = strdup(&(buffer[6]));

                    printf("username before: %s\n", new_username);
                    g_tree_foreach(userlist, search_by_username, new_username);
                    printf("username after: %s\n", new_username);

                    if(found == 1){
                        found = 0;
                        send_message((void *)curr_user, "SERVER: username already exists");
                    }
                    else {
                        curr_user->username = new_username;
                        send_message((void *)curr_user, ("SERVER: your username has been set"));
                    }
                    
                }
                if (strncmp("/say", buffer, 4) == 0) {
                    /* Skip whitespace */
                    int i = 4;
                    while (buffer[i] != '\0' && isspace(buffer[i])) { i++; }
                    /* Skip whitespace */
                    int j = i+1;
                    while (buffer[j] != '\0' && isgraph(buffer[j])) { j++; }
                    char *receiver = strndup(&(buffer[i]), j - i);
                    char *message = &buffer[j];
                    printf("receiver: %s, message: %s\n", receiver, message);
                    if(strncmp("anonymous", curr_user->username, 9) == 0){
                        send_message((void *)curr_user, "SERVER: Set your username with \"/user\" before sending a personal message");
                    }
                    else if(strncmp("anonymous", receiver, 9) == 0){
                        send_message((void *)curr_user, "SERVER: anonymous can not receive personal message");
                    }
                    else{
                        /* Send private message to receiver. */
                        snprintf(buffer, 255, "%s: %s", curr_user->username,message);
                        //SSL_write(server_ssl, buffer, strlen(buffer));
                    }
                    

                }
                //Assuming users can not be named anon when joining
                if (strncmp("/join", buffer, 5) == 0){
                    printf("trying to add user to room %s\n",strdup(&(buffer[6]));
                        struct room* result = (struct room*)g_tree_lookup(roomList,strdup(&(buffer[6])));
                    if(result != NULL){
                        printf("found room as: %s\n", result->name);
                        //TODO check if user already exists in room
                        result->members = g_list_prepend(result->members,curr_user->username);
                    }
                    else{
                        printf("user tried to get into room that does not exist, you should send him a message telling him so\n");
                    }
                    printf("after adding this motherfucker then the poeple in this room include:\n");
                    g_list_foreach (result->members, (GFunc)print_room_users, NULL);

                }
            }
            else{
                buffer[bytes] = '\0';
                g_tree_foreach(userlist, send_message_to_all, buffer);            
                //printf("recieved and sent back message: %s", buffer);
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
    roomList = g_tree_new((GCompareFunc)strcmp);
    //initialize a couple of rooms for now
    struct room* lobby = g_new(struct room,1);
    lobby->name = "lobby";
    lobby->members = NULL;
    struct room* nextRoom = g_new(struct room,1);
    nextRoom->name = "party";
    nextRoom->members = NULL;
    g_tree_insert(roomList, lobby->name, lobby);
    g_tree_insert(roomList, nextRoom->name, nextRoom);/*
    struct room* result = (struct room*)g_tree_lookup(roomList,"lobby");
    if(result != NULL){
        printf("found room lobby as: %s\n", result->name);
        result->members = g_list_prepend(result->members,"hauxi");
        g_list_foreach (result->members, (GFunc)print_room_users, NULL) ; 
    }
    else{
        printf("result was null\n");
    }*/
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
            //printf(" sel was > 0\n");
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
                            newconnection->username = "anonymous";
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
