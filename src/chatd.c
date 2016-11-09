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

typedef struct user {
    int conn_fd;
    SSL *conn_ssl;
    char *username;
    char *curr_room;
} user;

struct room {
    char *name;
    GList *members;
} room;
typedef struct message_with_sender {
    char* message;
    char* receiver;
} message_with_sender;
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

static SSL *server_ssl;
int sock;
fd_set rfds;
GTree *userlist;
GTree *roomList;

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

gboolean send_pm(gpointer key, gpointer user, gpointer message_struct){
    //get rid of warning
    if(key == NULL){
    }
    struct user *curr_user = (struct user *) user;
    struct message_with_sender* temp = (message_with_sender *)message_struct;
    if(strcmp(curr_user->username, temp->receiver) == 0){
        int err = SSL_write(curr_user->conn_ssl, temp->message, strlen(temp->message));
        if(err == -1){
            printf("ERROR SENDING MESSAGE\n");
        }
        return TRUE;
    }
    return FALSE;
}

void send_message(void *user, char *message){
    struct user *curr_user = (struct user *) user; 
    int err = SSL_write(curr_user->conn_ssl, message, strlen(message));
    if(err == -1){
        printf("ERROR SENDING MESSAGE\n");
    }
}

gboolean print_room_users(gpointer username, gpointer data){
    if(data == NULL){
    }
    printf("%s\n", (char*)username);
    return FALSE;
}

GString * list_of_users;
gboolean get_userlist(gpointer username, gpointer list){    
    GString *updated_list = (GString *)list;
    g_string_append(updated_list, (char*)username);
    list = updated_list;
    return FALSE;
}

int found = 0;
gboolean search_by_username(gpointer key, gpointer user, gpointer lookup){
    //get rid of warning
    if(key == NULL){
    }
    struct user *curr_user = (struct user *) user;
    printf("lookup before: %s\n", (char*)lookup);
    if(strncmp(curr_user->username, lookup, strlen(lookup)) == 0){
        found = 1;
        return TRUE;
    }
    return FALSE;
}


gboolean get_data_from_users(gpointer key, gpointer user, gpointer ret){
    //get rid of warning
    if(key == NULL){
    }
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
            if(strncmp("anonymous", curr_user->username, 9) == 0 && (strncmp("/user", buffer, 5) != 0)){
                send_message((void *)curr_user, "SERVER: please authenticate a username with \"/user [your username]\"");
            }
            else if(buffer[0] == '/'){
                printf("Client sent command\n");
                if (strncmp("/who", buffer, 4) == 0){

                    //TODO if there is something after who it should says wrong command
                    //printf("SERVER: /who\n");
                    printf("curr user room is: %s\n",curr_user->curr_room);
                    if(strcmp(curr_user->curr_room,"none") == 0){
                        //TODO tell user he should join room first
                        printf("server logging that user sohuld be on room before whoing\n");
                    }
                    else{
                        struct room* result = (struct room*)g_tree_lookup(roomList,curr_user->curr_room);
                        list_of_users = g_string_new("List of users in same room as you: ");
                        //TODO add the room name to this string
                        
                        g_list_foreach (result->members, (GFunc)get_userlist, list_of_users);
                        send_message((void *)curr_user, (char *)list_of_users->str);
                        g_string_free(list_of_users, TRUE);
                    }
                }
                if (strncmp("/user", buffer, 5) == 0){
                    char *new_username = strdup(&(buffer[6]));
                    g_tree_foreach(userlist, search_by_username, new_username);
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
                    char *message = &buffer[j + 1];

                    snprintf(buffer, 255, "%s: %s", curr_user->username, message);
                    struct message_with_sender* msg_sender = g_new(struct message_with_sender, 1);
                    msg_sender->message = buffer;
                    msg_sender->receiver = receiver;

                    if(strncmp("anonymous", msg_sender->receiver, 9) == 0){
                        send_message((void *)curr_user, "SERVER: anonymous can not receive personal message");
                    }
                    else{
                        g_tree_foreach(userlist, send_pm, msg_sender);
                    }


                }
                if (strncmp("/help", buffer, 5) == 0){
                    char help[1024];
                    snprintf(help, 1024, "\"/user [Your Username]\" - registers you as a user\n\"/who\" - lists all users online\n\"/say [Username]\" - sends a personal message to another user\n\"/join [Chatroom]\" - lets you join a chatroom\n");
                    send_message((void *)curr_user, help);
                }
                //Assuming users can not be named anon when joining
                if (strncmp("/join", buffer, 5) == 0){
                    char *new_room = strdup(&(buffer[6]));
                    struct room* result = (struct room*)g_tree_lookup(roomList,new_room);
                    if(result != NULL){
                        if(strcmp(curr_user->curr_room,"none") != 0){
                            struct room* old_room_ptr = (struct room*)g_tree_lookup(roomList,curr_user->curr_room);
                            old_room_ptr->members = g_list_remove(old_room_ptr->members,curr_user->username);
                            curr_user->curr_room = strdup(new_room);
                        }

                        curr_user->curr_room = strdup(new_room);
                        result->members = g_list_prepend(result->members,curr_user->username);
                    }
                    else{
                        printf("user tried to get into room that does not exist, you should send him a message telling him so\n");
                    }
                    printf("people inside party:\n");
                    struct room* party  = (struct room*)g_tree_lookup(roomList,"party");
                    g_list_foreach (party->members, (GFunc)print_room_users, NULL);
                    printf("people inside lobby:\n");
                    struct room* lobby = (struct room*)g_tree_lookup(roomList,"lobby");
                    g_list_foreach (lobby->members, (GFunc)print_room_users, NULL);

                }                
            }
            else{
                buffer[bytes] = '\0';
                g_tree_foreach(userlist, send_message_to_all, buffer);            
            }

        }

    }
    return FALSE;
}

int main(int argc, char **argv)
{
    struct sockaddr_in server, *client;
    int listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

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

    if(bind(listen_sock, (struct sockaddr *) &server, sizeof(server)) == -1 ){
        printf("bind failed\n");
    }
    //Receive a TCP connection
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
    g_tree_insert(roomList, nextRoom->name, nextRoom);
    //struct room* result = (struct room*)g_tree_lookup(roomList,"lobby");
    //struct room* party = (struct room*)g_tree_lookup(roomList,"party");
    
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
        }
        else if(sel > 0){
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
                        char welcome[1024] = {'\0'};
                        snprintf(welcome, 1024, "Welcome!\nTo start using the chat you have to authenticate a username with the command \"/user [Your Username]\"\nType \"/help\" to get a list of commands");
                        err = SSL_write(server_ssl, welcome, sizeof(welcome)-1);
                        
                        if(err == -1){
                            printf("ERROR SENDING MESSAGE\n");
                        } 
                        else{
                            struct user *newconnection = g_new(struct user,1);
                            newconnection->conn_ssl = server_ssl;
                            newconnection->conn_fd = sock;
                            newconnection->username = "anonymous";
                            newconnection->curr_room = "none";
                            g_tree_insert(userlist, client, newconnection);
                        }              
                    }
                } 
                else{
                    printf("SSL connection failed (SSL_new)\n");
                }
            }
            //check for new message requests
        }
        else{
            //maybe check for timeouts
            //printf("5 sec interval- sel was something else: %d \n", sel);
        }

        g_tree_foreach(userlist, get_data_from_users, &rfds);
    

    }

    SSL_shutdown(server_ssl);
    close(sock);
    SSL_free(server_ssl);
    SSL_CTX_free(ssl_ctx);

    exit(EXIT_SUCCESS);
}
