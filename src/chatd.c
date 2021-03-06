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
    int timeout;
} user;

typedef struct room {
    char *name;
    GList *members;
} room;
typedef struct message_with_info {
    char* message;
    char* info;
} message_with_info;


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
    struct message_with_info* msg = (struct message_with_info*) message;
    if(strcmp(msg->info,curr_user->curr_room) == 0){
        int err = SSL_write(curr_user->conn_ssl, msg->message, strlen(msg->message));
        if(err == -1){
            printf("ERROR SENDING MESSAGE\n");
        }
    }
    return FALSE;
}

gboolean send_pm(gpointer key, gpointer user, gpointer message_struct){
    //get rid of warning
    if(key == NULL){
    }
    struct user *curr_user = (struct user *) user;
    struct message_with_info* temp = (message_with_info *)message_struct;
    if(strcmp(curr_user->username, temp->info) == 0){
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

GString * list_of_users;
gboolean get_userlist(gpointer username, gpointer list){    
    GString *updated_list = (GString *)list;
    g_string_append(updated_list, (char*)username);
    g_string_append(updated_list, "\n");
    list = updated_list;
    return FALSE;
}

GString * list_of_chatrooms;
gboolean get_chatroomlist(gpointer key, gpointer chatroom, gpointer list){
    if(key == NULL){
    }    
    GString *updated_list = (GString *)list;
    struct room* temp = (struct room *)chatroom;
    g_string_append(updated_list, temp->name);
    g_string_append(updated_list, "\n");
    list = updated_list;
    return FALSE;
}

int found = 0;
gboolean search_by_username(gpointer key, gpointer user, gpointer lookup){
    //get rid of warning
    if(key == NULL){
    }
    struct user *curr_user = (struct user *) user;
    if(strncmp(curr_user->username, lookup, strlen(lookup)) == 0){
        found = 1;
        return TRUE;
    }
    return FALSE;
}


void disconnectUser(struct user* user, void* key){

    printf("disconnected user: ");
    timestamp(key);
    if(strcmp(user->curr_room, "none") != 0){
        struct room* room_ptr = (struct room*)g_tree_lookup(roomList,user->curr_room);
        room_ptr->members = g_list_remove(room_ptr->members, user->username);
    }
    SSL_shutdown(user->conn_ssl);
    g_tree_remove(userlist, key); 
}

gboolean check_users_timeout(gpointer key, gpointer user, gpointer maxTime){
    struct user *curr_user = (struct user *) user;
    int* time = (int*)maxTime;
    curr_user->timeout += 1;
    if(curr_user->timeout == *time){
            char* message = "You have been disconnected for inactivity :( \n";
            printf("timed out\n");
          int err = SSL_write(curr_user->conn_ssl, message, strlen(message));
          if(err == -1){
              printf("ERROR SENDING MESSAGE\n");
          }
        disconnectUser(curr_user, key);
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
        char buffer[1024] = {'\0'};
        int bytes = SSL_read(curr_user->conn_ssl, buffer, sizeof(buffer)-1);
        if(bytes <= 0){
            disconnectUser(curr_user, key);
        }
        else{
            if(strncmp("anonymous", curr_user->username, 9) == 0 && (strncmp("/user", buffer, 5) != 0)){
                send_message((void *)curr_user, "SERVER: please authenticate a username with \"/user [your username]\"");
            }
            else if(buffer[0] == '/'){
                if (strncmp("/who", buffer, 4) == 0){
                    if(strcmp(curr_user->curr_room,"none") == 0){
                        //TODO tell user he should join room first
                        send_message((void *)curr_user, "SERVER: You have too be in a chatroom to use \"/who\"");
                        
                    }
                    else{
                        struct room* result = (struct room*)g_tree_lookup(roomList,curr_user->curr_room);
                        list_of_users = g_string_new("List of users in same room as you: \n");
                        //TODO add the room name to this string
                        
                        g_list_foreach (result->members, (GFunc)get_userlist, list_of_users);
                        send_message((void *)curr_user, (char *)list_of_users->str);
                        g_string_free(list_of_users, TRUE);
                    }
                }
                if (strncmp("/list", buffer, 5) == 0){
                    list_of_chatrooms = g_string_new("List of available chatrooms: \n");
                    g_tree_foreach(roomList, get_chatroomlist, list_of_chatrooms);
                    send_message((void * )curr_user, (char *)list_of_chatrooms->str);
                    g_string_free(list_of_chatrooms, TRUE);
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

                    GDateTime *timestamp;
                    timestamp = g_date_time_new_now_local();
                    char *str = g_date_time_format(timestamp, "%x %X");

                    char temp[256];
                    GString *msg = g_string_new("");

                    g_string_append(msg, temp);
                    g_string_append(msg, message);

                    struct message_with_info* msg_sender = g_new(struct message_with_info, 1);
                    msg_sender->message = (char *)msg->str;
                    msg_sender->info = receiver;

                    g_tree_foreach(userlist, search_by_username, receiver);

                    if(strncmp("anonymous", msg_sender->info, 9) == 0){
                        send_message((void *)curr_user, "SERVER: anonymous can not receive personal message");
                    }
                    else if(found == 0){
                        send_message((void *)curr_user, "SERVER: There is no user registered with that name");
                    }
                    else if(strcmp(receiver, curr_user->username) == 0){
                        send_message((void *)curr_user, "SERVER: You can not send yourself a private message (cuz FUCK YOU! thats why!)");
                    }
                    else{
                        found = 0;
                        g_tree_foreach(userlist, send_pm, msg_sender);
                    }

                    g_date_time_unref(timestamp);
                    g_free(str);
                    g_string_free(msg, TRUE);

                }
                if (strncmp("/help", buffer, 5) == 0){
                    char help[1024];
                    snprintf(help, 1024, "\"/user [Your Username]\" - registers you as a user\n\"/who\" - lists all users online\n\"/say [Username]\" - sends a personal message to another user\n\"/join [Chatroom]\" - lets you join a chatroom\n\"/list\" - lists all available chatrooms");
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
                        send_message((void *)curr_user, "SERVER: This room does not exist, use \"/list\" to see available rooms");
                    }
                }                
            }
            else{
                if(strcmp(curr_user->curr_room, "none") == 0){
                    
                        send_message((void *)curr_user, ("SERVER: You have to join a room to be able to chat. Use /help to see a list of command to do so."));
                }
                else{
                    //send message to people in room;
                    GDateTime *timestamp;
                    timestamp = g_date_time_new_now_local();
                    char *str = g_date_time_format(timestamp, "%x %X");

                    char temp[256];
                    snprintf(temp, 255, "<%s> %s: ", str, curr_user->username);
                    GString *msg_temp = g_string_new("");

                    g_string_append(msg_temp, temp);
                    g_string_append(msg_temp, buffer);

                    struct message_with_info* msg = g_new(struct message_with_info,1);
                    buffer[bytes] = '\0';

                    msg->message = (char *)msg_temp->str;
                    msg->info = curr_user->curr_room;

                    g_tree_foreach(userlist, send_message_to_all, msg);            
                    g_free(msg);
                    g_date_time_unref(timestamp);
                    g_free(str);
                    g_string_free(msg_temp, TRUE);
                }
            }
            //User did something so we reset timeout
            curr_user->timeout = 0;
        }
    }
    return FALSE;
}

int main(int argc, char **argv)
{
    struct sockaddr_in server, *client;
    int listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    int maxTimeOut = 10;
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
                            newconnection->timeout = 0;
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
            int* ptr = &maxTimeOut; 
            g_tree_foreach(userlist, check_users_timeout, ptr);
        
        }

        g_tree_foreach(userlist, get_data_from_users, &rfds);
    

    }

    SSL_shutdown(server_ssl);
    close(sock);
    SSL_free(server_ssl);
    SSL_CTX_free(ssl_ctx);

    exit(EXIT_SUCCESS);
}
