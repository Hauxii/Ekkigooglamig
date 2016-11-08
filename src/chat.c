/* A UDP echo server with timeouts.
 *
 * Note that you will not need to use select and the timeout for a
 * tftp server. However, select is also useful if you want to receive
 * from multiple sockets at the same time. Read the documentation for
 * select on how to do this (Hint: Iterate with FD_ISSET()).
 */

#include <assert.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <termios.h>
#include <signal.h>
#include <arpa/inet.h>

/* Secure socket layer headers */
#include <openssl/ssl.h>
#include <openssl/err.h>

/* For nicer interaction, we use the GNU readline library. */
#include <readline/readline.h>
#include <readline/history.h>

#define RSA_CLIENT_CERT "client.crt"
#define RSA_CLIENT_KEY  "client.key"


/* This variable holds a file descriptor of a pipe on which we send a
 * number if a signal is received. */
static int exitfd[2];


/* If someone kills the client, it should still clean up the readline
   library, otherwise the terminal is in a inconsistent state. The
   signal number is sent through a self pipe to notify the main loop
   of the received signal. This avoids a race condition in select. */
void
signal_handler(int signum)
{
        int _errno = errno;
        if (write(exitfd[1], &signum, sizeof(signum)) == -1 && errno != EAGAIN) {
                        abort();
        }
        fsync(exitfd[1]);
        errno = _errno;
}


static void initialize_exitfd(void)
{
        /* Establish the self pipe for signal handling. */
        if (pipe(exitfd) == -1) {
                perror("pipe()");
                exit(EXIT_FAILURE);
        }

        /* Make read and write ends of pipe nonblocking */
        int flags;        
        flags = fcntl(exitfd[0], F_GETFL);
        if (flags == -1) {
                perror("fcntl-F_GETFL");
                exit(EXIT_FAILURE);
        }        
        flags |= O_NONBLOCK;                /* Make read end nonblocking */
        if (fcntl(exitfd[0], F_SETFL, flags) == -1) {
                perror("fcntl-F_SETFL");
                exit(EXIT_FAILURE);
        }
 
        flags = fcntl(exitfd[1], F_GETFL);
        if (flags == -1) {
                perror("fcntl-F_SETFL");
                exit(EXIT_FAILURE);
        }
        flags |= O_NONBLOCK;                /* Make write end nonblocking */
        if (fcntl(exitfd[1], F_SETFL, flags) == -1) {
                perror("fcntl-F_SETFL");
                exit(EXIT_FAILURE);
        }
        
        /* Set the signal handler. */
        struct sigaction sa;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = SA_RESTART;           // Restart interrupted reads()s 
        sa.sa_handler = signal_handler;
        if (sigaction(SIGINT, &sa, NULL) == -1) {
                perror("sigaction");
                exit(EXIT_FAILURE);
        }
        if (sigaction(SIGTERM, &sa, NULL) == -1) {
                perror("sigaction");
                exit(EXIT_FAILURE);
        }       
}


/* The next two variables are used to access the encrypted stream to
 * the server. The socket file descriptor server_fd is provided for
 * select (if needed), while the encrypted communication should use
 * server_ssl and the SSL API of OpenSSL.
 */
//static int server_fd;
static SSL *server_ssl;


/* This variable shall point to the name of the user. The initial value
   is NULL. Set this variable to the username once the user managed to be
   authenticated. */
//static char *user;

/* This variable shall point to the name of the chatroom. The initial
   value is NULL (not member of a chat room). Set this variable whenever
   the user changed the chat room successfully. */
//static char *chatroom;

/* This prompt is used by the readline library to ask the user for
 * input. It is good style to indicate the name of the user and the
 * chat room he is in as part of the prompt. */
static char *prompt;



/* When a line is entered using the readline library, this function
   gets called to handle the entered line. Implement the code to
   handle the user requests in this function. The client handles the
   server messages in the loop in main(). */
void readline_callback(char *line)
{
        char buffer[256];
        if (NULL == line) {
                rl_callback_handler_remove();
                signal_handler(SIGTERM);
                return;
        }
        if (strlen(line) > 0) {
                add_history(line);
        }
        if ((strncmp("/bye", line, 4) == 0) ||
            (strncmp("/quit", line, 5) == 0)) {
                rl_callback_handler_remove();
                signal_handler(SIGTERM);
                return;
        }
        if (strncmp("/game", line, 5) == 0) {
                /* Skip whitespace */
                int i = 4;
                while (line[i] != '\0' && isspace(line[i])) { i++; }
                if (line[i] == '\0') {
                        write(STDOUT_FILENO, "Usage: /game username\n",
                              29);
                        fsync(STDOUT_FILENO);
                        rl_redisplay();
                        return;
                }
                /* Start game */
                return;
        }
        if (strncmp("/join", line, 5) == 0) {
                int i = 5;
                /* Skip whitespace */
                while (line[i] != '\0' && isspace(line[i])) { i++; }
                if (line[i] == '\0') {
                        write(STDOUT_FILENO, "Usage: /join chatroom\n", 22);
                        fsync(STDOUT_FILENO);
                        rl_redisplay();
                        return;
                }
                //char *chatroom = strdup(&(line[i]));

                /* Process and send this information to the server. */

                /* Maybe update the prompt. */
                free(prompt);
                prompt = NULL; /* What should the new prompt look like? */
		rl_set_prompt(prompt);
                return;
        }
        if (strncmp("/list", line, 5) == 0) {
                /* Query all available chat rooms */
                return;
        }
        if (strncmp("/roll", line, 5) == 0) {
                /* roll dice and declare winner. */
                return;
        }
        if (strncmp("/say", line, 4) == 0) {
                /* Skip whitespace */
                int i = 4;
                while (line[i] != '\0' && isspace(line[i])) { i++; }
                if (line[i] == '\0') {
                        write(STDOUT_FILENO, "Usage: /say username message\n",
                              29);
                        fsync(STDOUT_FILENO);
                        rl_redisplay();
                        return;
                }
                /* Skip whitespace */
                int j = i+1;
                while (line[j] != '\0' && isgraph(line[j])) { j++; }
                if (line[j] == '\0') {
                        write(STDOUT_FILENO, "Usage: /say username message\n",
                              29);
                        fsync(STDOUT_FILENO);
                        rl_redisplay();
                        return;
                }
                //char *receiver = strndup(&(line[i]), j - i - 1);
                //char *message = strndup(&(line[j]), j - i - 1);

                /* Send private message to receiver. */

                return;
        }
        if (strncmp("/user", line, 5) == 0) {
                int i = 5;
                /* Skip whitespace */
                while (line[i] != '\0' && isspace(line[i])) { i++; }
                if (line[i] == '\0') {
                        write(STDOUT_FILENO, "Usage: /user username\n", 22);
                        fsync(STDOUT_FILENO);
                        rl_redisplay();
                        return;
                }
                //char *new_user = strdup(&(line[i]));
               // char passwd[48];
               // getpasswd("Password: ", passwd, 48);

                /* Process and send this information to the server. */

                /* Maybe update the prompt. */
                free(prompt);
                prompt = NULL; /* What should the new prompt look like? */
		rl_set_prompt(prompt);
                return;
        }
        if (strncmp("/who", line, 4) == 0) {
                /* Query all available users */
                return;
        }
        /* Sent the buffer to the server. */
        snprintf(buffer, 255, "Message: %s\n", line);
        write(STDOUT_FILENO, buffer, strlen(buffer));
        fsync(STDOUT_FILENO);
}

int main(int argc, char **argv)
{
    if(argc != 3 ){
        printf("wrong parameters");
        return -1;
    }
        initialize_exitfd();
        
        /* Initialize OpenSSL */
	SSL_library_init();
	SSL_load_error_strings();
	SSL_CTX *ssl_ctx = SSL_CTX_new(TLSv1_client_method());
    if(ssl_ctx == NULL){
        printf("failed to set ssl_ctx\n");
    }

	/* TODO:
	 * We may want to use a certificate file if we self sign the
	 * certificates using SSL_use_certificate_file(). If available,
	 * a private key can be loaded using
	 * SSL_CTX_use_PrivateKey_file(). The use of private keys with
	 * a server side key data base can be used to authenticate the
	 * client.
	 */
     if(SSL_CTX_use_certificate_file(ssl_ctx, RSA_CLIENT_CERT, SSL_FILETYPE_PEM) <= 0){
      printf("error loading crt file\n");
    }
    if(SSL_CTX_use_PrivateKey_file(ssl_ctx, RSA_CLIENT_KEY, SSL_FILETYPE_PEM) <= 0){
      printf("error loading key file\n");
    }
    if(!SSL_CTX_check_private_key(ssl_ctx)){
      printf("key and certificate dont match\n");
    }

	/* Create and set up a listening socket. The sockets you
	 * create here can be used in select calls, so do not forget
	 * them.
	 */

	

	/* Now we can create BIOs and use them instead of the socket.
	 * The BIO is responsible for maintaining the state of the
	 * encrypted connection and the actual encryption. Reads and
	 * writes to sock_fd will insert unencrypted data into the
	 * stream, which even may crash the server.
	 */

     char msg[1024]; //2048

    /* Set up secure connection to the chatd server. */
     struct sockaddr_in server_addr;
     int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
     if(sock == -1){
        printf("sock error\n");
     }
     const int server_port = strtol(argv[2], NULL, 10);
     //TODO: check error
     
     memset (&server_addr, '\0', sizeof(server_addr));
     server_addr.sin_family      = AF_INET;
     server_addr.sin_port        = htons(server_port);
     server_addr.sin_addr.s_addr = inet_addr(argv[1]);

     int conn_error = connect(sock, (struct sockaddr *) &server_addr, sizeof(server_addr));
     if(conn_error == -1){
        printf("connection error\n");
     }

     server_ssl = SSL_new(ssl_ctx);
     if(server_ssl == NULL){
        printf("server_ssl is null\n");
    }
     /* Use the socket for the SSL connection. */
    SSL_set_fd(server_ssl, sock);

     int handshake = SSL_connect(server_ssl);
     if(handshake == -1){
        printf("handshake error\n");
     }

     printf("Connected with %s encryption\n", SSL_get_cipher(server_ssl));

     X509 *server_crt;
     server_crt = SSL_get_peer_certificate(server_ssl);
     if(server_crt == NULL){
        printf("Error getting server certificate/Server doesnt have certificate\n");
     }

        /* Read characters from the keyboard while waiting for input.
         */
        prompt = strdup("> ");
        rl_callback_handler_install(prompt, (rl_vcpfunc_t*) &readline_callback);
        for (;;) {
            fd_set rfds;
	       struct timeval timeout;

                /* You must change this. Keep exitfd[0] in the read set to
                   receive the message from the signal handler. Otherwise,
                   the chat client can break in terrible ways. */
                FD_ZERO(&rfds);
                FD_SET(STDIN_FILENO, &rfds);
                FD_SET(sock, &rfds);
		      timeout.tv_sec = 5;
		      timeout.tv_usec = 0;
		
                int r = select(((sock > STDIN_FILENO) ? sock : STDIN_FILENO) + 1, &rfds, NULL, NULL, &timeout);
                if (r < 0) {
                        if (errno == EINTR) {
                                /* This should either retry the call or
                                   exit the loop, depending on whether we
                                   received a SIGTERM. */
                                continue;
                        }
                        /* Not interrupted, maybe nothing we can do? */
                        perror("select()");
                        break;
                }
                if (r == 0) {
                        write(STDOUT_FILENO, "No message?\n", 12);
                        fsync(STDOUT_FILENO);
                        /* Whenever you print out a message, call this
                           to reprint the current input line. */
			             rl_redisplay();
                        continue;
                }
                if (FD_ISSET(exitfd[0], &rfds)) {
                        /* We received a signal. */
                        int signum;
                        for (;;) {
                                if (read(exitfd[0], &signum, sizeof(signum)) == -1) {
                                        if (errno == EAGAIN) {
                                                break;
                                        } else {
                                                perror("read()");
                                                exit(EXIT_FAILURE);
                                        }
                                }
                        }
                        if (signum == SIGINT) {
                                /* Don't do anything. */
                        } else if (signum == SIGTERM) {
                                /* Clean-up and exit. */
                                break;
                        }
                                
                }
                if (FD_ISSET(STDIN_FILENO, &rfds)) {
                        rl_callback_read_char();
                }

                /* Handle messages from the server here! */
                int length = SSL_read(server_ssl, msg, sizeof(msg) -1);

                if(length == -1){
                    printf("Could not read from server\n");
                }
                if(length == 0){
                    //conn terminated
                    break;
                }

                msg[length] = '\0';
                write(STDOUT_FILENO, msg, strlen(msg));
                //char rbuf[50] = {'a'};
                //int bytes = SSL_read(server_ssl, rbuf, sizeof(rbuf));
                //rbuf[bytes] = 0;
                //printf("%s\n", rbuf);
        }
        
        /* replace by code to shutdown the connection and exit
           the program. */
}
