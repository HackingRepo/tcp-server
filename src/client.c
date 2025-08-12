#define _POSIX_C_SOURCE 200809L

#include <netdb.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>  // Added for close()

#include "./shared.h"

#define MAX_MSG_SIZE 1024
#define MIN_MSG_SIZE 1

static void cleanup(void);
static void handle_sigint(int sig);
static bool send_message(int socket_fd, const char *msg, size_t len);
static bool receive_message(int socket_fd, char *buffer, size_t buffer_size);

static struct addrinfo *server_info = NULL;
static int socket_fd = -1;

int main(void) {
    signal(SIGPIPE, SIG_IGN); // Ignore SIGPIPE to prevent crashes on broken pipes
    atexit(cleanup);
    signal(SIGINT, handle_sigint);

    int rv;
    struct addrinfo hints = {0};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    rv = getaddrinfo(NULL, PORT, &hints, &server_info);
    if (rv != 0) {
        fprintf(stderr, "getaddrinfo(): %s\n", gai_strerror(rv));
        return EXIT_FAILURE;
    }

    socket_fd = socket(server_info->ai_family, server_info->ai_socktype,
                      server_info->ai_protocol);
    if (socket_fd == -1) {
        perror("socket()");
        return EXIT_FAILURE;
    }

    rv = connect(socket_fd, server_info->ai_addr, server_info->ai_addrlen);
    if (rv == -1) {
        perror("connect()");
        return EXIT_FAILURE;
    }

    // Free server_info immediately after use
    freeaddrinfo(server_info);
    server_info = NULL;

    char received_msg[MAX_MSG_SIZE];
    char *line = NULL;
    size_t line_cap = 0;
    ssize_t line_len;

    printf("> ");
    while ((line_len = getline(&line, &line_cap, stdin)) > 0) {
        // Remove newline
        if (line_len > 0 && line[line_len - 1] == '\n') {
            line[--line_len] = '\0';
        }

        // Validate message size
        if (line_len < MIN_MSG_SIZE || line_len >= MAX_MSG_SIZE) {
            fprintf(stderr, "Message length must be between %d and %d bytes\n",
                    MIN_MSG_SIZE, MAX_MSG_SIZE - 1);
            printf("> ");
            continue;
        }

        // Send message
        if (!send_message(socket_fd, line, line_len)) {
            free(line);
            return EXIT_FAILURE;
        }

        // Receive response
        if (!receive_message(socket_fd, received_msg, sizeof(received_msg))) {
            free(line);
            return EXIT_FAILURE;
        }

        printf("server says: %s\n> ", received_msg);
    }

    free(line);
    return EXIT_SUCCESS;
}

static bool send_message(int socket_fd, const char *msg, size_t len) {
    size_t total_sent = 0;
    while (total_sent < len) {
        ssize_t sent = send(socket_fd, msg + total_sent, len - total_sent, 0);
        if (sent == -1) {
            perror("send()");
            return false;
        }
        total_sent += sent;
    }
    return true;
}

static bool receive_message(int socket_fd, char *buffer, size_t buffer_size) {
    memset(buffer, 0, buffer_size);
    ssize_t bytes_read = recv(socket_fd, buffer, buffer_size - 1, 0);
    
    if (bytes_read == -1) {
        perror("recv()");
        return false;
    }
    if (bytes_read == 0) {
        fprintf(stderr, "recv(): server closed the connection\n");
        return false;
    }

    buffer[bytes_read] = '\0';
    return true;
}

static void cleanup(void) {
    if (socket_fd != -1) {
        close(socket_fd);
    }
    if (server_info != NULL) {
        freeaddrinfo(server_info);
    }
}

static void handle_sigint(int sig) {
    (void)sig;  // Unused parameter
    exit(EXIT_SUCCESS);
}