#define _POSIX_C_SOURCE 200809L
#include <netdb.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include "./shared.h"

#define MAX_MSG_SIZE 1024
#define MIN_MSG_SIZE 1
#define RECV_TIMEOUT_SEC 30
#define SEND_TIMEOUT_SEC 30
#define MAX_RETRIES 3

static void cleanup(void);
static void handle_sigint(int sig);
static bool send_message(int socket_fd, const char *msg, size_t len);
static bool receive_message(int socket_fd, char *buffer, size_t buffer_size);
static bool setup_socket_timeouts(int socket_fd);
static bool validate_input(const char *input, size_t len);

static struct addrinfo *server_info = NULL;
static int socket_fd = -1;
static volatile sig_atomic_t running = 1;

int main(void) {
    // Set up signal handlers
    struct sigaction sa = {
        .sa_handler = handle_sigint,
        .sa_flags = 0
    };
    sigemptyset(&sa.sa_mask);
    
    if (sigaction(SIGINT, &sa, NULL) == -1 ||
        sigaction(SIGTERM, &sa, NULL) == -1) {
        perror("sigaction");
        return EXIT_FAILURE;
    }
    signal(SIGPIPE, SIG_IGN);
    atexit(cleanup);

    // Initialize address info
    struct addrinfo hints = {
        .ai_family = AF_UNSPEC,
        .ai_socktype = SOCK_STREAM,
        .ai_flags = AI_PASSIVE
    };

    int rv = getaddrinfo(NULL, PORT, &hints, &server_info);
    if (rv != 0) {
        fprintf(stderr, "getaddrinfo(): %s\n", gai_strerror(rv));
        return EXIT_FAILURE;
    }

    // Create and connect socket
    socket_fd = socket(server_info->ai_family, server_info->ai_socktype,
                      server_info->ai_protocol);
    if (socket_fd == -1) {
        perror("socket()");
        return EXIT_FAILURE;
    }

    // Set socket options
    if (!setup_socket_timeouts(socket_fd)) {
        return EXIT_FAILURE;
    }

    rv = connect(socket_fd, server_info->ai_addr, server_info->ai_addrlen);
    if (rv == -1) {
        perror("connect()");
        return EXIT_FAILURE;
    }

    freeaddrinfo(server_info);
    server_info = NULL;

    // Main communication loop
    char received_msg[MAX_MSG_SIZE];
    char *line = NULL;
    size_t line_cap = 0;
    ssize_t line_len;

    printf("> ");
    while (running && (line_len = getline(&line, &line_cap, stdin)) > 0) {
        if (line_len > 0 && line[line_len - 1] == '\n') {
            line[--line_len] = '\0';
        }

        if (!validate_input(line, line_len)) {
            printf("> ");
            continue;
        }

        int retry_count = 0;
        bool success = false;
        while (retry_count < MAX_RETRIES && !success) {
            if (send_message(socket_fd, line, line_len)) {
                if (receive_message(socket_fd, received_msg, sizeof(received_msg))) {
                    success = true;
                    printf("server says: %s\n> ", received_msg);
                }
            }
            if (!success) {
                retry_count++;
                if (retry_count < MAX_RETRIES) {
                    fprintf(stderr, "Retrying... (%d/%d)\n", retry_count, MAX_RETRIES);
                    sleep(1);
                }
            }
        }

        if (!success) {
            fprintf(stderr, "Communication failed after %d retries\n", MAX_RETRIES);
            break;
        }
    }

    free(line);
    return EXIT_SUCCESS;
}

static bool validate_input(const char *input, size_t len) {
    if (len < MIN_MSG_SIZE || len >= MAX_MSG_SIZE) {
        fprintf(stderr, "Message length must be between %d and %d bytes\n",
                MIN_MSG_SIZE, MAX_MSG_SIZE - 1);
        return false;
    }

    // Check for printable characters only
    for (size_t i = 0; i < len; i++) {
        if (input[i] != '\0' && !isprint((unsigned char)input[i])) {
            fprintf(stderr, "Message contains invalid characters\n");
            return false;
        }
    }
    return true;
}

static bool setup_socket_timeouts(int socket_fd) {
    struct timeval timeout = {
        .tv_sec = RECV_TIMEOUT_SEC,
        .tv_usec = 0
    };

    if (setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0 ||
        setsockopt(socket_fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0) {
        perror("setsockopt failed");
        return false;
    }

    int yes = 1;
    if (setsockopt(socket_fd, SOL_SOCKET, SO_KEEPALIVE, &yes, sizeof(yes)) < 0) {
        perror("setsockopt failed");
        return false;
    }

    return true;
}

static bool send_message(int socket_fd, const char *msg, size_t len) {
    size_t total_sent = 0;
    while (total_sent < len) {
        ssize_t sent = send(socket_fd, msg + total_sent, len - total_sent, MSG_NOSIGNAL);
        if (sent == -1) {
            if (errno == EINTR) continue;
            perror("send()");
            return false;
        }
        total_sent += sent;
    }
    return true;
}

static bool receive_message(int socket_fd, char *buffer, size_t buffer_size) {
    if (!buffer || buffer_size == 0) return false;
    
    memset(buffer, 0, buffer_size);
    size_t total_read = 0;
    
    while (total_read < buffer_size - 1) {
        ssize_t bytes_read = recv(socket_fd, 
                                buffer + total_read, 
                                buffer_size - total_read - 1, 
                                0);
        
        if (bytes_read == -1) {
            if (errno == EINTR) continue;
            perror("recv()");
            return false;
        }
        if (bytes_read == 0) {
            fprintf(stderr, "recv(): server closed the connection\n");
            return false;
        }
        
        total_read += bytes_read;
        if (memchr(buffer, '\0', total_read)) break;
    }
    
    buffer[total_read] = '\0';
    return true;
}

static void cleanup(void) {
    if (socket_fd != -1) {
        shutdown(socket_fd, SHUT_RDWR);
        close(socket_fd);
        socket_fd = -1;
    }
    if (server_info != NULL) {
        freeaddrinfo(server_info);
        server_info = NULL;
    }
}

static void handle_sigint(int sig) {
    (void)sig;
    running = 0;
    exit(EXIT_SUCCESS);
}