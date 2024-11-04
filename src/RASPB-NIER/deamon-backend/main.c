#include <sys/socket.h>
#include <sys/un.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>

#define SOCKET_PATH "/tmp/nier_backend.sock" 
#define BACKLOG 5 // Number of connections allowed on the incoming queue

void *client_handler(void *client_socket) {
    char buffer[100];
    int bytes_read;
    int client_fd = *(int*)client_socket;
    // Read and echo data from client
    while ((bytes_read = read(client_fd, buffer, sizeof(buffer) - 1)) > 0) {
        buffer[sizeof(buffer) - 1] = '\0';
        printf("Received: %s\n", buffer);
        // Echo the received message back to the client
        if (write(client_fd, buffer, sizeof(buffer)) == -1) {
            perror("write error");
            break;
        }
        memset(buffer, 0, sizeof(buffer));
    }

    if (bytes_read == -1) {
        perror("read error");
    }
    
    close(client_fd); // Close the client connection
}

int main() {
    int server_fd, new_socket;
    struct sockaddr_un addr;
    printf("Server is starting\n");

    // 1. Create a socket
    if ((server_fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        perror("socket error");
        exit(EXIT_FAILURE);
    }

    // 2. Configure the socket address structure
    memset(&addr, 0, sizeof(struct sockaddr_un));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);

    // 3. Bind the socket to a file path
    unlink(SOCKET_PATH); // Remove any existing socket file
    if (bind(server_fd, (struct sockaddr*)&addr, sizeof(struct sockaddr_un)) == -1) {
        perror("bind error");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    // 4. Set the socket to listen for incoming connections
    if (listen(server_fd, BACKLOG) == -1) {
        perror("listen error");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    printf("Server is listening on %s\n", SOCKET_PATH);

    // 5. Accept connections in a loop
    while (1) {
        if ((new_socket = accept(server_fd, NULL, NULL)) == -1) {
            perror("accept error");
            continue;
        }
        int *client_socket = malloc(sizeof(int));
        if (client_socket == NULL) {
            perror("malloc failed");
            close(new_socket);
            continue;
        }
        *client_socket = new_socket;
        pthread_t thread_id;
        if (pthread_create(&thread_id, NULL, client_handler, client_socket) != 0) {
            perror("pthread_create failed");
            close(new_socket);
            free(client_socket);
            continue;
        }

        // Detach the thread to reclaim resources when it finishes
        pthread_detach(thread_id);
    }

    // 6. Clean up
    close(server_fd);
    unlink(SOCKET_PATH);
    return 0;
}