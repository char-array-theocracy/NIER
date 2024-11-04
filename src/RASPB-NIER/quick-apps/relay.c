#include <fcgi_stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdio.h>
#include <unistd.h>
#define SOCKET_PATH "/tmp/nier_backend.sock"

int main(void) {            
    int client_fd;
    struct sockaddr_un addr;
    char buffer[100];

    if ((client_fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        perror("socket error");
        exit(EXIT_FAILURE);
    }

    memset(&addr, 0, sizeof(struct sockaddr_un));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);

    while (FCGI_Accept() >= 0) {

        // Get the QUERY_STRING environment variable
        char *query_string = getenv("QUERY_STRING");

        if (connect(client_fd, (struct sockaddr*)&addr, sizeof(struct sockaddr_un)) == -1) {
            perror("connect error");
            close(client_fd);
            exit(EXIT_FAILURE);
        }

        if (write(client_fd, query_string, strlen(query_string)) == -1) {
            perror("write error");
            close(client_fd);
            exit(EXIT_FAILURE);
        }


        // Set Content-Type for the response
        printf("Content-type: text/html\r\n\r\n");


        // Check if query string is present
        if (query_string != NULL) {
            printf("<html><body>\n");
            printf("<h1>Hello, FastCGI</h1>\n");

            // 5. Receive a response from the server
            int bytes_read = read(client_fd, buffer, sizeof(buffer) - 1);
            if (bytes_read > 0) {
                buffer[bytes_read] = '\0'; // Null-terminate the received data
                printf("<p>Received from server: %s<p>\n", buffer);
            } else {
                perror("read error");
            }

            // Parse the query string for specific parameters (e.g., "name")
            char *name = strstr(query_string, "name=");
            if (name) {
                name += 5; // Move past "name="
                printf("<p>%s!</p>\n", query_string);
            } else {
                printf("<p>Name not provided in query string.</p>\n");
            }
            printf("</body></html>\n");
        } else {
            printf("<p>No query string provided.</p>\n");
        }
    }
    close(client_fd);
    return 0;
}
