#include <fcgi_stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    while (FCGI_Accept() >= 0) {
        // Set Content-Type for the response
        printf("Content-type: text/html\r\n\r\n");

        // Get the QUERY_STRING environment variable
        char *query_string = getenv("QUERY_STRING");

        // Check if query string is present
        if (query_string != NULL) {
            printf("<html><body>\n");
            printf("<h1>Hello, FastCGI</h1>\n");
            printf("<p>Query String: %s</p>\n", query_string);

            // Parse the query string for specific parameters (e.g., "name")
            char *name = strstr(query_string, "name=");
            if (name) {
                name += 5; // Move past "name="
                printf("<p>Hello, %s!</p>\n", name);
            } else {
                printf("<p>Name not provided in query string.</p>\n");
            }
            printf("</body></html>\n");
        } else {
            printf("<p>No query string provided.</p>\n");
        }
    }
    return 0;
}
