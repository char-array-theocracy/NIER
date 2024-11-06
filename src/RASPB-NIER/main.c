#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <pwd.h>
#include <limits.h>
#include <errno.h>

#include "fcgiapp.h"
#include "cJSON.h"
#include "responses.h"

#define PATH_MAX 4096
#define THREAD_COUNT 4  
#define MAX_SESSIONS 50
#define TOKEN_SIZE 32

FILE *log_file;
pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;


typedef struct {
    int sock;
    int thread_id;
} thread_data_t;

void init_logging() {
    // Get the current user's home directory
    struct passwd *pw = getpwuid(getuid());
    if (pw == NULL) {
        perror("Failed to get user info");
        exit(1);
    }
    const char *homedir = pw->pw_dir;

    // Construct the log directory path: /home/$USER/NIER/logs
    char log_dir[PATH_MAX];
    snprintf(log_dir, sizeof(log_dir), "%s/NIER/logs", homedir);

    // Check if the directory exists
    struct stat st = {0};
    if (stat(log_dir, &st) == -1) {
        // Directory does not exist, attempt to create it
        if (mkdir(log_dir, 0755) != 0) {
            perror("Failed to create log directory");
            exit(1);
        }
    } else if (!S_ISDIR(st.st_mode)) {
        // Path exists but is not a directory
        fprintf(stderr, "Log path exists but is not a directory: %s\n", log_dir);
        exit(1);
    }

    // Construct the log file path: /home/$USER/NIER/logs/backend.log
    char log_file_path[PATH_MAX];
    snprintf(log_file_path, sizeof(log_file_path), "%s/backend.log", log_dir);

    // Open the log file in append mode, create it if it doesn't exist
    log_file = fopen(log_file_path, "a");
    if (log_file == NULL) {
        perror("Failed to open log file");
        exit(1);
    }
}

void *handle_request(void *arg)
{
    thread_data_t *data = (thread_data_t *)arg;
    int sock = data->sock;
    int thread_id = data->thread_id;
    int rc;
    FCGX_Request request;

    // Initialize the request with the socket
    FCGX_InitRequest(&request, sock, 0);

    while (1)
    {
        // Accept a new request
        rc = FCGX_Accept_r(&request);
        if (rc < 0)
        {
            break;
        }

        if (strcmp(FCGX_GetParam("REQUEST_METHOD", request.envp), "POST") == 0) {
            char *content_length_str = FCGX_GetParam("CONTENT_LENGTH", request.envp);
            int content_length = content_length_str ? atoi(content_length_str) : 0;

            char *json_data = (char *)malloc(content_length + 1);
            if (json_data == NULL) {
                FCGX_FPrintF(request.out, "Content-Type: text/plain\r\n\r\n");
                FCGX_FPrintF(request.out, "Error: Memory allocation failed\n");
                FCGX_Finish_r(&request);  // Finish the request before continuing
                continue;
            }

            clock_t start, end;
            double cpu_time_used;
            start = clock();
            char time_str[20];
            time_t now = time(NULL);
            struct tm *t = localtime(&now);

            FCGX_GetStr(json_data, content_length, request.in);
            json_data[content_length] = '\0';  // Null-terminate the JSON string
            cJSON *json = cJSON_Parse(json_data);
            free(json_data);

            if (json == NULL) {
                FCGX_FPrintF(request.out, "Content-Type: text/plain\r\n\r\n");
                FCGX_FPrintF(request.out, "Error: Invalid JSON\n");
                FCGX_Finish_r(&request);  // Finish the request before continuing
                continue;
            }

            // Send response headers
            FCGX_FPrintF(request.out, "Content-Type: text/plain\r\n\r\n");

            cJSON *prefix = cJSON_GetObjectItem(json, "prefix");
            char *prefix_value = NULL;  // Initialize prefix_value for logging

            if (!cJSON_IsString(prefix) || (prefix->valuestring == NULL)) {
                FCGX_FPrintF(request.out, "Error: Prefix is not a valid string");
            } else {
                prefix_value = prefix->valuestring;  // Store for logging

                char *output;
                if (strcmp(prefix_value, "test_name_age") == 0) {
                    output = test_name_age(json);
                    FCGX_FPrintF(request.out, "%s", output);
                    free(output);
                } else {
                    FCGX_FPrintF(request.out, "Error: Invalid prefix");
                }
            }

            end = clock();
            cpu_time_used = ((double)(end - start) / CLOCKS_PER_SEC) * 1000;

            // Logging with thread safety
            pthread_mutex_lock(&log_mutex);
            strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", t);
            fprintf(log_file, "[%s] Worker: %d, type: %s, cpu time: %.2f milliseconds\n",
                    time_str, thread_id, prefix_value ? prefix_value : "unknown", cpu_time_used);
            fflush(log_file);
            pthread_mutex_unlock(&log_mutex);

            cJSON_Delete(json);

        } else {
            FCGX_FPrintF(request.out, "Content-Type: text/plain\r\n\r\n");
            FCGX_FPrintF(request.out, "Error: Only POST method is allowed\n");
        }
        // Finish the request
        FCGX_Finish_r(&request);
    }

    // Clean up
    FCGX_Free(&request, 1);
    return NULL;
}

int main(int argc, char *argv[])
{
    int i;
    pthread_t threads[THREAD_COUNT];
    thread_data_t thread_data[THREAD_COUNT]; // Array to hold thread data

    // Initialize the FastCGI library
    FCGX_Init();

    // Open the socket
    int sock = FCGX_OpenSocket("/tmp/fcgi.sock-0", 5);
    if (sock < 0) {
        perror("Failed to open socket");
        exit(1);
    }

    // Ensure the socket file has appropriate permissions
    chmod("/tmp/fcgi.sock-0", 0777);

    // Initialize logging
    init_logging();

    // Create worker threads
    for (i = 0; i < THREAD_COUNT; i++)
    {
        thread_data[i].sock = sock;
        thread_data[i].thread_id = i + 1; // Assign thread IDs starting from 1

        if (pthread_create(&threads[i], NULL, handle_request, (void *)&thread_data[i]))
        {
            perror("pthread_create");
            exit(1);
        }
    }

    // Wait for all threads to complete (they run indefinitely in this example)
    for (i = 0; i < THREAD_COUNT; i++)
    {
        pthread_join(threads[i], NULL);
    }

    // Close the log file
    fclose(log_file);

    return 0;
}
