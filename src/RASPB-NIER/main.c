#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include "fcgiapp.h"
#include "cJSON.h"
#include "responses.h"

#define THREAD_COUNT 4  // Number of worker threads

// Worker thread function
void *handle_request(void *arg)
{
    int rc;
    FCGX_Request request;

    // Initialize the request
    FCGX_InitRequest(&request, 0, 0);

    while (1)
    { 
        // Accept a new request
        rc = FCGX_Accept_r(&request);
        if (rc < 0)
        {
            // Handle error or end of requests
            break;
        }

        if (strcmp(FCGX_GetParam("REQUEST_METHOD", request.envp), "POST") == 0) {  
            char *content_length_str = FCGX_GetParam("CONTENT_LENGTH", request.envp);
            int content_length = content_length_str ? atoi(content_length_str) : 0;
            
            char *json_data = (char *)malloc(content_length + 1);
            if (json_data == NULL) {
                FCGX_FPrintF(request.out, "Content-Type: text/plain\r\n\r\n");
                FCGX_FPrintF(request.out, "Error: Memory allocation failed\n");
                continue;
            }

            FCGX_GetStr(json_data, content_length, request.in);
            json_data[content_length] = '\0';  // Null-terminate the JSON string
            cJSON *json = cJSON_Parse(json_data);
            free(json_data);

            if (json == NULL) {
                FCGX_FPrintF(request.out, "Content-Type: text/plain\r\n\r\n");
                FCGX_FPrintF(request.out, "Error: Invalid JSON\n");
                continue;
            }

            // Send response headers and data
            FCGX_FPrintF(request.out, "Content-Type: text/plain\r\n\r\n");
            
            cJSON *prefix = cJSON_GetObjectItem(json, "prefix");
            if (!cJSON_IsString(prefix) || (prefix->valuestring == NULL)) {
            FCGX_FPrintF(request.out, "Error: Prefix is not a valid string");
            } else {

                char *output;
                if (strcmp(prefix->valuestring, "test_name_age") == 0) {
                    output = test_name_age(json);
                    FCGX_FPrintF(request.out, "%s", output);
                    free(output);
                } else {
                    FCGX_FPrintF(request.out, "Error: Invalid prefix");
                }
            }
            // Clean up JSON object
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

    // Initialize the FastCGI library
    FCGX_Init();

    // Create worker threads
    for (i = 0; i < THREAD_COUNT; i++)
    {
        if (pthread_create(&threads[i], NULL, handle_request, (void *)(long)i))
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

    return 0;
}
