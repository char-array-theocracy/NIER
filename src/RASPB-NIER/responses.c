#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <pthread.h>

pthread_mutex_t client_list_mutex = PTHREAD_MUTEX_INITIALIZER;

char *test_name_age (cJSON *json) {
            cJSON *name = cJSON_GetObjectItem(json, "name");
            cJSON *age = cJSON_GetObjectItem(json, "age");
            int len = strlen(name->valuestring) + 22;
            char *string = calloc(len, 1);
            if (cJSON_IsString(name) && cJSON_IsNumber(age)) {
                snprintf(string, len, "Name: %s\nOldness: %d\n\0", name->valuestring, age->valueint);
            } else {
                snprintf(string, len, "Error: Invalid JSON structure\n", name->valuestring, age->valueint);
            }
            return string;
}