#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

char *test_name_age (cJSON *json) {
            // Extract "name" and "age" fields
            cJSON *name = cJSON_GetObjectItem(json, "name");
            cJSON *age = cJSON_GetObjectItem(json, "age");
            int len = strlen(name->valuestring) + 23;
            char *string = calloc(len, 1);
            if (cJSON_IsString(name) && cJSON_IsNumber(age)) {
                snprintf(string, len, "Name: %s\nOldness: %d\n\0", name->valuestring, age->valueint);
            } else {
                snprintf(string, len, "Error: Invalid JASON structure\n", name->valuestring, age->valueint);
            }
            return string;
}