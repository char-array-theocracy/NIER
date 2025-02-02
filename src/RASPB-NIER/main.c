#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <pthread.h>
#include <mosquitto.h>
#include <sqlite3.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <cjson/cJSON.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <curl/curl.h>
#include "mongoose.h"
#include "NIER.h"
#include "statements.h"

#define LISTEN_URI "ws://localhost:8000"
#define MQTT_BROKER_URI "0.0.0.0"
#define MQTT_BROKER_PORT 8883
#define MQTT_PSK_IDENTITY "test1"
#define MQTT_PSK_KEY "84fb1595364544af46ad955509b7a07c"
#define BEACON_PORT 54321
#define BEACON_IP "255.255.255.255"
#define MQTT_QOS 2
#define MAX_WS_CONNECTIONS 50
#define MAX_SENSOR_DATA_KB 64

pthread_mutex_t TOTPAttemptsLock;
struct TOTPAttempt *TOTPAttempts;
int TOTPAttemptsSize = 0;
int TOTPAttemptsUsed = 0;
struct mosquitto *mosquittoThing;
int disableMQTT = 0;
int debugFlag = 0;
sqlite3 *database = NULL;
struct mg_http_serve_opts serveOptions = {.root_dir = "./assets/"};
struct mg_connection *WSConnections[MAX_WS_CONNECTIONS];
int activeWSConnections;
pthread_mutex_t WSConnectionsLock;

void *udpBeaconTask(UNUSED void *arg)
{
    struct ifaddrs *interfaces = NULL;
    struct ifaddrs *tempAddress = NULL;
    cJSON *broadcastMessageJSON = cJSON_CreateObject();
    if (broadcastMessageJSON)
    {
        if (getifaddrs(&interfaces) == 0)
        {
            tempAddress = interfaces;
            while (tempAddress != NULL)
            {
                if (tempAddress->ifa_addr->sa_family == AF_INET && strcmp(tempAddress->ifa_name, "lo") != 0 && strstr(tempAddress->ifa_name, "wl") != NULL)
                {
                    char ip[INET_ADDRSTRLEN];
                    void *addr = &((struct sockaddr_in *)tempAddress->ifa_addr)->sin_addr;
                    inet_ntop(AF_INET, addr, ip, INET_ADDRSTRLEN);
                    NIER_LOGI("NIER", "UDP beacon broadcasting IP: %s", ip);
                    char ipWithDomain[256];
                    snprintf(ipWithDomain, 255, "mqtts://%s:8883", ip);
                    cJSON_AddStringToObject(broadcastMessageJSON, "ip", ipWithDomain);
                }
                tempAddress = tempAddress->ifa_next;
            }
        }
        else
        {
            NIER_LOGE("NIER", "Failed to acquire ip address for UDP broadcast");
            return NULL;
        }
        char broadcastMessage[256] = {0};
        snprintf(broadcastMessage, 255, "%s", cJSON_PrintUnformatted(broadcastMessageJSON));
        cJSON_Delete(broadcastMessageJSON);

        int sockfd;
        struct sockaddr_in broadcastAddress;
        int broadcastEnable = 1;

        if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
        {
            NIER_LOGE("NIER", "Failed to create the UDP broadcast socket");
            return NULL;
        }

        if (setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, &broadcastEnable, sizeof(broadcastEnable)) < 0)
        {
            NIER_LOGE("NIER", "Failed to set up the UDP broadcast socket");
            return NULL;
        }

        memset(&broadcastAddress, 0, sizeof(broadcastAddress));
        broadcastAddress.sin_family = AF_INET;
        broadcastAddress.sin_port = htons(BEACON_PORT);
        broadcastAddress.sin_addr.s_addr = inet_addr(BEACON_IP);

        for (;;)
        {
            if (sendto(sockfd, broadcastMessage, strlen(broadcastMessage), 0, (struct sockaddr *)&broadcastAddress, sizeof(broadcastAddress)) != (ssize_t)strlen(broadcastMessage))
            {
                NIER_LOGW("NIER", "Failed to send broadcast message");
            }
            sleep(2);
        }
    }
    freeifaddrs(interfaces);
    return NULL;
}

void mosqetLog(UNUSED struct mosquitto *mosq, UNUSED void *userdata, UNUSED int level, const char *str)
{
    NIER_LOGD("Mosquitto", "%s", str);
}

void mosqetOnConnect(struct mosquitto *mosq, UNUSED void *obj, int rc)
{
    if (rc == 0)
    {
        NIER_LOGI("Mosquitto", "Connected to MQTT broker");
        mosquitto_subscribe(mosq, NULL, "devices/presence", MQTT_QOS);
        mosquitto_subscribe(mosq, NULL, "devices/+/status", MQTT_QOS);
        mosquitto_subscribe(mosq, NULL, "devices/+/responses", MQTT_QOS);
        mosquitto_subscribe(mosq, NULL, "devices/+/temperatureHumiditySensor", MQTT_QOS);
    }
    else
    {
        NIER_LOGI("Mosquitto", "Failed to connect to broker, return code: %d", rc);
    }
}

void mosqetOnMessage(UNUSED struct mosquitto *mosq, UNUSED void *obj, const struct mosquitto_message *msg)
{
    if (strncmp(msg->topic, "devices/presence", 16) == 0)
    {
        cJSON *receivedPresence = cJSON_Parse((char *)msg->payload);
        if (receivedPresence == NULL)
        {
            NIER_LOGE("NIER", "Failed to parse received JSON");
            return;
        }

        cJSON *deviceIDObject = cJSON_GetObjectItem(receivedPresence, "deviceID");
        if (deviceIDObject == NULL)
        {
            NIER_LOGE("NIER", "Failed to parse deviceID from received JSON");
            cJSON_Delete(receivedPresence);
            return;
        }
        char *deviceID = cJSON_GetStringValue(deviceIDObject);

        cJSON *isOnlineObject = cJSON_GetObjectItem(receivedPresence, "online");
        if (isOnlineObject == NULL)
        {
            NIER_LOGE("NIER", "Failed to parse online state from received JSON");
            cJSON_Delete(receivedPresence);
            return;
        }
        int isOnline = cJSON_GetNumberValue(isOnlineObject);

        cJSON *deviceTypeObject = cJSON_GetObjectItem(receivedPresence, "deviceType");
        if (deviceTypeObject == NULL)
        {
            NIER_LOGE("NIER", "Failed to parse deviceType from received JSON");
            cJSON_Delete(receivedPresence);
            return;
        }
        char *deviceType = cJSON_GetStringValue(deviceTypeObject);

        sqlite3_stmt *stmt = NULL;

        if (sqlite3_prepare_v2(database, checkDeviceOnlineState, -1, &stmt, NULL) != SQLITE_OK)
        {
            NIER_LOGE("SQLite", "Failed to prepare checkDeviceQuery: %s", sqlite3_errmsg(database));
            cJSON_Delete(receivedPresence);
            return;
        }

        sqlite3_bind_text(stmt, 1, deviceID, -1, SQLITE_STATIC);

        int rc = sqlite3_step(stmt);
        if (rc == SQLITE_ROW)
        {
            int currentOnline = sqlite3_column_int(stmt, 0);
            const char *currentDeviceType = (const char *)sqlite3_column_text(stmt, 1);
            sqlite3_finalize(stmt);

            if (currentOnline != isOnline || (currentDeviceType != NULL && strcmp(currentDeviceType, deviceType) != 0))
            {
                if (sqlite3_prepare_v2(database, updateDevice, -1, &stmt, NULL) != SQLITE_OK)
                {
                    NIER_LOGE("SQLite", "Failed to prepare updateDeviceQuery: %s", sqlite3_errmsg(database));
                    cJSON_Delete(receivedPresence);
                    return;
                }
                sqlite3_bind_int(stmt, 1, isOnline);
                sqlite3_bind_text(stmt, 2, deviceType, -1, SQLITE_STATIC);
                sqlite3_bind_text(stmt, 3, deviceID, -1, SQLITE_STATIC);

                if (sqlite3_step(stmt) != SQLITE_DONE)
                {
                    NIER_LOGE("SQLite", "Failed to update device: %s", sqlite3_errmsg(database));
                }
                else
                {
                    NIER_LOGI("NIER", "Updated device %s: ONLINE=%d, DEVICE_TYPE=%s.", deviceID, isOnline, deviceType);
                }
                sqlite3_finalize(stmt);
            }
            else
            {
                NIER_LOGI("NIER", "Device %s is already in the desired state (ONLINE=%d, DEVICE_TYPE=%s).", deviceID, isOnline, deviceType);
            }
        }
        else if (rc == SQLITE_DONE)
        {
            sqlite3_finalize(stmt);

            if (sqlite3_prepare_v2(database, insertDevice, -1, &stmt, NULL) != SQLITE_OK)
            {
                NIER_LOGE("SQLite", "Failed to prepare insertDeviceQuery: %s", sqlite3_errmsg(database));
                cJSON_Delete(receivedPresence);
                return;
            }
            sqlite3_bind_text(stmt, 1, deviceID, -1, SQLITE_STATIC);
            sqlite3_bind_int(stmt, 2, isOnline);
            sqlite3_bind_text(stmt, 3, deviceType, -1, SQLITE_STATIC);

            if (sqlite3_step(stmt) != SQLITE_DONE)
            {
                NIER_LOGE("SQLite", "Failed to insert new device: %s", sqlite3_errmsg(database));
            }
            else
            {
                NIER_LOGI("NIER", "Inserted new device %s with ONLINE=%d, DEVICE_TYPE=%s.", deviceID, isOnline, deviceType);
            }
            sqlite3_finalize(stmt);
        }
        else
        {
            NIER_LOGE("SQLite", "Error checking device presence: %s", sqlite3_errmsg(database));
            sqlite3_finalize(stmt);
        }

        cJSON_Delete(receivedPresence);

        broadcastWSMessage(getDeviceList());
    }
    else if (strstr(msg->topic, "status") != NULL)
    {
        cJSON *deviceStatusJSON = cJSON_CreateObject();
        cJSON *deviceStatusItem = cJSON_Parse(msg->payload);
        char *deviceId = NULL;
        char topicCopy[256] = {0};
        snprintf(topicCopy, sizeof(topicCopy) - 1, "%s", msg->topic);
        if ((deviceId = strtok(topicCopy, "/")) && deviceId != NULL)
        {
            deviceId = strtok(NULL, "/");
        }

        if (deviceId)
            cJSON_AddStringToObject(deviceStatusItem, "deviceId", deviceId);
        cJSON_AddItemToObject(deviceStatusJSON, "deviceStatus", deviceStatusItem);
        broadcastWSMessage(cJSON_PrintUnformatted(deviceStatusJSON));
        cJSON_Delete(deviceStatusJSON);
    }
    else if (strstr(msg->topic, "responses") != NULL)
    {
        cJSON *deviceResponseJSON = cJSON_CreateObject();
        cJSON *deviceResponseItem = cJSON_Parse(msg->payload);
        cJSON *call = cJSON_GetObjectItem(deviceResponseItem, "call");
        char *deviceId = NULL;
        char topicCopy[256] = {0};
        snprintf(topicCopy, sizeof(topicCopy) - 1, "%s", msg->topic);
        if ((deviceId = strtok(topicCopy, "/")) && deviceId != NULL)
        {
            deviceId = strtok(NULL, "/");
        }

        if (deviceId)
            cJSON_AddStringToObject(deviceResponseItem, "deviceId", deviceId);
        cJSON_AddItemToObject(deviceResponseJSON, "deviceResponse", deviceResponseItem);
        cJSON *deviceResponse = cJSON_GetObjectItem(deviceResponseJSON, "deviceResponse");

        if (strncmp(cJSON_GetStringValue(call), "changeSwitchState", 17) == 0)
        {
            sqlite3_stmt *updateDeviceDataStmt = NULL;
            cJSON *data = cJSON_GetObjectItem(deviceResponse, "state");
            char dataFinal[16] = {0};
            snprintf(dataFinal, 15, "%d", (int)cJSON_GetNumberValue(data));
            if (sqlite3_prepare_v2(database, updateDeviceData, -1, &updateDeviceDataStmt, NULL) != SQLITE_OK)
            {
                NIER_LOGE("SQLite", "Failed to prepare updateDeviceData statement");
            }
            sqlite3_bind_text(updateDeviceDataStmt, 1, dataFinal, -1, SQLITE_STATIC);
            sqlite3_bind_text(updateDeviceDataStmt, 2, deviceId, -1, SQLITE_STATIC);
            if (sqlite3_step(updateDeviceDataStmt) != SQLITE_DONE)
            {
                NIER_LOGE("SQLite", "Failed to update data:  %s", sqlite3_errmsg(database));
            }
            sqlite3_finalize(updateDeviceDataStmt);
            broadcastWSMessage(getDeviceList());
        }
        else
        {
            broadcastWSMessage(cJSON_PrintUnformatted(deviceResponseJSON));
        }
        cJSON_Delete(deviceResponseJSON);
    }
    else if (strstr(msg->topic, "temperatureHumiditySensor") != NULL)
    {
        char *deviceId = NULL;
        char topicCopy[256] = {0};
        snprintf(topicCopy, sizeof(topicCopy) - 1, "%s", msg->topic);
        if ((deviceId = strtok(topicCopy, "/")) && deviceId != NULL)
        {
            deviceId = strtok(NULL, "/");
        }

        cJSON *receivedSensorDataJSON = cJSON_Parse(msg->payload);
        cJSON *sensorDataArray = NULL;

        sqlite3_stmt *checkDeviceDataStmt = NULL;
        if (sqlite3_prepare_v2(database, checkDeviceData, -1, &checkDeviceDataStmt, NULL) != SQLITE_OK)
        {
            NIER_LOGE("SQLite", "Failed to prepare checkDeviceDataStmt: %s", sqlite3_errmsg(database));
            return;
        }

        sqlite3_bind_text(checkDeviceDataStmt, 1, deviceId, -1, SQLITE_STATIC);
        if (sqlite3_step(checkDeviceDataStmt) == SQLITE_ROW)
        {
            const unsigned char *existingData = sqlite3_column_text(checkDeviceDataStmt, 0);
            if (existingData)
            {
                sensorDataArray = cJSON_Parse((const char *)existingData);
            }
        }

        if (!sensorDataArray)
        {
            sensorDataArray = cJSON_CreateArray();
        }

        cJSON_AddItemToArray(sensorDataArray, receivedSensorDataJSON);
        char *dataFinal = cJSON_PrintUnformatted(sensorDataArray);
        if (strlen(dataFinal) >= MAX_SENSOR_DATA_KB * 1000)
        {
            NIER_LOGW("NIER", "Sensor data reached 64 kB, clearing...");
            free(dataFinal);
            dataFinal = NULL;
        }

        sqlite3_finalize(checkDeviceDataStmt);

        sqlite3_stmt *updateDeviceDataStmt = NULL;
        if (sqlite3_prepare_v2(database, updateDeviceData, -1, &updateDeviceDataStmt, NULL) != SQLITE_OK)
        {
            NIER_LOGE("SQLite", "Failed to prepare updateDeviceData statement");
            free(dataFinal);
            cJSON_Delete(sensorDataArray);
            return;
        }

        if (dataFinal == NULL)
        {
            dataFinal = strdup("[]");
        }

        sqlite3_bind_text(updateDeviceDataStmt, 1, dataFinal, -1, SQLITE_STATIC);
        sqlite3_bind_text(updateDeviceDataStmt, 2, deviceId, -1, SQLITE_STATIC);

        if (sqlite3_step(updateDeviceDataStmt) != SQLITE_DONE)
        {
            NIER_LOGE("SQLite", "Failed to update data: %s", sqlite3_errmsg(database));
        }

        sqlite3_finalize(updateDeviceDataStmt);
        free(dataFinal);
        cJSON_Delete(sensorDataArray);

        broadcastWSMessage(getDeviceList());
    }
}

void mosqetOnDisconnect(UNUSED struct mosquitto *mosq, UNUSED void *obj, int rc)
{
    NIER_LOGE("Mosquitto", "Disconnected from broker with return code: %d", rc);
    while ((mosquitto_connect(mosquittoThing, MQTT_BROKER_URI, MQTT_BROKER_PORT, 10)) != MOSQ_ERR_SUCCESS)
    {
        NIER_LOGW("Mosquitto", "Failed to reconnect to broker");
        sleep(4);
    }
}

void *mongoosePollThread(void *arg)
{
    struct mg_mgr *mgr = (struct mg_mgr *)arg;
    for (;;)
    {
        mg_mgr_poll(mgr, 1000);
    }
    return NULL;
}

void httpHandler(struct mg_connection *c, int ev, void *ev_data)
{
    if (ev == MG_EV_HTTP_MSG)
    {
        struct mg_http_message *hm = (struct mg_http_message *)ev_data;
        char userName[256] = {0};
        char addressHex[33] = {0};
        mgAddrToHex(&c->rem, addressHex, sizeof(addressHex));
        cleanExpiredSessions();
        bool isAuthenticated = checkSession(hm, c, userName);

        if (!mg_match(hm->uri, mg_str("/icons/*"), NULL))
        {
            if (!isAuthenticated)
            {
                if (!(mg_match(hm->uri, mg_str("/login"), NULL) ||
                      mg_match(hm->uri, mg_str("/api/login"), NULL)))
                {
                    mg_http_reply(c, 302, "Location: /login\r\n", "");
                    return;
                }
            }
            else
            {
                if (mg_match(hm->uri, mg_str("/login"), NULL) ||
                    mg_match(hm->uri, mg_str("/api/login"), NULL) || mg_match(hm->uri, mg_str("/"), NULL))
                {
                    mg_http_reply(c, 302, "Location: /dashboard\r\n", "");
                    return;
                }
            }
        }

        if (mg_match(hm->uri, mg_str("/dashboard"), NULL) && isAuthenticated)
        {
            mg_http_serve_file(c, hm, "./assets/dashboard.html", &serveOptions);
        }
        else if (mg_match(hm->uri, mg_str("/login"), NULL))
        {
            mg_http_serve_file(c, hm, "./assets/login.html", &serveOptions);
        }
        else if (mg_match(hm->uri, mg_str("/test"), NULL) && isAuthenticated)
        {
            mg_http_serve_file(c, hm, "./assets/test.html", &serveOptions);
        }
        else if (mg_match(hm->uri, mg_str("/websocket"), NULL) && isAuthenticated)
        {
            mg_ws_upgrade(c, hm, "Access-Control-Allow-Origin: *\r\n");
        }
        else if (mg_match(hm->uri, mg_str("/api/logout"), NULL) && isAuthenticated)
        {
            struct mg_str *cookieHeader = mg_http_get_header(hm, "Cookie");
            if (!cookieHeader)
            {
                mg_http_reply(c, 500, "", "Internal Server Error\n");
                return;
            }
            char cookieBuf[256] = {0};
            snprintf(cookieBuf, sizeof(cookieBuf), "%.*s", (int)cookieHeader->len, cookieHeader->buf);
            char *sessionPtr = strstr(cookieBuf, "session_id=");
            if (!sessionPtr)
            {
                mg_http_reply(c, 500, "", "Internal Server Error\n");
                return;
            }
            sessionPtr += strlen("session_id=");
            sqlite3_stmt *deleteExpiredSessionStmt = NULL;
            if (sqlite3_prepare_v2(database, deleteExpiredSession, -1, &deleteExpiredSessionStmt, NULL) != SQLITE_OK)
            {
                mg_http_reply(c, 500, "", "Internal Server Error\n");
                return;
            }
            NIER_LOGI("NIER", "Logout id: %s", sessionPtr);
            sqlite3_bind_text(deleteExpiredSessionStmt, 1, sessionPtr, -1, SQLITE_STATIC);
            sqlite3_step(deleteExpiredSessionStmt);
            sqlite3_finalize(deleteExpiredSessionStmt);
            mg_http_reply(c, 302, "Location: /login\r\n", "");
            return;
        }
        else if (mg_match(hm->uri, mg_str("/api/login"), NULL))
        {
            pthread_mutex_lock(&TOTPAttemptsLock);
            TOTPAttempts = cleanTOTPAttempts(TOTPAttempts, &TOTPAttemptsUsed, TOTPAttemptsSize);
            if (TOTPAttempts == NULL)
                NIER_LOGE("NIER", "Failed to clean TOTP Attempts");
            for (int i = 0; i < TOTPAttemptsUsed; i++)
            {
                if (strncmp(TOTPAttempts[i].ipHex, addressHex, 32) == 0)
                {
                    int timeDifference = (int)(time(NULL) - TOTPAttempts[i].attemptTime);
                    if (timeDifference < 30)
                    {
                        NIER_LOGW("NIER", "IP: %s in login attempt timeout", mgHexToAddr(addressHex));
                        mg_http_reply(c, 400, "", "Please try again in %d seconds\n", 30 - timeDifference);
                        pthread_mutex_unlock(&TOTPAttemptsLock);
                        return;
                    }
                }
            }
            if ((TOTPAttemptsUsed + 1) > TOTPAttemptsSize)
            {
                TOTPAttemptsSize *= 2;
                struct TOTPAttempt *temp = realloc(TOTPAttempts, TOTPAttemptsSize * sizeof(struct TOTPAttempt));
                if (temp == NULL)
                {
                    NIER_LOGE("NIER", "Failed to reallocate TOTP attempts array");
                    mg_http_reply(c, 500, "", "Internal server error\n");
                    return;
                }
                else
                {
                    TOTPAttempts = temp;
                }
            }
            strncpy(TOTPAttempts[TOTPAttemptsUsed].ipHex, addressHex, sizeof(TOTPAttempts[TOTPAttemptsUsed].ipHex));
            TOTPAttempts[TOTPAttemptsUsed].ipHex[sizeof(TOTPAttempts[TOTPAttemptsUsed].ipHex) - 1] = '\0';
            TOTPAttempts[TOTPAttemptsUsed].attemptTime = time(NULL);
            TOTPAttemptsUsed++;
            pthread_mutex_unlock(&TOTPAttemptsLock);
            if (hm->body.len > 1023)
            {
                mg_http_reply(c, 400, "", "Username or password is too long\n");
                return;
            }
            char buffer[1024];
            memset(buffer, 0, sizeof(buffer));
            snprintf(buffer, sizeof(buffer), "%.*s", (int)hm->body.len, hm->body.buf);

            cJSON *loginInfo = cJSON_Parse(buffer);
            if (!loginInfo)
            {
                mg_http_reply(c, 400, "", "Invalid JSON\n");
                return;
            }
            cJSON *password = cJSON_GetObjectItem(loginInfo, "password");
            cJSON *totpCode = cJSON_GetObjectItem(loginInfo, "TOTP");
            cJSON *username = cJSON_GetObjectItem(loginInfo, "username");

            if (!username || !cJSON_IsString(username) || !password || !cJSON_IsString(password))
            {
                cJSON_Delete(loginInfo);
                mg_http_reply(c, 400, "", "Missing or invalid username/password\n");
                return;
            }
            sqlite3_stmt *totpQueryStatement = NULL;
            if (sqlite3_prepare_v2(database, totpPasswordQuery, -1, &totpQueryStatement, NULL) != SQLITE_OK)
            {
                cJSON_Delete(loginInfo);
                mg_http_reply(c, 500, "", "Internal Server Error\n");
                return;
            }
            sqlite3_bind_text(totpQueryStatement, 1, cJSON_GetStringValue(username), -1, SQLITE_STATIC);
            switch (sqlite3_step(totpQueryStatement))
            {
            case SQLITE_ROW:
            {
                const char *dbPassword = (const char *)sqlite3_column_text(totpQueryStatement, 0);
                const unsigned char *dbTotpCode = sqlite3_column_text(totpQueryStatement, 1);
                if (!dbTotpCode || !dbPassword)
                {
                    mg_http_reply(c, 500, "", "Internal server error\n");
                    break;
                }
                char generated[7];
                memset(generated, 0, sizeof(generated));
                if (generateTOTP((const char *)dbTotpCode, 30, 6, generated) != 0)
                {
                    mg_http_reply(c, 500, "", "Internal Server Error\n");
                    break;
                }
                if (strncmp(generated, cJSON_GetStringValue(totpCode), 6) == 0 && strncmp(dbPassword, cJSON_GetStringValue(password), strlen(cJSON_GetStringValue(password))) == 0)
                {
                    createSession(cJSON_GetStringValue(username), c);
                }
                else
                {
                    mg_http_reply(c, 300, "", "Incorrect login details\n");
                }
                break;
            }
            case SQLITE_DONE:
                mg_http_reply(c, 200, "", "Incorrect login details\n");
                break;
            default:
                mg_http_reply(c, 500, "", "Internal Server Error\n");
                break;
            }
            sqlite3_finalize(totpQueryStatement);
            cJSON_Delete(loginInfo);
            return;
        }
        else
        {
            mg_http_serve_dir(c, hm, &serveOptions);
        }
    }
    else if (ev == MG_EV_WS_MSG)
    {
        struct mg_ws_message *wm = (struct mg_ws_message *)ev_data;
        cJSON *wsMessage = cJSON_Parse(wm->data.buf);
        if (wsMessage == NULL)
        {
            NIER_LOGW("NIER", "Failed to parse WS message JSON");
            char result[] = "{\"error\":\"invalid JSON\"}";
            mg_ws_send(c, result, strlen(result), WEBSOCKET_OP_TEXT);
            return;
        }
        cJSON *callJSON = cJSON_GetObjectItem(wsMessage, "call");
        if (callJSON == NULL)
        {
            char result[] = "{\"error\":\"invalid call\"}";
            mg_ws_send(c, result, strlen(result), WEBSOCKET_OP_TEXT);
            cJSON_Delete(wsMessage);
            return;
        }
        char *call = cJSON_GetStringValue(callJSON);

        if (strncmp(call, "listDevices", 11) == 0)
        {
            char *result = getDeviceList();
            mg_ws_send(c, result, strlen(result), WEBSOCKET_OP_TEXT);
        }
        if (strncmp(call, "listCameras", 11) == 0)
        {
            sqlite3_stmt *cameraListStmt;
            cJSON *cameraListJSON = cJSON_CreateObject();
            cJSON *cameraListJSONArray = cJSON_AddArrayToObject(cameraListJSON, "listCameras");
            if (sqlite3_prepare_v2(database, listCameras, -1, &cameraListStmt, NULL) == SQLITE_OK)
            {
                while (sqlite3_step(cameraListStmt) == SQLITE_ROW)
                {
                    cJSON_AddItemToArray(cameraListJSONArray, cJSON_CreateString((const char *)sqlite3_column_text(cameraListStmt, 0)));
                }
                if (sqlite3_finalize(cameraListStmt) != SQLITE_OK)
                {
                    NIER_LOGE("SQLite", "Failed to finalize statement: %s", sqlite3_errmsg(database));
                    cJSON_Delete(cameraListJSON);
                    char result[] = "{\"error\":\"server error\"}";
                    mg_ws_send(c, result, strlen(result), WEBSOCKET_OP_TEXT);
                    return;
                }
                mg_ws_send(c, cJSON_PrintUnformatted(cameraListJSON), strlen(cJSON_PrintUnformatted(cameraListJSON)), WEBSOCKET_OP_TEXT);
                cJSON_Delete(cameraListJSON);
                return;
            }
            else
            {
                NIER_LOGE("SQLite", "Failed to prepare statement: %s", sqlite3_errmsg(database));
                cJSON_Delete(cameraListJSON);
                char result[] = "{\"error\":\"server error\"}";
                mg_ws_send(c, result, strlen(result), WEBSOCKET_OP_TEXT);
                return;
            }
        }
        else if (strncmp(call, "cameraMessage", 13) == 0)
        {
            cJSON *camerNameJSON = cJSON_GetObjectItem(wsMessage, "camera");
            if (!camerNameJSON)
            {
                char result[] = "{\"error\":\"invalid camera name\"}";
                mg_ws_send(c, result, strlen(result), WEBSOCKET_OP_TEXT);
                cJSON_Delete(wsMessage);
                return;
            }
            cJSON *cameraCommandJSON = cJSON_GetObjectItem(wsMessage, "message");
            if (!camerNameJSON)
            {
                char result[] = "{\"error\":\"invalid camera message\"}";
                mg_ws_send(c, result, strlen(result), WEBSOCKET_OP_TEXT);
                cJSON_Delete(wsMessage);
                return;
            }
            cJSON *cameraCommandCallJSON = cJSON_GetObjectItem(cameraCommandJSON, "call");
            if (!camerNameJSON)
            {
                char result[] = "{\"error\":\"invalid camera call\"}";
                mg_ws_send(c, result, strlen(result), WEBSOCKET_OP_TEXT);
                cJSON_Delete(wsMessage);
                return;
            }
            const char *cameraCall = cJSON_GetStringValue(cameraCommandCallJSON);
            const char *cameraName = cJSON_GetStringValue(camerNameJSON);
            char cameraControlUrl[512];
            char cameraControlUsername[512];
            char cameraControlPassword[512];
            sqlite3_stmt *cameraInfoStmt;
            if (sqlite3_prepare_v2(database, checkCameraValues, -1, &cameraInfoStmt, NULL) == SQLITE_OK)
            {
                sqlite3_bind_text(cameraInfoStmt, 1, cameraName, -1, SQLITE_STATIC);
                if (sqlite3_step(cameraInfoStmt) == SQLITE_ROW)
                {
                    strncpy(cameraControlUrl, (char *)sqlite3_column_text(cameraInfoStmt, 1), 511);
                    strncpy(cameraControlUsername, (char *)sqlite3_column_text(cameraInfoStmt, 2), 511);
                    strncpy(cameraControlPassword, (char *)sqlite3_column_text(cameraInfoStmt, 3), 511);
                }
                else
                {
                    char result[] = "{\"error\":\"unknown camera\"}";
                    mg_ws_send(c, result, strlen(result), WEBSOCKET_OP_TEXT);
                    cJSON_Delete(wsMessage);
                    return;
                }
                if (sqlite3_finalize(cameraInfoStmt) != SQLITE_OK)
                {
                    char result[] = "{\"error\":\"internal server error\"}";
                    mg_ws_send(c, result, strlen(result), WEBSOCKET_OP_TEXT);
                    cJSON_Delete(wsMessage);
                    return;
                }
            }
            else
            {
                NIER_LOGE("SQLite", "Failed to prepare statement: %s", sqlite3_errmsg(database));
                char result[] = "{\"error\":\"internal server error\"}";
                mg_ws_send(c, result, strlen(result), WEBSOCKET_OP_TEXT);
                cJSON_Delete(wsMessage);
                return;
            }

            if (strncmp(cameraCall, "moveLeft", 8) == 0)
            {
                char curlUrl[512];
                snprintf(curlUrl, 511, "%s?cmd=ptzMoveLeft&usr=%s&pwd=%s", cameraControlUrl, cameraControlUsername, cameraControlPassword);

                CURL *curl = curl_easy_init();
                if (curl)
                {
                    curl_easy_setopt(curl, CURLOPT_URL, curlUrl);
                    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, nullWriteCallback);
                    if (curl_easy_perform(curl) != CURLE_OK)
                    {
                        NIER_LOGE("libCURL", "Failed to execute curl");
                        char result[] = "{\"error\":\"internal server error\"}";
                        mg_ws_send(c, result, strlen(result), WEBSOCKET_OP_TEXT);
                        cJSON_Delete(wsMessage);
                        curl_easy_cleanup(curl);
                        return;
                    }
                    curl_easy_cleanup(curl);
                }
                else
                {
                    NIER_LOGE("libCURL", "Failed to initialize easy curl");
                    char result[] = "{\"error\":\"internal server error\"}";
                    mg_ws_send(c, result, strlen(result), WEBSOCKET_OP_TEXT);
                    cJSON_Delete(wsMessage);
                    return;
                }
            }
            else if (strncmp(cameraCall, "moveRight", 9) == 0)
            {
                char curlUrl[512];
                snprintf(curlUrl, 511, "%s?cmd=ptzMoveRight&usr=%s&pwd=%s", cameraControlUrl, cameraControlUsername, cameraControlPassword);

                CURL *curl = curl_easy_init();
                if (curl)
                {
                    curl_easy_setopt(curl, CURLOPT_URL, curlUrl);
                    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, nullWriteCallback);
                    if (curl_easy_perform(curl) != CURLE_OK)
                    {
                        NIER_LOGE("libCURL", "Failed to execute curl");
                        char result[] = "{\"error\":\"internal server error\"}";
                        mg_ws_send(c, result, strlen(result), WEBSOCKET_OP_TEXT);
                        cJSON_Delete(wsMessage);
                        curl_easy_cleanup(curl);
                        return;
                    }
                    curl_easy_cleanup(curl);
                }
                else
                {
                    NIER_LOGE("libCURL", "Failed to initialize easy curl");
                    char result[] = "{\"error\":\"internal server error\"}";
                    mg_ws_send(c, result, strlen(result), WEBSOCKET_OP_TEXT);
                    cJSON_Delete(wsMessage);
                    return;
                }
            }
            else if (strncmp(cameraCall, "moveUp", 6) == 0)
            {
                char curlUrl[512];
                snprintf(curlUrl, 511, "%s?cmd=ptzMoveUp&usr=%s&pwd=%s", cameraControlUrl, cameraControlUsername, cameraControlPassword);

                CURL *curl = curl_easy_init();
                if (curl)
                {
                    curl_easy_setopt(curl, CURLOPT_URL, curlUrl);
                    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, nullWriteCallback);
                    if (curl_easy_perform(curl) != CURLE_OK)
                    {
                        NIER_LOGE("libCURL", "Failed to execute curl");
                        char result[] = "{\"error\":\"internal server error\"}";
                        mg_ws_send(c, result, strlen(result), WEBSOCKET_OP_TEXT);
                        cJSON_Delete(wsMessage);
                        curl_easy_cleanup(curl);
                        return;
                    }
                    curl_easy_cleanup(curl);
                }
                else
                {
                    NIER_LOGE("libCURL", "Failed to initialize easy curl");
                    char result[] = "{\"error\":\"internal server error\"}";
                    mg_ws_send(c, result, strlen(result), WEBSOCKET_OP_TEXT);
                    cJSON_Delete(wsMessage);
                    return;
                }
            }
            else if (strncmp(cameraCall, "moveDown", 8) == 0)
            {
                char curlUrl[512];
                snprintf(curlUrl, 511, "%s?cmd=ptzMoveDown&usr=%s&pwd=%s", cameraControlUrl, cameraControlUsername, cameraControlPassword);

                CURL *curl = curl_easy_init();
                if (curl)
                {
                    curl_easy_setopt(curl, CURLOPT_URL, curlUrl);
                    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, nullWriteCallback);
                    if (curl_easy_perform(curl) != CURLE_OK)
                    {
                        NIER_LOGE("libCURL", "Failed to execute curl");
                        char result[] = "{\"error\":\"internal server error\"}";
                        mg_ws_send(c, result, strlen(result), WEBSOCKET_OP_TEXT);
                        cJSON_Delete(wsMessage);
                        curl_easy_cleanup(curl);
                        return;
                    }
                    curl_easy_cleanup(curl);
                }
                else
                {
                    NIER_LOGE("libCURL", "Failed to initialize easy curl");
                    char result[] = "{\"error\":\"internal server error\"}";
                    mg_ws_send(c, result, strlen(result), WEBSOCKET_OP_TEXT);
                    cJSON_Delete(wsMessage);
                    return;
                }
            }
            else if (strncmp(cameraCall, "moveStop", 8) == 0)
            {
                char curlUrl[512];
                snprintf(curlUrl, 511, "%s?cmd=ptzStopRun&usr=%s&pwd=%s", cameraControlUrl, cameraControlUsername, cameraControlPassword);

                CURL *curl = curl_easy_init();
                if (curl)
                {
                    curl_easy_setopt(curl, CURLOPT_URL, curlUrl);
                    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, nullWriteCallback);
                    if (curl_easy_perform(curl) != CURLE_OK)
                    {
                        NIER_LOGE("libCURL", "Failed to execute curl");
                        char result[] = "{\"error\":\"internal server error\"}";
                        mg_ws_send(c, result, strlen(result), WEBSOCKET_OP_TEXT);
                        cJSON_Delete(wsMessage);
                        curl_easy_cleanup(curl);
                        return;
                    }
                    curl_easy_cleanup(curl);
                }
                else
                {
                    NIER_LOGE("libCURL", "Failed to initialize easy curl");
                    char result[] = "{\"error\":\"internal server error\"}";
                    mg_ws_send(c, result, strlen(result), WEBSOCKET_OP_TEXT);
                    cJSON_Delete(wsMessage);
                    return;
                }
            }
            else if (strncmp(cameraCall, "moveHome", 8) == 0)
            {
                char curlUrl[512];
                snprintf(curlUrl, 511, "%s?cmd=ptzReset&usr=%s&pwd=%s", cameraControlUrl, cameraControlUsername, cameraControlPassword);

                CURL *curl = curl_easy_init();
                if (curl)
                {
                    curl_easy_setopt(curl, CURLOPT_URL, curlUrl);
                    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, nullWriteCallback);
                    if (curl_easy_perform(curl) != CURLE_OK)
                    {
                        NIER_LOGE("libCURL", "Failed to execute curl");
                        char result[] = "{\"error\":\"internal server error\"}";
                        mg_ws_send(c, result, strlen(result), WEBSOCKET_OP_TEXT);
                        cJSON_Delete(wsMessage);
                        curl_easy_cleanup(curl);
                        return;
                    }
                    curl_easy_cleanup(curl);
                }
                else
                {
                    NIER_LOGE("libCURL", "Failed to initialize easy curl");
                    char result[] = "{\"error\":\"internal server error\"}";
                    mg_ws_send(c, result, strlen(result), WEBSOCKET_OP_TEXT);
                    cJSON_Delete(wsMessage);
                    return;
                }
            }
            else if (strncmp(cameraCall, "toggleIR", 8) == 0)
            {
                char curlUrl[512];
                snprintf(curlUrl, 511, "%s?cmd=getDevState&usr=%s&pwd=%s", cameraControlUrl, cameraControlUsername, cameraControlPassword);
                char curlResponse[2056] = {0};
                
                CURL *curl = curl_easy_init();
                if (curl)
                {
                    curl_easy_setopt(curl, CURLOPT_URL, curlUrl);
                    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCallback);
                    curl_easy_setopt(curl, CURLOPT_WRITEDATA, curlResponse);
                    if (curl_easy_perform(curl) != CURLE_OK)
                    {
                        NIER_LOGE("libCURL", "Failed to execute curl");
                        char result[] = "{\"error\":\"internal server error\"}";
                        mg_ws_send(c, result, strlen(result), WEBSOCKET_OP_TEXT);
                        cJSON_Delete(wsMessage);
                        curl_easy_cleanup(curl);
                        return;
                    }
                    curl_easy_cleanup(curl);
                }
                else
                {
                    NIER_LOGE("libCURL", "Failed to initialize easy curl");
                    char result[] = "{\"error\":\"internal server error\"}";
                    mg_ws_send(c, result, strlen(result), WEBSOCKET_OP_TEXT);
                    cJSON_Delete(wsMessage);
                    return;
                }
                char *curlResponseCursor = strstr(curlResponse, "<infraLedState>");
                if (curlResponseCursor) 
                {
                    curlResponseCursor += strlen("<infraLedState>");
                    char IRStateString[3] = {0};
                    snprintf(IRStateString, 2, "%s", curlResponseCursor);
                    int IRState = atoi(IRStateString);
                    char curlUrl[512];
                    if (IRState == 1) snprintf(curlUrl, 511, "%s?cmd=closeInfraLed&usr=%s&pwd=%s", cameraControlUrl, cameraControlUsername, cameraControlPassword);
                    else snprintf(curlUrl, 511, "%s?cmd=openInfraLed&usr=%s&pwd=%s", cameraControlUrl, cameraControlUsername, cameraControlPassword);
                
                    CURL *curl = curl_easy_init();
                    if (curl)
                    {
                        curl_easy_setopt(curl, CURLOPT_URL, curlUrl);
                        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, nullWriteCallback);
                        if (curl_easy_perform(curl) != CURLE_OK)
                        {
                            NIER_LOGE("libCURL", "Failed to execute curl");
                            char result[] = "{\"error\":\"internal server error\"}";
                            mg_ws_send(c, result, strlen(result), WEBSOCKET_OP_TEXT);
                            cJSON_Delete(wsMessage);
                            curl_easy_cleanup(curl);
                            return;
                        }
                        curl_easy_cleanup(curl);
                    }
                    else
                    {
                        NIER_LOGE("libCURL", "Failed to initialize easy curl");
                        char result[] = "{\"error\":\"internal server error\"}";
                        mg_ws_send(c, result, strlen(result), WEBSOCKET_OP_TEXT);
                        cJSON_Delete(wsMessage);
                        return;
                    }
                }
            }
        }
        else if (strncmp(call, "relayMessage", 12) == 0)
        {
            cJSON *deviceIDJSON = cJSON_GetObjectItem(wsMessage, "deviceID");
            if (deviceIDJSON == NULL)
            {
                char result[] = "{\"error\":\"invalid deviceID\"}";
                mg_ws_send(c, result, strlen(result), WEBSOCKET_OP_TEXT);
                cJSON_Delete(wsMessage);
                return;
            }
            char *deviceID = cJSON_GetStringValue(deviceIDJSON);
            if (deviceID == NULL || strlen(deviceID) > 1011)
            {
                char result[] = "{\"error\":\"invalid or too long deviceID\"}";
                mg_ws_send(c, result, strlen(result), WEBSOCKET_OP_TEXT);
                cJSON_Delete(wsMessage);
                return;
            }

            cJSON *payloadJSON = cJSON_GetObjectItem(wsMessage, "message");
            if (payloadJSON == NULL)
            {
                char result[] = "{\"error\":\"invalid message\"}";
                mg_ws_send(c, result, strlen(result), WEBSOCKET_OP_TEXT);
                cJSON_Delete(wsMessage);
                return;
            }

            char *payload = cJSON_PrintUnformatted(payloadJSON);
            if (payload == NULL)
            {
                char result[] = "{\"error\":\"could not process message\"}";
                mg_ws_send(c, result, strlen(result), WEBSOCKET_OP_TEXT);
                cJSON_Delete(wsMessage);
                return;
            }

            char topic[1024] = {0};
            snprintf(topic, 1023, "devices/%s/calls", deviceID);

            if (mosquittoThing == NULL)
            {
                char result[] = "{\"error\":\"MQTT client not initialized\"}";
                mg_ws_send(c, result, strlen(result), WEBSOCKET_OP_TEXT);
                free(payload);
                cJSON_Delete(wsMessage);
                return;
            }

            if (mosquitto_publish(mosquittoThing, NULL, topic, strlen(payload), payload, MQTT_QOS, 0) != MOSQ_ERR_SUCCESS)
            {
                char result[] = "{\"error\":\"failure publishing\"}";
                mg_ws_send(c, result, strlen(result), WEBSOCKET_OP_TEXT);
                free(payload);
                cJSON_Delete(wsMessage);
                return;
            }
        }

        else
        {
            char result[] = "{\"error\":\"unknown call\"}";
            mg_ws_send(c, result, strlen(result), WEBSOCKET_OP_TEXT);
        }
        cJSON_Delete(wsMessage);
    }
    else if (ev == MG_EV_WS_OPEN)
    {
        addWSConnection(c);
    }
    else if (ev == MG_EV_CLOSE)
    {
        if (c->is_websocket)
            removeWSConnection(c);
    }
}

int main(int argc, char **argv)
{
    if (pthread_mutex_init(&TOTPAttemptsLock, NULL) != 0)
    {
        NIER_LOGE("NIER", "Failed to initialize TOTP Attempts pthread mutex lock");
        return -1;
    }
    if (pthread_mutex_init(&WSConnectionsLock, NULL) != 0)
    {
        NIER_LOGE("NIER", "Failed to initialize WS connections pthread mutex lock");
        return -1;
    }

    if (argc > 1)
    {
        for (int i = 1; i < argc; i++)
        {
            if (strncmp(argv[i], "-d", 2) == 0)
                debugFlag = 1;
            else if (strncmp(argv[i], "--Disable-MQTT", 13) == 0)
                disableMQTT = 1;
            else
            {
                printf("-d Debug mode\n");
                printf("-Disable-MQTT Disable all MQTT related functionality\n");
                NIER_LOGE("NIER", "Invalid argument");
            }
        }
    }
    printf("\033[31m"
           "    _   __ ____ ______ ____ \n"
           "   / | / //  _// ____// __ \\\n"
           "  /  |/ / / / / __/  / /_/ /\n"
           " / /|  /_/ / / /___ / _, _/ \n"
           "/_/ |_//___//_____//_/ |_|  \n"
           "\033[0m\n");

    pthread_t udpBeaconTaskId;
    if (pthread_create(&udpBeaconTaskId, NULL, udpBeaconTask, NULL) != 0)
    {
        NIER_LOGE("NIER", "Failed to create thread for udp beacon: %s", strerror(errno));
    }

    if (setupMosqBroker() != 0)
    {
        NIER_LOGE("NIER", "Failed to start mosquitto broker");
        return -1;
    }
    else
    {
        NIER_LOGI("NIER", "Started MQTT broker");
        sleep(1);
    }

    if (debugFlag == 1)
    {
        NIER_LOGD("NIER", "Debug mode activated");
    }
    if (sqlite3_threadsafe() == 0)
    {
        NIER_LOGE("SQLite", "SQLite is not compiled with thread safety!");
        return -1;
    }
    if (sqlite3_open("database.sqlite3", &database))
    {
        NIER_LOGE("SQLite", "Couldn't open database: %s", sqlite3_errmsg(database));
        return -1;
    }
    else
    {
        NIER_LOGI("SQLite", "Database opened successfully");
    }
    sqlite3_busy_timeout(database, 5000);

    sqlite3_stmt *usersCheckStmt = NULL;
    if (sqlite3_prepare_v2(database, checkUsersTable, -1, &usersCheckStmt, 0) != SQLITE_OK)
    {
        NIER_LOGE("SQLite", "Failed to prepare statement: %s", sqlite3_errmsg(database));
    }
    if (usersCheckStmt && sqlite3_step(usersCheckStmt) != SQLITE_ROW)
    {
        NIER_LOGW("SQLite", "No USERS table found, creating table for users");
        char *errorMessage = NULL;
        if (sqlite3_exec(database, createUsersTable, NULL, NULL, &errorMessage) != SQLITE_OK)
        {
            NIER_LOGE("SQLite", "Failed to create table: %s", errorMessage);
        }
        NIER_LOGI("NIER", "Please create a user using: createUser <user1> <user2> ...");
    }
    if (usersCheckStmt)
    {
        sqlite3_finalize(usersCheckStmt);
    }

    sqlite3_stmt *devicesListStmt = NULL;
    if (sqlite3_prepare_v2(database, checkDevicesTable, -1, &devicesListStmt, 0) != SQLITE_OK)
    {
        NIER_LOGE("SQLite", "Failed to prepare statement: %s", sqlite3_errmsg(database));
    }
    if (devicesListStmt && sqlite3_step(devicesListStmt) != SQLITE_ROW)
    {
        NIER_LOGW("SQLite", "No DEVICES table found, creating table for devices");
        char *errorMessage = NULL;
        if (sqlite3_exec(database, createDevicesTable, NULL, NULL, &errorMessage) != SQLITE_OK)
        {
            NIER_LOGE("SQLite", "Failed to create table: %s", errorMessage);
        }
    }
    if (devicesListStmt)
    {
        sqlite3_finalize(devicesListStmt);
    }

    sqlite3_stmt *cameraListStmt = NULL;
    if (sqlite3_prepare_v2(database, checkCamerasTable, -1, &cameraListStmt, 0) != SQLITE_OK)
    {
        NIER_LOGE("SQLite", "Failed to prepare statement: %s", sqlite3_errmsg(database));
    }
    if (cameraListStmt && sqlite3_step(cameraListStmt) != SQLITE_ROW)
    {
        NIER_LOGW("SQLite", "No CAMERAS table found, creating table for cameras");
        char *errorMessage = NULL;
        if (sqlite3_exec(database, createCamerasTable, NULL, NULL, &errorMessage) != SQLITE_OK)
        {
            NIER_LOGE("SQLite", "Failed to create table: %s", errorMessage);
        }
    }
    if (cameraListStmt)
    {
        sqlite3_finalize(cameraListStmt);
    }

    NIER_LOGI("NIER", "Starting camera streams");
    startCameraStreams();

    sqlite3_stmt *sessionsCheckStmt = NULL;
    if (sqlite3_prepare_v2(database, checkSessionsTable, -1, &sessionsCheckStmt, 0) != SQLITE_OK)
    {
        NIER_LOGE("SQLite", "Failed to prepare sessions statement: %s", sqlite3_errmsg(database));
    }
    if (sessionsCheckStmt && sqlite3_step(sessionsCheckStmt) != SQLITE_ROW)
    {
        NIER_LOGW("SQLite", "No SESSIONS table found, creating table for sessions");
        char *errorMessage2 = NULL;
        if (sqlite3_exec(database, createSessionsTable, NULL, NULL, &errorMessage2) != SQLITE_OK)
        {
            NIER_LOGE("SQLite", "Failed to create sessions table: %s", errorMessage2);
        }
    }
    if (sessionsCheckStmt)
    {
        sqlite3_finalize(sessionsCheckStmt);
    }

    if (disableMQTT == 0)
    {
        mosquitto_lib_init();
        if (!(mosquittoThing = mosquitto_new(NULL, true, NULL)))
            NIER_LOGE("Mosquitto", "Failed to create a mosquitto instance");
        mosquitto_connect_callback_set(mosquittoThing, mosqetOnConnect);
        mosquitto_message_callback_set(mosquittoThing, mosqetOnMessage);
        mosquitto_disconnect_callback_set(mosquittoThing, mosqetOnDisconnect);
        mosquitto_log_callback_set(mosquittoThing, mosqetLog);
        if ((mosquitto_tls_psk_set(mosquittoThing, MQTT_PSK_KEY, MQTT_PSK_IDENTITY, NULL)) != MOSQ_ERR_SUCCESS)
            NIER_LOGE("Mosquitto", "Failed to set up TLS-PSK");
        if ((mosquitto_connect(mosquittoThing, MQTT_BROKER_URI, MQTT_BROKER_PORT, 10)) != MOSQ_ERR_SUCCESS)
            NIER_LOGE("Mosquitto", "Failed to connect to broker");
        if ((mosquitto_loop_start(mosquittoThing)) != MOSQ_ERR_SUCCESS)
            NIER_LOGE("Mosquitto", "Failed to start event loop");
    }

    struct mg_mgr mgr;
    mg_mgr_init(&mgr);
    TOTPAttempts = calloc(10, sizeof(struct TOTPAttempt));
    if (TOTPAttempts == NULL)
        NIER_LOGE("NIER", "Failed to allocate memory for TOTP Attempt tracking");
    TOTPAttemptsSize = 10;
    pthread_mutex_unlock(&TOTPAttemptsLock);

    mg_http_listen(&mgr, LISTEN_URI, httpHandler, NULL);
    NIER_LOGI("Mongoose", "Listening on %s", LISTEN_URI);

    pthread_t mongoosePollThreadId;
    if (pthread_create(&mongoosePollThreadId, NULL, mongoosePollThread, &mgr) != 0)
    {
        NIER_LOGE("NIER", "Failed to create thread for mongoose polling: %s", strerror(errno));
    }

    char userInput[512];
    memset(userInput, 0, sizeof(userInput));
    for (;;)
    {
        if (fgets(userInput, sizeof(userInput), stdin) != NULL)
        {
            if (strncmp(userInput, "createUser", 10) == 0)
            {
                char *userInputPointer = userInput + 10;
                char *token = NULL;
                if ((token = strtok(userInputPointer, " \n")) != NULL)
                {
                    do
                    {
                        if (strlen(token) > 255)
                        {
                            NIER_LOGW("NIER", "User name too long!");
                            break;
                        }
                        char username[256] = {0};
                        strncpy(username, token, 255);
                        if ((token = strtok(NULL, " \n")) == NULL)
                        {
                            NIER_LOGW("NIER", "No password provided!");
                        }
                        if (strlen(token) > 255)
                        {
                            NIER_LOGW("NIER", "Password too long!");
                            break;
                        }
                        unsigned char randomBytes[32];
                        char sharedSecret[33];
                        memset(sharedSecret, 0, sizeof(sharedSecret));
                        if (RAND_bytes(randomBytes, 32) != 1)
                        {
                            NIER_LOGE("OpenSSL", "Error generating random bytes");
                        }
                        for (size_t i = 0; i < 32; i++)
                        {
                            sharedSecret[i] = base32Chars[randomBytes[i] % 32];
                        }
                        sqlite3_stmt *insertStatement = NULL;
                        if (sqlite3_prepare_v2(database, insertUserStatement, -1, &insertStatement, 0) != SQLITE_OK)
                        {
                            NIER_LOGE("SQLite", "Failed to prepare statement: %s", sqlite3_errmsg(database));
                        }
                        else
                        {
                            sqlite3_bind_text(insertStatement, 1, username, -1, SQLITE_STATIC);
                            sqlite3_bind_text(insertStatement, 2, token, -1, SQLITE_STATIC);
                            sqlite3_bind_text(insertStatement, 3, sharedSecret, -1, SQLITE_STATIC);
                            if (sqlite3_step(insertStatement) != SQLITE_DONE)
                            {
                                NIER_LOGE("SQLite", "Failed to insert user: %s", sqlite3_errmsg(database));
                            }
                        }
                        if (insertStatement && (sqlite3_finalize(insertStatement) != SQLITE_OK))
                        {
                            NIER_LOGE("SQLite", "Failed to finalize statement: %s", sqlite3_errmsg(database));
                        }
                        NIER_LOGI("NIER", "TOTP setup key for user %s - %s", username, sharedSecret);
                    } while ((token = strtok(NULL, " \n")) != NULL);
                }
            }
            else if (strncmp(userInput, "deleteUser", 10) == 0)
            {
                sqlite3_stmt *delStmt = NULL;
                char *userInputPointer = userInput + 10;
                char *token = NULL;
                if ((token = strtok(userInputPointer, " \n")) != NULL)
                {
                    do
                    {
                        if (sqlite3_prepare_v2(database, deleteUserStatement, -1, &delStmt, 0) == SQLITE_OK)
                        {
                            sqlite3_bind_text(delStmt, 1, token, -1, SQLITE_STATIC);
                            if (sqlite3_step(delStmt) != SQLITE_DONE)
                            {
                                NIER_LOGE("SQLite", "Failed to delete user: %s", sqlite3_errmsg(database));
                            }
                            if (sqlite3_finalize(delStmt) != SQLITE_OK)
                            {
                                NIER_LOGE("SQLite", "Failed to finalize statement: %s", sqlite3_errmsg(database));
                            }
                            NIER_LOGI("SQLite", "Deleted user %s", token);
                        }
                        else
                        {
                            NIER_LOGE("SQLite", "Failed to prepare statement: %s", sqlite3_errmsg(database));
                        }
                    } while ((token = strtok(NULL, " \n")) != NULL);
                }
            }
            else if (strncmp(userInput, "listUsers", 9) == 0)
            {
                sqlite3_stmt *stmt = NULL;
                if (sqlite3_prepare_v2(database, listUsersQuery, -1, &stmt, NULL) == SQLITE_OK)
                {
                    while (sqlite3_step(stmt) == SQLITE_ROW)
                    {
                        const unsigned char *name = sqlite3_column_text(stmt, 0);
                        const unsigned char *password = sqlite3_column_text(stmt, 1);
                        const unsigned char *totpCode = sqlite3_column_text(stmt, 2);
                        if (name && totpCode && password)
                        {
                            NIER_LOGI("NIER", "User: %s, Password: %s, TOTP Key: %s", name, password, totpCode);
                        }
                    }
                    sqlite3_finalize(stmt);
                }
                else
                {
                    NIER_LOGE("SQLite", "Failed to prepare statement: %s", sqlite3_errmsg(database));
                }
            }
            else if (strncmp(userInput, "addCamera", 9) == 0)
            {
                char *userInputPointer = userInput + 10;
                char *token = NULL;
                if ((token = strtok(userInputPointer, " \n")) != NULL)
                {
                    do
                    {
                        char cameraName[256] = {0};
                        char cameraRSTPUrl[256] = {0};
                        char cameraControlUrl[256] = {0};
                        char cameraControlUsername[256] = {0};
                        char cameraControlPassword[256] = {0};
                        strncpy(cameraName, token, 255);
                        if ((token = strtok(NULL, " \n")) != NULL)
                        {
                            strncpy(cameraRSTPUrl, token, 255);
                        }
                        else
                        {
                            NIER_LOGW("NIER", "No camera RSTP URL provided");
                        }
                        if ((token = strtok(NULL, " \n")) != NULL)
                        {
                            strncpy(cameraControlUrl, token, 255);
                        }
                        else
                        {
                            NIER_LOGW("NIER", "No camera Control URL provided");
                        }
                        if ((token = strtok(NULL, " \n")) != NULL)
                        {
                            strncpy(cameraControlUsername, token, 255);
                        }
                        else
                        {
                            NIER_LOGW("NIER", "No camera Control username provided");
                        }
                        if ((token = strtok(NULL, " \n")) != NULL)
                        {
                            strncpy(cameraControlPassword, token, 255);
                        }
                        else
                        {
                            NIER_LOGW("NIER", "No camera Control password provided");
                        }

                        sqlite3_stmt *cameraInsertStmt;
                        if (sqlite3_prepare_v2(database, insertCamera, -1, &cameraInsertStmt, NULL) == SQLITE_OK)
                        {
                            sqlite3_bind_text(cameraInsertStmt, 1, cameraName, -1, SQLITE_STATIC);
                            sqlite3_bind_text(cameraInsertStmt, 2, cameraRSTPUrl, -1, SQLITE_STATIC);
                            sqlite3_bind_text(cameraInsertStmt, 3, cameraControlUrl, -1, SQLITE_STATIC);
                            sqlite3_bind_text(cameraInsertStmt, 4, cameraControlUsername, -1, SQLITE_STATIC);
                            sqlite3_bind_text(cameraInsertStmt, 5, cameraControlPassword, -1, SQLITE_STATIC);
                            if (sqlite3_step(cameraInsertStmt) != SQLITE_DONE)
                            {
                                NIER_LOGE("NIER", "Failed to insert camera: %s", sqlite3_errmsg(database));
                            }
                            if (sqlite3_finalize(cameraInsertStmt) != SQLITE_OK)
                            {
                                NIER_LOGE("NIER", "Failed to finalize camera insert statement: %s", sqlite3_errmsg(database));
                            }
                            NIER_LOGI("NIER", "Inserted camera: %s, RSTP URL: %s, Control URL: %s", cameraName, cameraRSTPUrl, cameraControlUrl);
                        }
                        else
                        {
                            NIER_LOGE("SQLite", "Failed to prepare statement: %s", sqlite3_errmsg(database));
                        }
                    } while ((token = strtok(NULL, " \n")) != NULL);
                }
            }
            else if (strncmp(userInput, "deleteCamera", 12) == 0)
            {
                char *userInputPointer = userInput + 13;
                char *token = NULL;
                if ((token = strtok(userInputPointer, " \n")) != NULL)
                {
                    do
                    {
                        sqlite3_stmt *cameraRemoveStmt;
                        if (sqlite3_prepare_v2(database, removeCamera, -1, &cameraRemoveStmt, NULL) == SQLITE_OK)
                        {
                            sqlite3_bind_text(cameraRemoveStmt, 1, token, -1, SQLITE_STATIC);
                            if (sqlite3_step(cameraRemoveStmt) != SQLITE_DONE)
                            {
                                NIER_LOGE("NIER", "Failed to delete camera: %s", sqlite3_errmsg(database));
                            }
                            if (sqlite3_finalize(cameraRemoveStmt) != SQLITE_OK)
                            {
                                NIER_LOGE("NIER", "Failed to finalize statement: %s", sqlite3_errmsg(database));
                            }
                            NIER_LOGI("NIER", "Deleted camera: %s", token);
                        }
                        else
                        {
                            NIER_LOGE("SQLite", "Failed to prepare statement: %s", sqlite3_errmsg(database));
                        }
                    } while ((token = strtok(NULL, " \n")) != NULL);
                }
            }
            else if (strncmp(userInput, "listCameras", 11) == 0)
            {
                sqlite3_stmt *listCamerasStmt;
                if (sqlite3_prepare_v2(database, listCameras, -1, &listCamerasStmt, NULL) == SQLITE_OK)
                {
                    while (sqlite3_step(listCamerasStmt) == SQLITE_ROW)
                    {
                        const char *cameraName = (const char *)sqlite3_column_text(listCamerasStmt, 0);
                        const char *cameraRSTPUrl = (const char *)sqlite3_column_text(listCamerasStmt, 1);
                        const char *cameraControlUrl = (const char *)sqlite3_column_text(listCamerasStmt, 2);
                        const char *cameraControlUsername = (const char *)sqlite3_column_text(listCamerasStmt, 3);
                        const char *cameraControlPassword = (const char *)sqlite3_column_text(listCamerasStmt, 4);
                        NIER_LOGI("NIER", "Camera: %s, RSTP URL: %s, Control URL: %s, Control username: %s, Control password: %s", cameraName, cameraRSTPUrl, cameraControlUrl, cameraControlUsername, cameraControlPassword);
                    }
                    if (sqlite3_finalize(listCamerasStmt) != SQLITE_OK)
                    {
                        NIER_LOGE("NIER", "Failed to finalize statement: %s", sqlite3_errmsg(database));
                    }
                }
                else
                {
                    NIER_LOGE("SQLite", "Failed to prepare statement: %s", sqlite3_errmsg(database));
                }
            }
            else if (strncmp(userInput, "help", 4) == 0)
            {
                printf("Commands:\n");
                printf("  createUser <user1> <pass> ...                                        Create one or more users\n");
                printf("  deleteUser <user1> ...                                               Delete one or more users\n");
                printf("  listUsers                                                            List all users, passwords and their TOTP keys\n");
                printf("  addCamera  <name> <rstp url> <ctrl url> <ctrl user> <ctrl pass> ...  Add one or more cameras, restart required for changes to take effect\n");
                printf("  deleteCamera <name> ...                                              Delete one or more cameras, restart required for changes to take effect\n");
                printf("  listCameras                                                          List all cameras, rstp urls and their control urls, control usernames, passwords\n");
                printf("  exit                                                                 Exit program\n");
                printf("  help                                                                 Show this help\n");
            }
            else if (strncmp(userInput, "exit", 4) == 0)
            {
                break;
            }
            else
            {
                printf("Unknown command\n");
                printf("Try 'help' for a list of commands\n");
            }
        }
    }
    if (disableMQTT == 0)
    {
        mosquitto_disconnect(mosquittoThing);
        mosquitto_destroy(mosquittoThing);
        mosquitto_lib_cleanup();
    }
    free(TOTPAttempts);
    sqlite3_close_v2(database);
    pthread_cancel(mongoosePollThreadId);
    pthread_join(mongoosePollThreadId, NULL);
    mg_mgr_free(&mgr);
    return 0;
}
