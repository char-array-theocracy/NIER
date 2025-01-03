#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <math.h>
#include <pthread.h>
#include <mosquitto.h>
#include <sqlite3.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include "mongoose.h"
#include "NIER.h"
#include <cjson/cJSON.h>

#define LISTEN_URI "ws://localhost:8000"
#define MQTT_BROKER_URI "192.168.1.113"
#define MQTT_BROKER_PORT 8883
#define MQTT_PSK_IDENTITY "test1"
#define MQTT_PSK_KEY "84fb1595364544af46ad955509b7a07c"
#define MQTT_QOS 2
#define MAX_WS_CONNECTIONS 50

struct TOTPAttempt{
    char ipHex[33];
    time_t attemptTime;
};
pthread_mutex_t TOTPAttemptsLock; 
struct TOTPAttempt *TOTPAttempts;
int TOTPAttemptsSize  = 0;
int TOTPAttemptsUsed  = 0;
struct mosquitto *mosquittoThing;
int disableMQTT = 0;
int debugFlag = 0;
sqlite3 *database = NULL;
struct mg_http_serve_opts serveOptions = { .root_dir = "./assets/" };
struct mg_connection *WSConnections[MAX_WS_CONNECTIONS];
int activeWSConnections;
pthread_mutex_t WSConnectionsLock;

const char *base32Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const char *totpQuery = "SELECT TOTP_CODE FROM USERS WHERE NAME = ?";
const char *checkUsersTable = "SELECT name FROM sqlite_master WHERE type='table' AND name='USERS';";
const char *createUsersTable =
  "CREATE TABLE IF NOT EXISTS USERS("
  "NAME TEXT UNIQUE PRIMARY KEY,"
  "TOTP_CODE TEXT NOT NULL"
  ") WITHOUT ROWID;";
const char *insertUserStatement = "INSERT INTO USERS (NAME, TOTP_CODE) VALUES (?, ?);";
const char *deleteUserStatement = "DELETE FROM USERS WHERE NAME = ?";
const char *listUsersQuery = "SELECT NAME, TOTP_CODE FROM USERS";

const char *checkSessionsTable = "SELECT name FROM sqlite_master WHERE type='table' AND name='SESSIONS';";
const char *createSessionsTable =
  "CREATE TABLE IF NOT EXISTS SESSIONS("
  "ID TEXT PRIMARY KEY,"
  "USERNAME TEXT NOT NULL,"
  "EXPIRATION INTEGER,"
  "IP TEXT"
  ") WITHOUT ROWID;";
const char *insertSessionStatement = "INSERT INTO SESSIONS (ID, USERNAME, EXPIRATION, IP) VALUES (?, ?, ?, ?);";
const char *checkSessionValidity = "SELECT USERNAME, EXPIRATION, IP FROM SESSIONS WHERE ID = ?";
const char *deleteExpiredSession = "DELETE FROM SESSIONS WHERE ID = ?";

const char *createDevicesTable =
  "CREATE TABLE IF NOT EXISTS DEVICES("
  "ID TEXT UNIQUE PRIMARY KEY,"
  "ONLINE BOOLEAN NOT NULL,"
  "USED BOOLEAN NOT NULL,"
  "DEVICE_TYPE TEXT NOT NULL"
  ") WITHOUT ROWID;";
const char *listDevices =
  "SELECT ID, "
  "CASE WHEN ONLINE THEN '1' ELSE '0' END AS STATE, "
  "CASE WHEN USED THEN '1' ELSE '0' END AS STATE, "
  "DEVICE_TYPE "
  "FROM DEVICES;";
const char *checkDeviceOnlineState = "SELECT ONLINE, DEVICE_TYPE FROM DEVICES WHERE ID = ?;";
const char *updateDevice = "UPDATE DEVICES SET ONLINE = ?, DEVICE_TYPE = ? WHERE ID = ?;";
const char *insertDevice = "INSERT INTO DEVICES (ID, ONLINE, USED, DEVICE_TYPE) VALUES (?, ?, 0, ?);";
const char *checkDevicesTable = "SELECT name FROM sqlite_master WHERE type='table' AND name='DEVICES';";

void mosqetLog(struct mosquitto *mosq, void *userdata, int level, const char *str) 
{
    NIER_LOGD("Mosquitto", "%s", str);
}

void mosqetOnConnect(struct mosquitto *mosq, void *obj, int rc) 
{
    if (rc == 0) {
        NIER_LOGI("Mosquitto", "Connected to MQTT broker");
        mosquitto_subscribe(mosq, NULL, "devices/presence", MQTT_QOS);
        mosquitto_subscribe(mosq, NULL, "devices/+/status", MQTT_QOS);
        mosquitto_subscribe(mosq, NULL, "devices/+/responses", MQTT_QOS);
        NIER_LOGI("Mosquitto", "Subscribed to devices presence topic");
    } else {
        NIER_LOGI("Mosquitto", "Failed to connect to broker, return code: %d", rc);
    }
}

void mosqetOnMessage(struct mosquitto *mosq, void *obj, const struct mosquitto_message *msg) 
{
    if (strncmp(msg->topic, "devices/presence", 16) == 0) 
    {
        cJSON *receivedPresence = cJSON_Parse((char *)msg->payload);
        if (receivedPresence == NULL) {
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
        if (rc == SQLITE_ROW) {
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
                NIER_LOGI("NIER","Inserted new device %s with ONLINE=%d, DEVICE_TYPE=%s.", deviceID, isOnline, deviceType);
            }
            sqlite3_finalize(stmt);
        } 
        else 
        {
            NIER_LOGE("SQLite", "Error checking device presence: %s", sqlite3_errmsg(database));
            sqlite3_finalize(stmt);
        }

        cJSON_Delete(receivedPresence);
        cJSON *deviceListJSON = cJSON_CreateObject();
        cJSON *deviceArrayJSON = cJSON_AddArrayToObject(deviceListJSON, "listDevices");
        
        if (deviceListJSON == NULL) NIER_LOGE("NIER", "Failed to create JSON object");
        sqlite3_stmt *deviceListStmt = NULL;
        if (sqlite3_prepare_v2(database, listDevices, -1, &deviceListStmt, NULL) != SQLITE_OK) {
            NIER_LOGE("SQLite", "Failed to prepare checkDeviceQuery: %s", sqlite3_errmsg(database));
        }
        while(sqlite3_step(deviceListStmt) == SQLITE_ROW) {
            cJSON *deviceIndice = cJSON_CreateObject();
            cJSON_AddStringToObject(deviceIndice, "deviceId", sqlite3_column_text(deviceListStmt,0));
            cJSON_AddNumberToObject(deviceIndice, "online", atoi(sqlite3_column_text(deviceListStmt,1)));
            cJSON_AddNumberToObject(deviceIndice, "used", atoi(sqlite3_column_text(deviceListStmt,2)));
            cJSON_AddStringToObject(deviceIndice, "deviceType", sqlite3_column_text(deviceListStmt,3));
            cJSON_AddItemToArray(deviceArrayJSON, deviceIndice);
        }
        if ((sqlite3_finalize(deviceListStmt)) != SQLITE_OK) NIER_LOGE("SQLite", "Failed to finalize statement");
        char *result = cJSON_PrintUnformatted(deviceListJSON);
        broadcastWSMessage(result);   
        cJSON_Delete(deviceListJSON);
    }
    else if (strstr(msg->topic, "status") != NULL) 
    {
        cJSON *deviceStatusJSON = cJSON_CreateObject();
        cJSON *deviceStatusItem = cJSON_Parse(msg->payload);
        char *deviceId = NULL;
        if ((deviceId = strtok(msg->topic, "/")) &&  deviceId != NULL) 
        {
             deviceId = strtok(NULL, "/");
        }
        if (deviceId) cJSON_AddStringToObject(deviceStatusItem, "deviceId", deviceId); 
        cJSON_AddItemToObject(deviceStatusJSON, "deviceStatus", deviceStatusItem);
        broadcastWSMessage(cJSON_PrintUnformatted(deviceStatusJSON));
        cJSON_Delete(deviceStatusJSON); 
    }    
    else if (strstr(msg->topic, "responses") != NULL) 
    {
        cJSON *deviceResponseJSON = cJSON_CreateObject();
        cJSON *deviceResponseItem = cJSON_Parse(msg->payload);
        char *deviceId = NULL;
        if ((deviceId = strtok(msg->topic, "/")) &&  deviceId != NULL) 
        {
             deviceId = strtok(NULL, "/");
        }
        if (deviceId) cJSON_AddStringToObject(deviceResponseItem, "deviceId", deviceId); 
        cJSON_AddItemToObject(deviceResponseJSON, "deviceResponse", deviceResponseItem);
        broadcastWSMessage(cJSON_PrintUnformatted(deviceResponseJSON));
        cJSON_Delete(deviceResponseJSON); 
    }
}


void mosqetOnDisconnect(struct mosquitto *mosq, void *obj, int rc) {
    NIER_LOGE("Mosquitto", "Disconnected from broker with return code: %d", rc);
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

        NIER_LOGI("NIER", "URI:%.*s", (int)hm->uri.len, hm->uri.buf);
        if (!mg_match(hm->uri, mg_str("/icons/*"), NULL)) 
        {
            if (!isAuthenticated) {
                if (!(mg_match(hm->uri, mg_str("/login"), NULL) || 
                    mg_match(hm->uri, mg_str("/api/login"), NULL))) {
                    mg_http_reply(c, 302, "Location: /login\r\n", "");
                    return;
                }
            } else {
                if (mg_match(hm->uri, mg_str("/login"), NULL) || 
                    mg_match(hm->uri, mg_str("/api/login"), NULL) || mg_match(hm->uri, mg_str("/"), NULL)) 
                {
                    mg_http_reply(c, 302, "Location: /dashboard\r\n", "");
                    return;
                }
            }
        } 

        if (isAuthenticated) NIER_LOGI("NIER", "Authenticated connection: user: %s, ip: %s", userName, mgHexToAddr(addressHex));

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
            NIER_LOGI("Mongoose", "Upgraded ip: %s to WebSocket", mgHexToAddr(addressHex));
            mg_ws_upgrade(c, hm, "Access-Control-Allow-Origin: *\r\n");
        }
        else if (mg_match(hm->uri, mg_str("/api/logout"), NULL) && isAuthenticated) {
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
            if (TOTPAttempts == NULL) NIER_LOGE("NIER", "Failed to clean TOTP Attempts");   
            for (int i = 0; i < TOTPAttemptsUsed; i++) {
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
                struct TOTPAttempt *temp = realloc(TOTPAttempts, TOTPAttemptsSize*sizeof(struct TOTPAttempt));
                if (temp == NULL) NIER_LOGE("NIER", "Failed to reallocate TOTP attempts array");
                TOTPAttempts = temp;
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
            cJSON *username = cJSON_GetObjectItem(loginInfo, "username");

            if (!username || !cJSON_IsString(username) || !password || !cJSON_IsString(password))
            {
                cJSON_Delete(loginInfo);
                mg_http_reply(c, 400, "", "Missing or invalid username/password\n");
                return;
            }
            sqlite3_stmt *totpQueryStatement = NULL;
            if (sqlite3_prepare_v2(database, totpQuery, -1, &totpQueryStatement, NULL) != SQLITE_OK)
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
                    const unsigned char *totpCode = sqlite3_column_text(totpQueryStatement, 0);
                    if (!totpCode)
                    {
                        mg_http_reply(c, 400, "", "Invalid password\n");
                        break;
                    }
                    char generated[7];
                    memset(generated, 0, sizeof(generated));
                    if (generateTOTP((const char *)totpCode, 30, 6, generated) != 0)
                    {
                        mg_http_reply(c, 500, "", "Internal Server Error\n");
                        break;
                    }
                    if (strncmp(generated, cJSON_GetStringValue(password), 6) == 0)
                    {
                        createSession(cJSON_GetStringValue(username), c);
                    }
                    else
                    {
                        mg_http_reply(c, 200, "", "Incorrect password\n");
                    }
                    break;
                }
                case SQLITE_DONE:
                    mg_http_reply(c, 400, "", "Unknown username\n");
                    break;
                default:
                    mg_http_reply(c, 500, "", "Internal Server Error\n");
                    break;
            }
            sqlite3_finalize(totpQueryStatement);
            cJSON_Delete(loginInfo);
            return;
        } else 
        {
            mg_http_serve_dir(c, hm, &serveOptions);
        }
    }
    else if (ev == MG_EV_WS_MSG) 
    {
        struct mg_ws_message *wm = (struct mg_ws_message *) ev_data;
        NIER_LOGI("Mongoose", "Recieved WS message: %s", wm->data.buf);
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

        if (strncmp(call, "listDevices", 11) == 0) {
            cJSON *deviceListJSON = cJSON_CreateObject();
            cJSON *deviceArrayJSON = cJSON_AddArrayToObject(deviceListJSON, "listDevices");
            
            if (deviceListJSON == NULL) NIER_LOGE("NIER", "Failed to create JSON object");
            sqlite3_stmt *deviceListStmt = NULL;
            if (sqlite3_prepare_v2(database, listDevices, -1, &deviceListStmt, NULL) != SQLITE_OK) {
                NIER_LOGE("SQLite", "Failed to prepare checkDeviceQuery: %s", sqlite3_errmsg(database));
            }
            while(sqlite3_step(deviceListStmt) == SQLITE_ROW) {
                cJSON *deviceIndice = cJSON_CreateObject();
                cJSON_AddStringToObject(deviceIndice, "deviceId", sqlite3_column_text(deviceListStmt,0));
                cJSON_AddNumberToObject(deviceIndice, "online", atoi(sqlite3_column_text(deviceListStmt,1)));
                cJSON_AddNumberToObject(deviceIndice, "used", atoi(sqlite3_column_text(deviceListStmt,2)));
                cJSON_AddStringToObject(deviceIndice, "deviceType", sqlite3_column_text(deviceListStmt,3));
                cJSON_AddItemToArray(deviceArrayJSON, deviceIndice);
            }
            if ((sqlite3_finalize(deviceListStmt)) != SQLITE_OK) NIER_LOGE("SQLite", "Failed to finalize statement");
            char *result = cJSON_PrintUnformatted(deviceListJSON);   
            mg_ws_send(c, result, strlen(result), WEBSOCKET_OP_TEXT);
            cJSON_Delete(deviceListJSON);
        }
        else if (strncmp(call, "relayMessage", 12) == 0) 
        {
            cJSON *deviceIDJSON = cJSON_GetObjectItem(wsMessage, "deviceID");
            if (deviceIDJSON == NULL) {
                char result[] = "{\"error\":\"invalid deviceID\"}";
                mg_ws_send(c, result, strlen(result), WEBSOCKET_OP_TEXT);
                cJSON_Delete(wsMessage);
                return;
            }
            char *deviceID = cJSON_GetStringValue(deviceIDJSON);
            if (deviceID == NULL || strlen(deviceID) > 1011) { 
                char result[] = "{\"error\":\"invalid or too long deviceID\"}";
                mg_ws_send(c, result, strlen(result), WEBSOCKET_OP_TEXT);
                cJSON_Delete(wsMessage);
                return;
            }

            cJSON *payloadJSON = cJSON_GetObjectItem(wsMessage, "message");
            if (payloadJSON == NULL) {
                char result[] = "{\"error\":\"invalid message\"}";
                mg_ws_send(c, result, strlen(result), WEBSOCKET_OP_TEXT);
                cJSON_Delete(wsMessage);
                return;
            }

            char *payload = cJSON_PrintUnformatted(payloadJSON);
            if (payload == NULL) {
                char result[] = "{\"error\":\"could not process message\"}";
                mg_ws_send(c, result, strlen(result), WEBSOCKET_OP_TEXT);
                cJSON_Delete(wsMessage);
                return;
            }

            char topic[1024] = {0};
            snprintf(topic, 1023, "devices/%s/calls", deviceID);

            if (mosquittoThing == NULL) {
                char result[] = "{\"error\":\"MQTT client not initialized\"}";
                mg_ws_send(c, result, strlen(result), WEBSOCKET_OP_TEXT);
                free(payload); 
                cJSON_Delete(wsMessage);
                return;
            }

            if (mosquitto_publish(mosquittoThing, NULL, topic, strlen(payload), payload, MQTT_QOS, 0) != MOSQ_ERR_SUCCESS) {
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
        if (c->is_websocket) removeWSConnection(c);
    }
}

int main(int argc, char **argv)
{
    if (argc > 1)
    {
        for (int i = 1; i < argc; i++) 
        {
            if (strncmp(argv[i], "-d", 2) == 0) debugFlag = 1;
            else if (strncmp(argv[i], "--Disable-MQTT", 13) == 0) disableMQTT = 1;
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

    if (debugFlag == 1)
    {
        NIER_LOGD("NIER", "Debug mode activated");
    }
    if (sqlite3_threadsafe() == 0)
    {
        NIER_LOGE("SQLite", "SQLite is not compiled with thread safety!");
    }
    if (sqlite3_open("database.sqlite3", &database))
    {
        NIER_LOGE("SQLite", "Couldn't open database: %s", sqlite3_errmsg(database));
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
        if (!(mosquittoThing = mosquitto_new(NULL, true, NULL))) NIER_LOGE("Mosquitto", "Failed to create a mosquitto instance"); 
        mosquitto_connect_callback_set(mosquittoThing, mosqetOnConnect);
        mosquitto_message_callback_set(mosquittoThing, mosqetOnMessage);
        mosquitto_disconnect_callback_set(mosquittoThing, mosqetOnDisconnect);
        mosquitto_log_callback_set(mosquittoThing, mosqetLog);
        if ((mosquitto_tls_psk_set(mosquittoThing, MQTT_PSK_KEY, MQTT_PSK_IDENTITY, NULL)) != MOSQ_ERR_SUCCESS) NIER_LOGE("Mosquitto", "Failed to set up TLS-PSK");
        if ((mosquitto_connect(mosquittoThing, MQTT_BROKER_URI, MQTT_BROKER_PORT, 60)) != MOSQ_ERR_SUCCESS) NIER_LOGE("Mosquitto", "Failed to connect to broker");
        if ((mosquitto_loop_start(mosquittoThing)) != MOSQ_ERR_SUCCESS) NIER_LOGE("Mosquitto", "Failed to start event loop");
    }

    struct mg_mgr mgr;
    mg_mgr_init(&mgr);
    TOTPAttempts = calloc(10, sizeof(struct TOTPAttempt));
    if (TOTPAttempts = NULL) NIER_LOGE("NIER", "Failed to allocate memory for TOTP Attempt tracking");
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
                        if (strlen(token) > 255) {
                            NIER_LOGW("NIER", "User name too long!");
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
                            sqlite3_bind_text(insertStatement, 1, token, -1, SQLITE_STATIC);
                            sqlite3_bind_text(insertStatement, 2, sharedSecret, -1, SQLITE_STATIC);
                            if (sqlite3_step(insertStatement) != SQLITE_DONE)
                            {
                                NIER_LOGE("SQLite", "Failed to insert user: %s", sqlite3_errmsg(database));
                            }
                        }
                        if (insertStatement && (sqlite3_finalize(insertStatement) != SQLITE_OK))
                        {
                            NIER_LOGE("SQLite", "Failed to finalize statement: %s", sqlite3_errmsg(database));
                        }
                        NIER_LOGI("NIER", "TOTP setup key for user %s - %s", token, sharedSecret);
                    }
                    while ((token = strtok(NULL, " \n")) != NULL);
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
                    }
                    while ((token = strtok(NULL, " \n")) != NULL);
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
                        const unsigned char *totpCode = sqlite3_column_text(stmt, 1);
                        if (name && totpCode)
                        {
                            NIER_LOGI("NIER", "User: %s, TOTP Key: %s", name, totpCode);
                        }
                        else if (name)
                        {
                            NIER_LOGI("NIER", "User: %s, TOTP Key: (none)", name);
                        }
                    }
                    sqlite3_finalize(stmt);
                }
                else
                {
                    NIER_LOGE("SQLite", "Failed to prepare statement: %s", sqlite3_errmsg(database));
                }
            }
            else if (strncmp(userInput, "help", 4) == 0)
            {
                printf("Commands:\n");
                printf("  createUser <user1> ...    Create one or more users\n");
                printf("  deleteUser <user1> ...    Delete one or more users\n");
                printf("  listUsers                 List all users and their TOTP keys\n");
                printf("  exit                      Exit program\n");
                printf("  help                      Show this help\n");
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
