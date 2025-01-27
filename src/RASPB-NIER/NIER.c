#include "NIER.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <math.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <cjson/cJSON.h>
#include "statements.h"

#define MAX_WS_CONNECTIONS 50

extern int debugFlag;
extern struct mg_str loginApiUri;
extern sqlite3 *database;

extern const char *insertSessionStatement;
extern const char *checkSessionValidity;
extern const char *deleteExpiredSession;
extern const char *listDevices;

extern pthread_mutex_t WSConnectionsLock;
extern struct mg_connection *WSConnections[];
extern int activeWSConnections;

void NIER_LOGI(const char *tag, const char *format, ...)
{
    time_t now = time(NULL);
    char timeStr[20];
    strftime(timeStr, sizeof(timeStr), "%Y-%m-%d %H:%M:%S", localtime(&now));

    va_list args;
    va_start(args, format);
    printf("%s \033[32m[INFO] [%s] ", timeStr, tag);
    vprintf(format, args);
    printf("\033[0m\n");
    va_end(args);
}

void NIER_LOGW(const char *tag, const char *format, ...)
{
    time_t now = time(NULL);
    char timeStr[20];
    strftime(timeStr, sizeof(timeStr), "%Y-%m-%d %H:%M:%S", localtime(&now));

    va_list args;
    va_start(args, format);
    printf("%s \033[33m[WARN] [%s] ", timeStr, tag);
    vprintf(format, args);
    printf("\033[0m\n");
    va_end(args);
}

void NIER_LOGE(const char *tag, const char *format, ...)
{
    time_t now = time(NULL);
    char timeStr[20];
    strftime(timeStr, sizeof(timeStr), "%Y-%m-%d %H:%M:%S", localtime(&now));

    va_list args;
    va_start(args, format);
    printf("%s \033[31m[ERROR] [%s] ", timeStr, tag);
    vprintf(format, args);
    printf("\033[0m\n");
    va_end(args);
}

void NIER_LOGD(const char *tag, const char *format, ...)
{
    if (debugFlag == 1)
    {
        time_t now = time(NULL);
        char timeStr[20];
        strftime(timeStr, sizeof(timeStr), "%Y-%m-%d %H:%M:%S", localtime(&now));

        va_list args;
        va_start(args, format);
        printf("%s \033[34m[DEBUG] [%s] ", timeStr, tag);
        vprintf(format, args);
        printf("\033[0m\n");
        va_end(args);
    }
}

void intToBytes(uint64_t value, unsigned char *bytes)
{
    for (int i = 7; i >= 0; i--)
    {
        bytes[i] = (unsigned char)(value & 0xFF);
        value >>= 8;
    }
}

int generateTOTP(const char *base32Secret, int period, int digits, char *output)
{
    unsigned char decodedSecret[64];
    memset(decodedSecret, 0, sizeof(decodedSecret));
    size_t encodedLen = strlen(base32Secret);
    size_t bitsCollected = 0;
    uint32_t accumulator = 0;
    size_t decodedIdx = 0;

    for (size_t i = 0; i < encodedLen; i++)
    {
        char c = base32Secret[i];
        if (c == '=' || c == ' ' || c == '-')
            continue;
        const char *ptr = strchr(base32Chars, c);
        if (!ptr)
            return -1;
        int value = (int)(ptr - base32Chars);
        accumulator = (accumulator << 5) | (value & 0x1F);
        bitsCollected += 5;
        if (bitsCollected >= 8)
        {
            bitsCollected -= 8;
            if (decodedIdx >= sizeof(decodedSecret))
                return -1;
            decodedSecret[decodedIdx++] = (unsigned char)((accumulator >> bitsCollected) & 0xFF);
        }
    }
    int secretLen = (int)decodedIdx;
    if (secretLen <= 0)
        return -1;

    uint64_t currentTime = (uint64_t)time(NULL) / (uint64_t)period;
    unsigned char timeBytes[8];
    memset(timeBytes, 0, sizeof(timeBytes));
    for (int i = 7; i >= 0; i--)
    {
        timeBytes[i] = (unsigned char)(currentTime & 0xFF);
        currentTime >>= 8;
    }

    unsigned int hmacLen = 0;
    unsigned char *hmacResult = HMAC(EVP_sha1(), decodedSecret, secretLen, timeBytes, sizeof(timeBytes), NULL, &hmacLen);
    if (!hmacResult)
        return -1;

    int offset = hmacResult[hmacLen - 1] & 0x0F;
    uint32_t code = ((hmacResult[offset] & 0x7F) << 24) | ((hmacResult[offset + 1] & 0xFF) << 16) | ((hmacResult[offset + 2] & 0xFF) << 8) | (hmacResult[offset + 3] & 0xFF);

    uint32_t token = code % (uint32_t)pow(10, digits);
    snprintf(output, digits + 1, "%0*u", digits, token);
    return 0;
}

void mgAddrToHex(struct mg_addr *addr, char *dest, size_t destSize)
{
    if (!dest || destSize < 33)
        return;
    memset(dest, 0, destSize);
    for (int i = 0; i < (int)sizeof(addr->ip); i++)
    {
        sprintf(&dest[i * 2], "%02X", (unsigned char)addr->ip[i]);
    }
    dest[32] = 0;
}

char *mgHexToAddr(char *hexAddress)
{
    char truncatedHex[9] = {0};
    strncpy(truncatedHex, hexAddress, 8);
    truncatedHex[8] = '\0';
    uint32_t ipHex = strtoul(truncatedHex, NULL, 16);

    struct in_addr address;
    address.s_addr = htonl(ipHex);

    char *result = calloc(INET_ADDRSTRLEN, sizeof(char));
    inet_ntop(AF_INET, &address, result, INET_ADDRSTRLEN);
    return result;
}

int checkSession(struct mg_http_message *hm, struct mg_connection *c, char *userName)
{
    struct mg_str *cookieHeader = mg_http_get_header(hm, "Cookie");
    if (!cookieHeader)
        return 0;

    char cookieBuf[256] = {0};
    snprintf(cookieBuf, sizeof(cookieBuf), "%.*s", (int)cookieHeader->len, cookieHeader->buf);
    char *sessionPtr = strstr(cookieBuf, "session_id=");
    if (!sessionPtr)
        return 0;
    sessionPtr += strlen("session_id=");

    char sessionId[128];
    memset(sessionId, 0, sizeof(sessionId));
    int i = 0;
    while (*sessionPtr && *sessionPtr != ';' && i < 127)
    {
        sessionId[i++] = *sessionPtr++;
    }

    char ipHex[33];
    mgAddrToHex(&c->rem, ipHex, sizeof(ipHex));

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(database, checkSessionValidity, -1, &stmt, NULL) != SQLITE_OK)
        return 0;
    sqlite3_bind_text(stmt, 1, sessionId, -1, SQLITE_STATIC);

    int result = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW)
    {
        time_t exp = (time_t)sqlite3_column_int(stmt, 1);
        const unsigned char *dbip = sqlite3_column_text(stmt, 2);
        if (userName != NULL)
        {
            const char *userNamePointer = (const char *)sqlite3_column_text(stmt, 0);
            strncpy(userName, userNamePointer, 255);
        }

        if (dbip)
        {
            if (time(NULL) <= exp && strcmp(ipHex, (const char *)dbip) == 0)
            {
                result = 1;
            }
            else
            {
                sqlite3_finalize(stmt);
                if (sqlite3_prepare_v2(database, deleteExpiredSession, -1, &stmt, NULL) == SQLITE_OK)
                {
                    sqlite3_bind_text(stmt, 1, sessionId, -1, SQLITE_STATIC);
                    sqlite3_step(stmt);
                }
                sqlite3_finalize(stmt);
                return 0;
            }
        }
        else
        {
            sqlite3_finalize(stmt);
            if (sqlite3_prepare_v2(database, deleteExpiredSession, -1, &stmt, NULL) == SQLITE_OK)
            {
                sqlite3_bind_text(stmt, 1, sessionId, -1, SQLITE_STATIC);
                sqlite3_step(stmt);
            }
        }
    }
    sqlite3_finalize(stmt);
    return result;
}

void createSession(const char *user, struct mg_connection *c)
{
    char sessionId[65];
    memset(sessionId, 0, sizeof(sessionId));
    unsigned char rnd[32];
    RAND_bytes(rnd, 32);

    for (int i = 0; i < 32; i++)
    {
        sprintf(&sessionId[i * 2], "%02X", rnd[i]);
    }

    time_t expiration = time(NULL) + (5 * 3600);
    char ipHex[33];
    mgAddrToHex(&c->rem, ipHex, sizeof(ipHex));

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(database, insertSessionStatement, -1, &stmt, NULL) == SQLITE_OK)
    {
        sqlite3_bind_text(stmt, 1, sessionId, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, user, -1, SQLITE_STATIC);
        sqlite3_bind_int(stmt, 3, (int)expiration);
        sqlite3_bind_text(stmt, 4, ipHex, -1, SQLITE_STATIC);
        sqlite3_step(stmt);
    }
    sqlite3_finalize(stmt);

    mg_printf(c, "HTTP/1.1 200 OK\r\n"
                 "Set-Cookie: session_id=%s; HttpOnly; Secure; Path=/; Max-Age=%d\r\n"
                 "Content-Type: text/plain\r\n"
                 "Content-Length: 16\r\n\r\n"
                 "Login successful\n",
              sessionId, 5 * 3600);
}

struct TOTPAttempt *cleanTOTPAttempts(struct TOTPAttempt *TOTPAttempts, int *TOTPAttemptsUsed, int TOTPAttemptsSize)
{
    if (TOTPAttempts == NULL)
    {
        return calloc(TOTPAttemptsSize, sizeof(struct TOTPAttempt));
    }
    struct TOTPAttempt *TOTPAttemptsDuplicate = calloc(TOTPAttemptsSize, sizeof(struct TOTPAttempt));
    int validIndices = 0;
    for (int i = 0; i < *TOTPAttemptsUsed; i++)
    {
        if ((time(NULL) - TOTPAttempts[i].attemptTime) < 30)
        {
            TOTPAttemptsDuplicate[validIndices].attemptTime = TOTPAttempts[i].attemptTime;
            strncpy(TOTPAttemptsDuplicate[validIndices].ipHex, TOTPAttempts[i].ipHex, sizeof(TOTPAttemptsDuplicate[validIndices].ipHex) - 1);
            TOTPAttemptsDuplicate[validIndices].ipHex[sizeof(TOTPAttemptsDuplicate[validIndices].ipHex) - 1] = '\0';
            validIndices++;
        }
    }
    *TOTPAttemptsUsed = validIndices;
    free(TOTPAttempts);
    return TOTPAttemptsDuplicate;
}

void cleanExpiredSessions()
{
    time_t currentTime = time(NULL);
    sqlite3_stmt *stmt = NULL;
    const char *deleteExpiredStatement = "DELETE FROM sessions WHERE expiration <= ?";
    if (sqlite3_prepare_v2(database, deleteExpiredStatement, -1, &stmt, NULL) == SQLITE_OK)
    {
        sqlite3_bind_int(stmt, 1, (int)currentTime);
        sqlite3_step(stmt);
    }
    sqlite3_finalize(stmt);
}

void addWSConnection(struct mg_connection *c)
{
    pthread_mutex_lock(&WSConnectionsLock);
    if (activeWSConnections < MAX_WS_CONNECTIONS)
    {
        WSConnections[activeWSConnections++] = c;
    }
    else
    {
        NIER_LOGW("NIER", "Max WebSocket connections reached");
    }
    pthread_mutex_unlock(&WSConnectionsLock);
}

void removeWSConnection(struct mg_connection *c)
{
    struct mg_connection *WSConnectionsDuplicate[MAX_WS_CONNECTIONS];
    int newActiveWSConnections = 0;
    pthread_mutex_lock(&WSConnectionsLock);

    for (int i = 0; i < activeWSConnections; i++)
    {
        if (WSConnections[i] != c)
        {
            WSConnectionsDuplicate[newActiveWSConnections++] = WSConnections[i];
        }
    }

    for (int i = 0; i < MAX_WS_CONNECTIONS; i++)
    {
        if (i < newActiveWSConnections)
            WSConnections[i] = WSConnectionsDuplicate[i];
        else
            WSConnections[i] = NULL;
    }
    activeWSConnections = newActiveWSConnections;
    pthread_mutex_unlock(&WSConnectionsLock);
}

void broadcastWSMessage(const char *message)
{
    pthread_mutex_lock(&WSConnectionsLock);
    for (int i = 0; i < activeWSConnections; i++)
        mg_ws_send(WSConnections[i], message, strlen(message), WEBSOCKET_OP_TEXT);
    pthread_mutex_unlock(&WSConnectionsLock);
}

char *getDeviceList()
{
    cJSON *deviceListJSON = cJSON_CreateObject();
    cJSON *deviceArrayJSON = cJSON_AddArrayToObject(deviceListJSON, "listDevices");

    if (deviceListJSON == NULL)
        NIER_LOGE("NIER", "Failed to create JSON object");

    sqlite3_stmt *deviceListStmt = NULL;
    if (sqlite3_prepare_v2(database, listDevices, -1, &deviceListStmt, NULL) != SQLITE_OK)
    {
        NIER_LOGE("SQLite", "Failed to prepare checkDeviceQuery: %s", sqlite3_errmsg(database));
    }

    while (sqlite3_step(deviceListStmt) == SQLITE_ROW)
    {
        cJSON *deviceIndice = cJSON_CreateObject();
        cJSON_AddStringToObject(deviceIndice, "deviceId", (const char *)sqlite3_column_text(deviceListStmt, 0));
        cJSON_AddNumberToObject(deviceIndice, "online", atoi((const char *)sqlite3_column_text(deviceListStmt, 1)));
        cJSON_AddStringToObject(deviceIndice, "deviceType", (const char *)sqlite3_column_text(deviceListStmt, 2));

        const char *dataStr = (const char *)sqlite3_column_text(deviceListStmt, 3);
        if (dataStr && dataStr[0] == '[')
        {
            cJSON *dataJSON = cJSON_Parse(dataStr);
            if (dataJSON)
            {
                cJSON_AddItemToObject(deviceIndice, "data", dataJSON);
            }
        }
        else if (dataStr)
        {
            cJSON_AddNumberToObject(deviceIndice, "data", atoi(dataStr));
        }

        cJSON_AddItemToArray(deviceArrayJSON, deviceIndice);
    }

    if ((sqlite3_finalize(deviceListStmt)) != SQLITE_OK)
        NIER_LOGE("SQLite", "Failed to finalize statement");

    char *result = cJSON_PrintUnformatted(deviceListJSON);
    cJSON_Delete(deviceListJSON);
    return result;
}

int setupMosqBroker()
{
    mkdir("./logs", 0755);
    const char *homeDirectory = getenv("HOME");
    FILE *mosqBrokerConfDef = fopen("./config/mosquitto.conf.def", "r");
    if (mosqBrokerConfDef == NULL)
    {
        NIER_LOGE("NIER", "Failed to open mosquitto config template file");
        return -1;
    }
    char mosqBrokerConfDefText[4096] = {0};
    size_t mosqBrokerConfDefTextReadLength = fread(mosqBrokerConfDefText, 1, 4095, mosqBrokerConfDef);
    if (mosqBrokerConfDefTextReadLength < 50)
    {
        NIER_LOGE("NIER", "Failed to read mosquitto config template file");
        return -1;
    }
    remove("./config/mosquitto.conf");
    FILE *mosqBrokerConf = fopen("./config/mosquitto.conf", "w");
    if (mosqBrokerConf == NULL)
    {
        NIER_LOGE("NIER", "Failed to open mosquitto config file");
        return -1;
    }
    size_t dirPlaceholderLength = strlen("0___USER___0");
    int occuranceCount = 0;
    char *needleOccuranceCursor = mosqBrokerConfDefText;
    while ((needleOccuranceCursor = strstr(needleOccuranceCursor, "0___USER___0")) != NULL)
    {
        needleOccuranceCursor += dirPlaceholderLength;
        occuranceCount++;
    }
    int mosqBrokerConfLength = strlen(mosqBrokerConfDefText) + (strlen(homeDirectory) - dirPlaceholderLength) * occuranceCount + 1;
    char *mosqBrokerConfText = malloc(mosqBrokerConfLength);
    if (mosqBrokerConfText == NULL)
    {
        return -1;
    }
    char *needleCursor = mosqBrokerConfDefText;
    char *needleCursorPrevious = mosqBrokerConfDefText;
    char *mosqBrokerConfTextCursor = mosqBrokerConfText;
    for (int i = 0; i < occuranceCount; i++)
    {
        needleCursor = strstr(needleCursorPrevious, "0___USER___0");

        size_t prefixLen = needleCursor - needleCursorPrevious;
        memcpy(mosqBrokerConfTextCursor, needleCursorPrevious, prefixLen);
        mosqBrokerConfTextCursor += prefixLen;

        size_t homeLen = strlen(homeDirectory);
        memcpy(mosqBrokerConfTextCursor, homeDirectory, homeLen);
        mosqBrokerConfTextCursor += homeLen;

        needleCursor += dirPlaceholderLength;
        needleCursorPrevious = needleCursor;
    }
    size_t remainingLen = strlen(needleCursorPrevious);
    memcpy(mosqBrokerConfTextCursor, needleCursorPrevious, remainingLen);
    mosqBrokerConfTextCursor += remainingLen;

    fprintf(mosqBrokerConf, "%s", mosqBrokerConfText);
    free(mosqBrokerConfText);
    fclose(mosqBrokerConf);
    fclose(mosqBrokerConfDef);

    return system("mosquitto -c ./config/mosquitto.conf &");
}

void startCameraStreams()
{
    const char *homeDirectory = getenv("HOME");
    sqlite3_stmt *cameraListStmt;
    if (sqlite3_prepare_v2(database, listCameras, -1, &cameraListStmt, NULL) == SQLITE_OK)
    {
        while (sqlite3_step(cameraListStmt) == SQLITE_ROW)
        {
            char command[512] = {0};
            char outputPath[512] = {0};
            snprintf(outputPath, 511, "%s/NIER/assets/camera/%s", homeDirectory, sqlite3_column_text(cameraListStmt, 0));

            /*TODO: add relaunch logic*/
            snprintf(command, 511,
                     "mkdir -p %s && "
                     "ffmpeg -hide_banner -loglevel error -nostats -y "
                     "-i \"%s\" "
                     "-c copy -f hls "
                     "-hls_time 0.5 -hls_list_size 21600 "
                     "-hls_flags delete_segments+append_list "
                     "-hls_segment_filename \"%s/segment%%05d.ts\" "
                     "-hls_playlist_type event "
                     "\"%s/playlist.m3u8\"&",
                     outputPath, sqlite3_column_text(cameraListStmt, 1), outputPath, outputPath);

            if (system(command) != 0)
            {
                NIER_LOGE("FFmpeg", "Failed to invoke ffmpeg command");
            }
        }
        if (sqlite3_finalize(cameraListStmt) != SQLITE_OK)
        {
            NIER_LOGE("Failed to finalize statement: %s", sqlite3_errmsg(database));
        }
    }
    else
    {
        NIER_LOGE("Failed to prepare statement: %s", sqlite3_errmsg(database));
    }
}

size_t nullWriteCallback(UNUSED void *contents, size_t size, size_t nmemb, UNUSED void *userp)
{
    return size * nmemb;
}

size_t writeCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
    size_t totalSize = size * nmemb;
    strncat((char *)userp, (char *)contents, totalSize);
    return totalSize;
}
