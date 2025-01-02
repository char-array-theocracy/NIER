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

extern int debugFlag;
extern struct mg_str loginApiUri;
extern sqlite3 *database;

struct TOTPAttempt{
    char ipHex[33];
    time_t attemptTime;
};
extern const char *insertSessionStatement;
extern const char *checkSessionValidity;
extern const char *deleteExpiredSession;

static const char *base32Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

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
    exit(-1);
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
        if (c == '=' || c == ' ' || c == '-') continue;
        const char *ptr = strchr(base32Chars, c);
        if (!ptr) return -1;
        int value = (int)(ptr - base32Chars);
        accumulator = (accumulator << 5) | (value & 0x1F);
        bitsCollected += 5;
        if (bitsCollected >= 8)
        {
            bitsCollected -= 8;
            if (decodedIdx >= sizeof(decodedSecret)) return -1;
            decodedSecret[decodedIdx++] = (unsigned char)((accumulator >> bitsCollected) & 0xFF);
        }
    }
    int secretLen = (int)decodedIdx;
    if (secretLen <= 0) return -1;

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
    if (!hmacResult) return -1;

    int offset = hmacResult[hmacLen - 1] & 0x0F;
    uint32_t code = ((hmacResult[offset] & 0x7F) << 24)
                  | ((hmacResult[offset + 1] & 0xFF) << 16)
                  | ((hmacResult[offset + 2] & 0xFF) << 8)
                  |  (hmacResult[offset + 3] & 0xFF);

    uint32_t token = code % (uint32_t)pow(10, digits);
    snprintf(output, digits + 1, "%0*u", digits, token);
    return 0;
}

void mgAddrToHex(struct mg_addr *addr, char *dest, size_t destSize)
{
    if (!dest || destSize < 33) return;
    memset(dest, 0, destSize);
    for (int i = 0; i < (int)sizeof(addr->ip); i++)
    {
        sprintf(&dest[i * 2], "%02X", (unsigned char)addr->ip[i]);
    }
    dest[32] = 0;
}

char *mgHexToAddr(char *hexAddress) 
{
    char truncatedHex[9] =  {0};
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
    if (!cookieHeader) return 0;

    char cookieBuf[256] = {0};
    snprintf(cookieBuf, sizeof(cookieBuf), "%.*s", (int)cookieHeader->len, cookieHeader->buf);
    char *sessionPtr = strstr(cookieBuf, "session_id=");
    if (!sessionPtr) return 0;
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
    if (sqlite3_prepare_v2(database, checkSessionValidity, -1, &stmt, NULL) != SQLITE_OK) return 0;
    sqlite3_bind_text(stmt, 1, sessionId, -1, SQLITE_STATIC);

    int result = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW)
    {
        time_t exp = (time_t)sqlite3_column_int(stmt, 1);
        const unsigned char *dbip = sqlite3_column_text(stmt, 2);
        if (userName != NULL) {
            const char *userNamePointer = sqlite3_column_text(stmt, 0);
            strncpy(userName, userNamePointer, sizeof(userName));
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
    if (TOTPAttempts == NULL) {
    return calloc(TOTPAttemptsSize, sizeof(struct TOTPAttempt));
    }
    struct TOTPAttempt *TOTPAttemptsDuplicate = calloc(TOTPAttemptsSize, sizeof(struct TOTPAttempt));
    int validIndices = 0;
    for (int i = 0; i < *TOTPAttemptsUsed; i ++) 
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
    free (TOTPAttempts);
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
