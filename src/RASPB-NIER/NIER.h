#ifndef NIER_H
#define NIER_H

#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include "mongoose.h"
#include <stdint.h>
#include <sqlite3.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __GNUC__
#define UNUSED __attribute__((unused))
#else
#define UNUSED
#endif

extern int debugFlag;
extern struct mg_str loginApiUri;
extern sqlite3 *database;

void NIER_LOGI(const char *tag, const char *format, ...);
void NIER_LOGW(const char *tag, const char *format, ...);
void NIER_LOGE(const char *tag, const char *format, ...);
void NIER_LOGD(const char *tag, const char *format, ...);

void intToBytes(uint64_t value, unsigned char *bytes);
int generateTOTP(const char *base32Secret, int period, int digits, char *output);
void mgAddrToHex(struct mg_addr *addr, char *dest, size_t destSize);
int checkSession(struct mg_http_message *hm, struct mg_connection *c, char *userName);
void createSession(const char *user, struct mg_connection *c);
void cleanExpiredSessions();
struct TOTPAttempt *cleanTOTPAttempts(struct TOTPAttempt *TOTPAttempts, int *TOTPAttemptsUsed, int TOTPAttemptsSize); 
char *mgHexToAddr(char *hexAddress); 
void addWSConnection(struct mg_connection *c); 
void removeWSConnection(struct mg_connection *c); 
void broadcastWSMessage(const char *message);
char *getDeviceList();
int setupMosqBroker();

struct TOTPAttempt
{
    char ipHex[33];
    time_t attemptTime;
};

void startCameraStreams(); 
size_t nullWriteCallback(UNUSED void *contents, size_t size, size_t nmemb, UNUSED void *userp);

#ifdef __cplusplus
}
#endif

#endif
