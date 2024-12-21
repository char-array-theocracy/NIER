#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <math.h>
#include <pthread.h>
#include <sqlite3.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include "mongoose.h"
#include "NIER.h"
#include <cjson/cJSON.h>

#define LISTEN_URI "http://0.0.0.0:8000"

int debugFlag = 0;
struct mg_str loginApiUri;
sqlite3 *database = NULL;

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
const char *listUsersQuery = "SELECT NAME, TOTP_CODE FROM USERS";

void *mongoosePollThread(void *arg)
{
    struct mg_mgr *mgr = (struct mg_mgr *)arg;
    for (;;)
    {
        mg_mgr_poll(mgr, 1000);
    }
    return NULL;
}

extern int checkSession(struct mg_http_message *hm, struct mg_connection *c);
extern int generateTOTP(const char *base32Secret, int period, int digits, char *output);
extern void createSession(const char *user, struct mg_connection *c);

void ev_handler(struct mg_connection *c, int ev, void *ev_data)
{
    if (ev == MG_EV_HTTP_MSG)
    {
        struct mg_http_message *hm = (struct mg_http_message *)ev_data;
        int isAuthenticated = 0;

        if ((hm->uri.len == strlen("/api/login") && strncmp(hm->uri.buf, "/api/login", hm->uri.len) == 0) ||
            (hm->uri.len == strlen("/login.html") && strncmp(hm->uri.buf, "/login.html", hm->uri.len) == 0))
        {
        }
        else
        {
            isAuthenticated = checkSession(hm, c);
            if (!isAuthenticated)
            {
                mg_http_reply(c, 302, "Location: /login.html\r\n", "");
                return;
            }
        }

        if (mg_strcmp(hm->uri, loginApiUri) == 0)
        {
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
                        mg_http_reply(c, 400, "", "Invalid TOTP code\n");
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
                        mg_http_reply(c, 200, "", "Incorrect TOTP code\n");
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
        }

        struct mg_http_serve_opts opts = { .root_dir = "./web_root/" };
        mg_http_serve_dir(c, hm, &opts);
    }
}

int main(int argc, char **argv)
{
    if (argc > 1)
    {
        if (argc > 3)
        {
            NIER_LOGE("NIER", "Too many arguments");
        }
        if (argc >= 3 && strncmp(argv[2], "-d", 3) == 0)
        {
            debugFlag = 1;
        }
        else
        {
            printf("-d Debug mode\n");
            NIER_LOGE("NIER", "Invalid argument");
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

    struct mg_mgr mgr;
    mg_mgr_init(&mgr);
    loginApiUri = mg_str("/api/login");
    mg_http_listen(&mgr, LISTEN_URI, ev_handler, NULL);
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

    sqlite3_close_v2(database);
    pthread_cancel(mongoosePollThreadId);
    pthread_join(mongoosePollThreadId, NULL);
    mg_mgr_free(&mgr);
    return 0;
}
