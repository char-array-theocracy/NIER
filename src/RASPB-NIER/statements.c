#include "statements.h"

const char *base32Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const char *totpPasswordQuery = "SELECT PASSWORD, TOTP_CODE FROM USERS WHERE NAME = ?";
const char *checkUsersTable = "SELECT name FROM sqlite_master WHERE type='table' AND name='USERS';";
const char *createUsersTable =
    "CREATE TABLE IF NOT EXISTS USERS("
    "NAME TEXT UNIQUE PRIMARY KEY,"
    "PASSWORD TEXT NOT NULL,"
    "TOTP_CODE TEXT NOT NULL"
    ") WITHOUT ROWID;";
const char *insertUserStatement = "INSERT INTO USERS (NAME, PASSWORD, TOTP_CODE) VALUES (?, ?, ?);";
const char *deleteUserStatement = "DELETE FROM USERS WHERE NAME = ?";
const char *listUsersQuery = "SELECT NAME, PASSWORD, TOTP_CODE FROM USERS";

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
    "DEVICE_TYPE TEXT NOT NULL,"
    "DATA TEXT"
    ") WITHOUT ROWID;";
const char *listDevices =
    "SELECT ID, "
    "CASE WHEN ONLINE THEN '1' ELSE '0' END AS STATE, "
    "DEVICE_TYPE, "
    "DATA "
    "FROM DEVICES;";
const char *checkDeviceOnlineState = "SELECT ONLINE, DEVICE_TYPE FROM DEVICES WHERE ID = ?;";
const char *updateDevice = "UPDATE DEVICES SET ONLINE = ?, DEVICE_TYPE = ? WHERE ID = ?;";
const char *insertDevice = "INSERT INTO DEVICES (ID, ONLINE, DEVICE_TYPE, DATA) VALUES (?, ?, ?, ?);";
const char *checkDevicesTable = "SELECT name FROM sqlite_master WHERE type='table' AND name='DEVICES';";
const char *updateDeviceData = "UPDATE DEVICES SET DATA = ? WHERE ID = ?";
const char *checkDeviceData = "SELECT DATA FROM DEVICES WHERE ID = ?;";

const char *createCamerasTable =
    "CREATE TABLE IF NOT EXISTS CAMERAS ("
    "CAMERA_NAME TEXT UNIQUE PRIMARY KEY,"
    "RTSP_URL TEXT NOT NULL,"
    "CONTROL_URL TEXT NOT NULL,"
    "CONTROL_USERNAME TEXT NOT NULL,"
    "CONTROL_PASSWORD TEXT NOT NULL"
    ") WITHOUT ROWID;";
const char *insertCamera = "INSERT INTO CAMERAS (CAMERA_NAME, RTSP_URL, CONTROL_URL, CONTROL_USERNAME, CONTROL_PASSWORD) VALUES (?, ?, ?, ?, ?);";
const char *removeCamera = "DELETE FROM CAMERAS WHERE CAMERA_NAME = ?;";
const char *listCameras = "SELECT CAMERA_NAME, RTSP_URL, CONTROL_URL, CONTROL_USERNAME, CONTROL_PASSWORD FROM CAMERAS;";
const char *checkCamerasTable = "SELECT name FROM sqlite_master WHERE type='table' AND name='CAMERAS';";
const char *checkCameraValues = "SELECT RTSP_URL, CONTROL_URL, CONTROL_USERNAME, CONTROL_PASSWORD FROM CAMERAS WHERE CAMERA_NAME = ?;";