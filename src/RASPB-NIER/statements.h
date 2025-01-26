#ifndef STATEMENTS_H
#define STATEMENTS_H

extern const char *base32Chars;

extern const char *totpPasswordQuery;
extern const char *checkUsersTable;
extern const char *createUsersTable;
extern const char *insertUserStatement;
extern const char *deleteUserStatement;
extern const char *listUsersQuery;

extern const char *checkSessionsTable;
extern const char *createSessionsTable;
extern const char *insertSessionStatement;
extern const char *checkSessionValidity;
extern const char *deleteExpiredSession;

extern const char *createDevicesTable;
extern const char *listDevices;
extern const char *checkDeviceOnlineState;
extern const char *updateDevice;
extern const char *insertDevice;
extern const char *checkDevicesTable;
extern const char *updateDeviceData;
extern const char *checkDeviceData;

extern const char *createCamerasTable;
extern const char *insertCamera;
extern const char *removeCamera;
extern const char *listCameras;
extern const char *checkCamerasTable;
extern const char *checkCameraValues;

#endif 