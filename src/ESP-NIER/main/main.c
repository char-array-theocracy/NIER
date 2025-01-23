#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "mqtt_client.h"
#include "esp_tls.h"
#include "esp_adc/adc_oneshot.h"
#include "esp_adc_cal.h"
#include "cJSON.h"
#include "esp_timer.h"
#include "driver/gpio.h"
#include "esp_sntp.h"
#include "nvs.h"
#include "driver/i2c.h"
#include "hal/i2c_types.h"
#include "esp_mac.h"
#include "lwip/sockets.h"

static const uint8_t s_key[] = {0x84, 0xfb, 0x15, 0x95, 0x36, 0x45, 0x44, 0xaf, 0x46, 0xad, 0x95, 0x55, 0x09, 0xb7, 0xa0, 0x7c};
static const psk_hint_key_t psk_hint_key = {
    .key = s_key,
    .key_size = sizeof(s_key),
    .hint = "test1"};
#define WIFI_SSID "Art"
#define WIFI_PASS "13214227"
#define BEACON_PORT 54321
#define DEVICE1 "SmartSwitch"
#define DEVICE2 "TemperatureHumiditySensor"
static const char *TAG = "NIER";
static char *deviceIdentifier = NULL;
static int deviceType = 0;
static QueueHandle_t mqttDeviceQueue;
static const char base62Chars[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
static int wifiSuccessfulConnections = 0;
static esp_event_handler_instance_t wifiHandlerEventInstance;
static esp_event_handler_instance_t gotIpEventInstance;
static EventGroupHandle_t theEventGroup;
static int retryNum = 0;
static nvs_handle_t nvsHandle;
static TaskHandle_t deviceTaskHandle = NULL;
static TaskHandle_t mqttKeepAliveTaskHandle = NULL;

#define DETECT_ADC_CHANNEL ADC1_CHANNEL_2
#define V_REF 3300
#define DETECT_ADC_ATTEN ADC_ATTEN_DB_12
#define WIFI_SUCCESS BIT0
#define MQTT_SUCCESS BIT1
#define TIME_SYNC_SUCCESS BIT2
#define MAX_FAILURES 10
#define STATUS_INTERVAL_IN_SECONDS 10
#define MQTT_QOS 2
#define SNTP_PRIMARY_SERVER "pool.ntp.org"
#define SNTP_SECONDARY_SERVER "time.google.com"
#define TIMEZONE "EET-2EEST,M3.5.0/3,M10.5.0/4"
#define I2C_MASTER_SCL_IO GPIO_NUM_23
#define I2C_MASTER_SDA_IO GPIO_NUM_22
#define I2C_MASTER_FREQ_HZ 100000
#define I2C_MASTER_NUM I2C_NUM_0
#define I2C_MASTER_TX_BUF_DISABLE 0
#define I2C_MASTER_RX_BUF_DISABLE 0
#define SENSOR_I2C_ADDRESS 0x38

static char *readUDPBeacon()
{
    int sockfd;
    char buffer[256] = {0};
    char *recievedIP = calloc(256, sizeof(char));
    struct sockaddr_in listenAddress;
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        ESP_LOGE(TAG, "Failed to open socket for listening of UDP beacon");
        return NULL;
    }

    memset(&listenAddress, 0, sizeof(listenAddress));
    listenAddress.sin_family = AF_INET;
    listenAddress.sin_port = htons(BEACON_PORT);
    listenAddress.sin_addr.s_addr = INADDR_ANY;

    if (bind(sockfd, (struct sockaddr *)&listenAddress, sizeof(listenAddress)) < 0)
    {
        ESP_LOGE(TAG, "Failed to bind socket for listening of UDP beacon");
        close(sockfd);
        return NULL;
    }

    for (;;)
    {
        memset(buffer, 0, 256);
        ssize_t recievedLength = recv(sockfd, buffer, 255, 0);
        cJSON *recievedJSON = cJSON_ParseWithLength(buffer, (size_t)recievedLength);
        if (recievedJSON == NULL)
        {
            ESP_LOGW(TAG, "Failed to parse recieved UDP beacon message");
        }
        else
        {
            cJSON *ipJSON = cJSON_GetObjectItem(recievedJSON, "ip");
            if (ipJSON == NULL)
            {
                ESP_LOGW(TAG, "Failed to parse recieved UDP beacon message");
            }
            else
            {
                snprintf(recievedIP, 255, "%s", cJSON_GetStringValue(ipJSON));
                ESP_LOGI(TAG, "Recieved IP from UDP beacon: %s", recievedIP);
                cJSON_Delete(recievedJSON);
                break;
            }
        }
    }
    close(sockfd);
    return recievedIP;
}

static void timeSyncNotification(struct timeval *tv)
{
    ESP_LOGI(TAG, "Time synchronized with NTP server");
    xEventGroupSetBits(theEventGroup, TIME_SYNC_SUCCESS);
}

static void initializeSNTP(void)
{
    ESP_LOGI(TAG, "Initializing SNTP");
    esp_sntp_setoperatingmode(SNTP_OPMODE_POLL);
    esp_sntp_setservername(0, SNTP_PRIMARY_SERVER);
    esp_sntp_setservername(1, SNTP_SECONDARY_SERVER);
    esp_sntp_set_sync_interval(3600);
    esp_sntp_set_time_sync_notification_cb(timeSyncNotification);
    esp_sntp_init();
}

static void logErrorIfNonZero(const char *message, int errorCode)
{
    if (errorCode != 0)
    {
        ESP_LOGE(TAG, "Last error %s: 0x%x", message, errorCode);
    }
}

static void wifiEventHandler(void *arg, esp_event_base_t eventBase, int32_t eventId, void *eventData)
{
    if (eventBase == WIFI_EVENT && eventId == WIFI_EVENT_STA_START)
    {
        ESP_LOGI(TAG, "Connecting to AP...");
        esp_wifi_connect();
    }
    else if (eventBase == WIFI_EVENT && eventId == WIFI_EVENT_STA_DISCONNECTED)
    {
        if (retryNum < MAX_FAILURES)
        {
            xEventGroupClearBits(theEventGroup, WIFI_SUCCESS);
            if (wifiSuccessfulConnections > 0)
            {
                ESP_LOGE(TAG, "Lost connection to AP");
                ESP_LOGW(TAG, "Reconnecting...");
            }
            else
            {
                ESP_LOGE(TAG, "Failed to connect to AP");
                ESP_LOGW(TAG, "Trying again...");
            }
            esp_wifi_connect();
            retryNum++;
            vTaskDelay(pdMS_TO_TICKS(3000));
        }
        else
        {
            ESP_LOGE(TAG, "Failed to reconnect to AP, rebooting...");
            esp_restart();
        }
    }
    else if (eventBase == WIFI_EVENT && eventId == WIFI_EVENT_STA_CONNECTED)
    {
        ESP_LOGI(TAG, "Connected to AP");
        retryNum = 0;
    }
}

static void ipEventHandler(void *arg, esp_event_base_t eventBase, int32_t eventId, void *eventData)
{
    if (eventBase == IP_EVENT && eventId == IP_EVENT_STA_GOT_IP)
    {
        ip_event_got_ip_t *event = (ip_event_got_ip_t *)eventData;
        ESP_LOGI(TAG, "STA IP: " IPSTR, IP2STR(&event->ip_info.ip));
        xEventGroupSetBits(theEventGroup, WIFI_SUCCESS);
        wifiSuccessfulConnections++;
    }
}

static void connectWifi(void)
{
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &wifiEventHandler, NULL, &wifiHandlerEventInstance));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &ipEventHandler, NULL, &gotIpEventInstance));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    wifi_config_t wifiConfig = {
        .sta = {
            .ssid = WIFI_SSID,
            .password = WIFI_PASS,
            .threshold.authmode = WIFI_AUTH_WPA_WPA2_PSK,
            .pmf_cfg = {
                .capable = false,
                .required = false},
        },
    };
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifiConfig));
    ESP_ERROR_CHECK(esp_wifi_start());
    EventBits_t bits = xEventGroupWaitBits(theEventGroup, WIFI_SUCCESS, pdFALSE, pdFALSE, portMAX_DELAY);
    if (bits & WIFI_SUCCESS)
    {
        ESP_LOGI(TAG, "Connected to Wi-Fi");
    }
    else
    {
        ESP_LOGE(TAG, "Failed to connect to Wi-Fi");
    }
}

void mqttStatus(void *pvParameters)
{
    esp_mqtt_client_handle_t client = *(esp_mqtt_client_handle_t *)pvParameters;
    while (1)
    {
        cJSON *message = cJSON_CreateObject();
        if (message)
        {
            cJSON_AddNumberToObject(message, "time", time(0));
            cJSON_AddNumberToObject(message, "uptime", esp_timer_get_time() / 1000000);
            wifi_ap_record_t ap;
            esp_wifi_sta_get_ap_info(&ap);
            cJSON_AddNumberToObject(message, "rssi", ap.rssi);
            cJSON_AddNumberToObject(message, "heapTotal", heap_caps_get_total_size(MALLOC_CAP_DEFAULT));
            cJSON_AddNumberToObject(message, "heapUsed", esp_get_free_heap_size());
            char *jsonString = cJSON_PrintUnformatted(message);
            if (jsonString)
            {
                char topic[128];
                snprintf(topic, sizeof(topic), "devices/%s/status", deviceIdentifier);
                int msg_id = esp_mqtt_client_publish(client, topic, jsonString, 0, MQTT_QOS, 0);
                if (msg_id >= 0)
                {
                    ESP_LOGI(TAG, "Sent status");
                }
                else
                {
                    ESP_LOGE(TAG, "Failed to send status");
                }
                free(jsonString);
            }
            cJSON_Delete(message);
        }
        vTaskDelay(pdMS_TO_TICKS(STATUS_INTERVAL_IN_SECONDS * 1000));
    }
}

static void mqttEventHandler(void *arg, esp_event_base_t eventBase, int32_t eventId, void *eventData)
{
    esp_mqtt_event_handle_t event = eventData;
    esp_mqtt_client_handle_t client = event->client;
    switch ((esp_mqtt_event_id_t)eventId)
    {
    case MQTT_EVENT_BEFORE_CONNECT:
        ESP_LOGI(TAG, "MQTT_EVENT_BEFORE_CONNECT");
        break;
    case MQTT_EVENT_CONNECTED:
        ESP_LOGI(TAG, "MQTT_EVENT_CONNECTED");
        {
            cJSON *connectionMessage = cJSON_CreateObject();
            if (connectionMessage)
            {
                cJSON_AddStringToObject(connectionMessage, "deviceID", deviceIdentifier);
                cJSON_AddNumberToObject(connectionMessage, "online", 1);
                switch (deviceType)
                {
                case (1):
                    cJSON_AddStringToObject(connectionMessage, "deviceType", DEVICE1);
                    break;
                case (2):
                    cJSON_AddStringToObject(connectionMessage, "deviceType", DEVICE2);
                default:
                    cJSON_AddStringToObject(connectionMessage, "deviceType", "Unknown");
                    break;
                }
                char *jsonString = cJSON_PrintUnformatted(connectionMessage);
                if (jsonString)
                {
                    esp_mqtt_client_publish(client, "devices/presence", jsonString, 0, MQTT_QOS, 0);
                    free(jsonString);
                }
                cJSON_Delete(connectionMessage);
            }
            xEventGroupSetBits(theEventGroup, MQTT_SUCCESS);
        }
        break;
    case MQTT_EVENT_DISCONNECTED:
        ESP_LOGI(TAG, "MQTT_EVENT_DISCONNECTED");
        xEventGroupClearBits(theEventGroup, MQTT_SUCCESS);
        break;
    case MQTT_EVENT_SUBSCRIBED:
        ESP_LOGI(TAG, "MQTT_EVENT_SUBSCRIBED, messageId=%d", event->msg_id);
        break;
    case MQTT_EVENT_UNSUBSCRIBED:
        ESP_LOGI(TAG, "MQTT_EVENT_UNSUBSCRIBED, messageId=%d", event->msg_id);
        break;
    case MQTT_EVENT_PUBLISHED:
        ESP_LOGI(TAG, "MQTT_EVENT_PUBLISHED, messageId=%d", event->msg_id);
        break;
    case MQTT_EVENT_DATA:
    {
        cJSON *receivedMessage = cJSON_Parse(event->data);
        if (!receivedMessage)
        {
            ESP_LOGW(TAG, "Failed to parse received JSON");
            return;
        }
        if (xQueueSend(mqttDeviceQueue, &receivedMessage, portMAX_DELAY) != pdTRUE)
        {
            ESP_LOGW(TAG, "Failed to enqueue message");
            cJSON_Delete(receivedMessage);
        }
    }
    break;
    case MQTT_EVENT_ERROR:
        ESP_LOGI(TAG, "MQTT_EVENT_ERROR");
        if (event->error_handle && event->error_handle->error_type == MQTT_ERROR_TYPE_TCP_TRANSPORT)
        {
            logErrorIfNonZero("esp-tls", event->error_handle->esp_tls_last_esp_err);
            logErrorIfNonZero("tls stack", event->error_handle->esp_tls_stack_err);
            logErrorIfNonZero("socket errno", event->error_handle->esp_transport_sock_errno);
        }
        break;
    default:
        ESP_LOGI(TAG, "Other event id:%d", event->event_id);
        break;
    }
}

static char *acquireIdentifier(void)
{
    uint8_t mac[6];
    esp_wifi_get_mac(WIFI_IF_STA, mac);
    uint64_t macValue = 0;
    for (int i = 0; i < 6; i++)
    {
        macValue = (macValue << 8) | mac[i];
    }
    char *base62Encoded = calloc(12, sizeof(char));
    char buffer[12];
    int index = 0;
    do
    {
        uint8_t remainder = macValue % 62;
        buffer[index++] = base62Chars[remainder];
        macValue /= 62;
    } while (macValue > 0);
    for (int i = 0; i < index; i++)
    {
        base62Encoded[i] = buffer[index - i - 1];
    }
    base62Encoded[index] = '\0';
    return base62Encoded;
}

static int identifyDevice(void)
{
    adc_oneshot_unit_handle_t adcHandle;
    adc_oneshot_unit_init_cfg_t initConfig = {
        .unit_id = ADC_UNIT_1,
        .ulp_mode = ADC_ULP_MODE_DISABLE,
    };
    ESP_ERROR_CHECK(adc_oneshot_new_unit(&initConfig, &adcHandle));
    adc_oneshot_chan_cfg_t channelConfig = {
        .bitwidth = ADC_BITWIDTH_DEFAULT,
        .atten = DETECT_ADC_ATTEN,
    };
    ESP_ERROR_CHECK(adc_oneshot_config_channel(adcHandle, DETECT_ADC_CHANNEL, &channelConfig));
    float voltage = 0;
    for (int i = 0; i < 5; i++)
    {
        int temp;
        ESP_ERROR_CHECK(adc_oneshot_read(adcHandle, DETECT_ADC_CHANNEL, &temp));
        voltage += ((float)temp * 3.3) / 4095.0;
        vTaskDelay(pdMS_TO_TICKS(50));
    }
    voltage /= 5.0;
    ESP_LOGI(TAG, "U: %f", voltage);
    ESP_ERROR_CHECK(adc_oneshot_del_unit(adcHandle));
    if (voltage > 2.52 && voltage <= 3.3)
    {
        return 1;
    }
    else if (voltage > 2.128 && voltage < 2.52)
    {
        return 2;
    }
    else if (voltage > 1.81 && voltage <= 2.095)
    {
        return 5;
    }
    else if (voltage > 1.57 && voltage <= 1.8)
    {
        return 6;
    }
    else
    {
        return 0;
    }
}

static void smartSwitch(void *pvParamaters)
{
    esp_mqtt_client_handle_t client = *(esp_mqtt_client_handle_t *)pvParamaters;
    char callsTopic[128];
    snprintf(callsTopic, sizeof(callsTopic), "devices/%s/calls", deviceIdentifier);
    esp_mqtt_client_subscribe(client, callsTopic, MQTT_QOS);
    gpio_config_t io_conf = {
        .pin_bit_mask = (1ULL << GPIO_NUM_0),
        .mode = GPIO_MODE_OUTPUT,
        .pull_down_en = false,
        .pull_up_en = false,
        .intr_type = GPIO_INTR_DISABLE};
    gpio_config(&io_conf);
    int32_t restoreState = -1;
    ESP_ERROR_CHECK_WITHOUT_ABORT(nvs_get_i32(nvsHandle, "switchState", &restoreState));
    if (restoreState >= 0)
    {
        gpio_set_level(GPIO_NUM_0, restoreState);
    }
    else
    {
        ESP_LOGW(TAG, "Failed to restore switch state");
        restoreState = 0;
    }

    char respTopic[128] = {0};
    snprintf(respTopic, sizeof(respTopic), "devices/%s/responses", deviceIdentifier);
    char respStr[256] = {0};
    snprintf(respStr, sizeof(respStr), "{\"call\":\"changeSwitchState\",\"state\":%ld}", restoreState);
    esp_mqtt_client_publish(client, respTopic, respStr, 0, MQTT_QOS, 0);

    ESP_LOGI(TAG, "Restored switch state: %ld", restoreState);
    while (1)
    {
        cJSON *receivedMessage = NULL;
        if (xQueueReceive(mqttDeviceQueue, &receivedMessage, portMAX_DELAY) != pdTRUE)
        {

            ESP_LOGW(TAG, "Failed to dequeue message");
            continue;
        }
        if (!receivedMessage)
        {
            ESP_LOGW(TAG, "Invalid JSON for switch");
            continue;
        }
        cJSON *callItem = cJSON_GetObjectItemCaseSensitive(receivedMessage, "call");
        if (!callItem || !cJSON_IsString(callItem))
        {
            ESP_LOGW(TAG, "No valid call object");
            cJSON_Delete(receivedMessage);
            continue;
        }
        if (strcmp(callItem->valuestring, "changeSwitchState") != 0)
        {
            ESP_LOGI(TAG, "Ignoring non-switch call: %s", callItem->valuestring);
            cJSON_Delete(receivedMessage);
            continue;
        }
        cJSON *receivedState = cJSON_GetObjectItemCaseSensitive(receivedMessage, "state");
        if (!receivedState || !cJSON_IsNumber(receivedState))
        {
            ESP_LOGW(TAG, "Missing switch state");
            cJSON_Delete(receivedMessage);
            continue;
        }
        int state = receivedState->valueint;
        gpio_set_level(GPIO_NUM_0, state);
        nvs_set_i32(nvsHandle, "switchState", state);
        cJSON *switchResponse = cJSON_CreateObject();
        if (switchResponse)
        {
            cJSON_AddStringToObject(switchResponse, "call", "changeSwitchState");
            cJSON_AddNumberToObject(switchResponse, "state", state);
            char *respStr = cJSON_PrintUnformatted(switchResponse);
            if (respStr)
            {
                char respTopic[128];
                snprintf(respTopic, sizeof(respTopic), "devices/%s/responses", deviceIdentifier);
                esp_mqtt_client_publish(client, respTopic, respStr, 0, MQTT_QOS, 0);
                free(respStr);
            }
            cJSON_Delete(switchResponse);
        }
        cJSON_Delete(receivedMessage);
    }
}

static void i2c_master_init(void)
{
    i2c_config_t conf = {
        .mode = I2C_MODE_MASTER,
        .sda_io_num = I2C_MASTER_SDA_IO,
        .scl_io_num = I2C_MASTER_SCL_IO,
        .sda_pullup_en = GPIO_PULLUP_ENABLE,
        .scl_pullup_en = GPIO_PULLUP_ENABLE,
        .master.clk_speed = I2C_MASTER_FREQ_HZ};
    ESP_ERROR_CHECK(i2c_param_config(I2C_MASTER_NUM, &conf));
    ESP_ERROR_CHECK(i2c_driver_install(I2C_MASTER_NUM, conf.mode, I2C_MASTER_RX_BUF_DISABLE, I2C_MASTER_TX_BUF_DISABLE, 0));
    ESP_LOGI(TAG, "I2C SDA=%d, SCL=%d, address=0x%02X", I2C_MASTER_SDA_IO, I2C_MASTER_SCL_IO, SENSOR_I2C_ADDRESS);
}

static esp_err_t aht10_init(void)
{
    i2c_cmd_handle_t cmd = i2c_cmd_link_create();
    i2c_master_start(cmd);
    i2c_master_write_byte(cmd, (SENSOR_I2C_ADDRESS << 1) | I2C_MASTER_WRITE, true);
    i2c_master_write_byte(cmd, 0xBE, true);
    i2c_master_write_byte(cmd, 0x08, true);
    i2c_master_write_byte(cmd, 0x00, true);
    i2c_master_stop(cmd);
    esp_err_t err = i2c_master_cmd_begin(I2C_MASTER_NUM, cmd, pdMS_TO_TICKS(100));
    i2c_cmd_link_delete(cmd);
    if (err != ESP_OK)
    {
        ESP_LOGW(TAG, "AHT10 init error: %s", esp_err_to_name(err));
        return err;
    }
    vTaskDelay(pdMS_TO_TICKS(20));
    return ESP_OK;
}

static esp_err_t aht10_readData(float *temperature, float *humidity)
{
    i2c_cmd_handle_t cmd = i2c_cmd_link_create();
    i2c_master_start(cmd);
    i2c_master_write_byte(cmd, (SENSOR_I2C_ADDRESS << 1) | I2C_MASTER_WRITE, true);
    i2c_master_write_byte(cmd, 0xAC, true);
    i2c_master_write_byte(cmd, 0x33, true);
    i2c_master_write_byte(cmd, 0x00, true);
    i2c_master_stop(cmd);
    esp_err_t err = i2c_master_cmd_begin(I2C_MASTER_NUM, cmd, pdMS_TO_TICKS(100));
    i2c_cmd_link_delete(cmd);
    if (err != ESP_OK)
    {
        return err;
    }
    vTaskDelay(pdMS_TO_TICKS(75));
    uint8_t data[6] = {0};
    cmd = i2c_cmd_link_create();
    i2c_master_start(cmd);
    i2c_master_write_byte(cmd, (SENSOR_I2C_ADDRESS << 1) | I2C_MASTER_READ, true);
    for (int i = 0; i < 5; i++)
    {
        i2c_master_read_byte(cmd, &data[i], I2C_MASTER_ACK);
    }
    i2c_master_read_byte(cmd, &data[5], I2C_MASTER_NACK);
    i2c_master_stop(cmd);
    err = i2c_master_cmd_begin(I2C_MASTER_NUM, cmd, pdMS_TO_TICKS(100));
    i2c_cmd_link_delete(cmd);
    if (err != ESP_OK)
    {
        return err;
    }
    uint32_t rawHum = ((uint32_t)data[1] << 16 | (uint32_t)data[2] << 8 | data[3]) >> 4;
    uint32_t rawTemp = ((uint32_t)(data[3] & 0x0F) << 16) | ((uint32_t)data[4] << 8) | data[5];
    *humidity = (rawHum * 100.0f) / 1048576.0f;
    *temperature = (rawTemp * 200.0f / 1048576.0f) - 50.0f;
    return ESP_OK;
}

static void temperatureHumidityTask(void *pvParameters)
{
    esp_mqtt_client_handle_t client = *(esp_mqtt_client_handle_t *)pvParameters;
    while (1)
    {
        float temperature = 0, humidity = 0;
        if (aht10_readData(&temperature, &humidity) == ESP_OK)
        {
            cJSON *message = cJSON_CreateObject();
            if (message)
            {
                char temperatureString[64] = {0};
                char humidityString[64] = {0};
                snprintf(temperatureString, sizeof(temperatureString) - 1, "%.3f", temperature);
                snprintf(humidityString, sizeof(humidityString) - 1, "%.3f", humidity);
                char timeString[20] = {0};
                snprintf(timeString, sizeof(timeString), "%lld", time(NULL));
                cJSON *timeObject = cJSON_CreateObject();
                cJSON_AddNumberToObject(timeObject, "t", atof(temperatureString));
                cJSON_AddNumberToObject(timeObject, "h", atof(humidityString));
                cJSON_AddItemToObject(message, timeString, timeObject);
                char *jsonString = cJSON_PrintUnformatted(message);
                if (jsonString)
                {
                    char topic[128];
                    snprintf(topic, sizeof(topic), "devices/%s/temperatureHumiditySensor", deviceIdentifier);
                    esp_mqtt_client_publish(client, topic, jsonString, 0, MQTT_QOS, 1);
                    free(jsonString);
                }
                cJSON_Delete(message);
            }
        }
        else
        {
            ESP_LOGW(TAG, "Failed to read AHT10 sensor");
        }
        vTaskDelay(pdMS_TO_TICKS(60000 * 30));
    }
}

void app_main(void)
{
    esp_log_level_set("wifi", ESP_LOG_DEBUG);
    setenv("TZ", TIMEZONE, 1);
    mqttDeviceQueue = xQueueCreate(10, sizeof(cJSON *));
    theEventGroup = xEventGroupCreate();
    ESP_ERROR_CHECK(nvs_flash_init());
    deviceType = identifyDevice();
    connectWifi();
    initializeSNTP();
    deviceIdentifier = acquireIdentifier();
    ESP_LOGI(TAG, "Device identifier: %s", deviceIdentifier);
    EventBits_t timeBits = xEventGroupWaitBits(theEventGroup, TIME_SYNC_SUCCESS, pdFALSE, pdFALSE, portMAX_DELAY);
    if (!(timeBits & TIME_SYNC_SUCCESS))
    {
        ESP_LOGE(TAG, "Failed to sync RTC with NTP server");
    }
    cJSON *lwt = cJSON_CreateObject();
    if (lwt)
    {
        cJSON_AddStringToObject(lwt, "deviceID", deviceIdentifier);
        cJSON_AddNumberToObject(lwt, "online", 0);
        switch (deviceType)
        {
        case (1):
            cJSON_AddStringToObject(lwt, "deviceType", DEVICE1);
            break;
        case (2):
            cJSON_AddStringToObject(lwt, "deviceType", DEVICE2);
        default:
            cJSON_AddStringToObject(lwt, "deviceType", "Unknown");
            break;
        }
    }
    char lwtBuf[256] = {0};
    snprintf(lwtBuf, sizeof(lwtBuf), "%s", lwt ? cJSON_PrintUnformatted(lwt) : "{}");
    if (lwt)
        cJSON_Delete(lwt);
    char *BrokerIp = readUDPBeacon();
    const esp_mqtt_client_config_t mqttCfg = {
        .broker.address.uri = BrokerIp,
        .broker.verification.psk_hint_key = &psk_hint_key,
        .session.last_will.msg = lwtBuf,
        .session.last_will.msg_len = strlen(lwtBuf),
        .session.last_will.qos = 1,
        .session.last_will.topic = "devices/presence",
        .session.last_will.retain = 0,
        .session.keepalive = 2};
    esp_mqtt_client_handle_t client = esp_mqtt_client_init(&mqttCfg);
    esp_mqtt_client_register_event(client, ESP_EVENT_ANY_ID, mqttEventHandler, NULL);
    esp_mqtt_client_start(client);
    EventBits_t mqttBits = xEventGroupWaitBits(theEventGroup, MQTT_SUCCESS, pdFALSE, pdFALSE, portMAX_DELAY);
    if (mqttBits & MQTT_SUCCESS)
    {
        ESP_LOGI(TAG, "Connected to MQTT broker");
        xTaskCreate(mqttStatus, "mqttStatus", 4096, &client, tskIDLE_PRIORITY + 1, &mqttKeepAliveTaskHandle);
    }
    else
    {
        ESP_LOGE(TAG, "Failed to connect to MQTT broker");
    }
    ESP_ERROR_CHECK(nvs_open("storage", NVS_READWRITE, &nvsHandle));
    switch (deviceType)
    {
    case 1:
        ESP_LOGI(TAG, "Detected device-type: %d -> SmartSwitch", deviceType);
        xTaskCreate(smartSwitch, "smartSwitch", 4096, &client, tskIDLE_PRIORITY + 2, &deviceTaskHandle);
        break;
    case 2:
        ESP_LOGI(TAG, "Detected device-type: %d -> T/H Sensor (AHT10)", deviceType);
        i2c_master_init();
        if (aht10_init() != ESP_OK)
        {
            ESP_LOGW(TAG, "AHT10 initialization failed");
        }
        xTaskCreate(temperatureHumidityTask, "temperatureHumidityTask", 4096, &client, tskIDLE_PRIORITY + 2, &deviceTaskHandle);
        break;
    case 5:
    case 6:
        ESP_LOGI(TAG, "Detected device-type: %d", deviceType);
        ESP_LOGW(TAG, "This device-type is not implemented yet...");
        break;
    default:
        ESP_LOGE(TAG, "Unknown device type: %d", deviceType);
        break;
    }
    while (1)
    {
        vTaskDelay(pdMS_TO_TICKS(300));
    }
    free(BrokerIp);
    vEventGroupDelete(theEventGroup);
    ESP_ERROR_CHECK(esp_event_handler_instance_unregister(IP_EVENT, IP_EVENT_STA_GOT_IP, gotIpEventInstance));
    ESP_ERROR_CHECK(esp_event_handler_instance_unregister(WIFI_EVENT, ESP_EVENT_ANY_ID, wifiHandlerEventInstance));
}