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

/* Definitions */
#define DETECT_ADC_CHANNEL ADC1_CHANNEL_6
#define V_REF 3300                
#define DETECT_ADC_ATTEN ADC_ATTEN_DB_12
#define BROKER_URI "mqtts://192.168.1.155"
#define WIFI_SUCCESS BIT0
#define MQTT_SUCCESS BIT1
#define TIME_SYNC_SUCCESS BIT2
#define MAX_FAILURES 10
#define KEEP_ALIVE_INTERVAL_IN_SECONDS 4
#define SNTP_PRIMARY_SERVER "pool.ntp.org"
#define SNTP_SECONDARY_SERVER "time.google.com" 
#define TIMEZONE "EET-2EEST,M3.5.0/3,M10.5.0/4"

/* Out-of-scope */
static const char *TAG = "NIER";
static const uint8_t s_key[] = { 0x74, 0x65, 0x73, 0x74 }; // test
static char *deviceIdentifier = NULL;
static int deviceType = 0;
static const psk_hint_key_t psk_hint_key = {
    .key = s_key,
    .key_size = sizeof(s_key),
    .hint = "NIER"
};

static const wifi_config_t wifiConfig = {
    .sta = {
        .ssid = "Art",
        .password = "13214227",
        .threshold.authmode = WIFI_AUTH_WPA_WPA2_PSK, 
        .pmf_cfg = {
            .capable = false, // Disabled PMF
            .required = false
        },
    },
};

static QueueHandle_t mqttDeviceQueue;
static const char base62Chars[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/* WiFi stuff */
static int wifiSuccessfulConnections = 0;
static esp_event_handler_instance_t wifiHandlerEventInstance;    
static esp_event_handler_instance_t gotIpEventInstance;
static EventGroupHandle_t theEventGroup;
static int retryNum = 0;

/* Task Handles */
static TaskHandle_t deviceTaskHandle = NULL;
static TaskHandle_t mqttKeepAliveTaskHandle = NULL;

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

static void wifiEventHandler(void* arg, esp_event_base_t eventBase,
                             int32_t eventId, void* eventData)
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
                ESP_LOGW(TAG, "Attempting to reconnect to AP...");
            } 
            else 
            {
                ESP_LOGE(TAG, "Failed to connect to AP");
                ESP_LOGW(TAG, "Attempting to connect to AP...");
            } 
            esp_wifi_set_config(WIFI_IF_STA, &wifiConfig);
            esp_wifi_connect();
            retryNum++;
            vTaskDelay(pdMS_TO_TICKS(3000));
        } 
        else 
        {
            ESP_LOGE(TAG, "Failed to reconnect to AP, rebooting ..."); 
            esp_restart();
        }
    }
    else if (eventBase == WIFI_EVENT && eventId == WIFI_EVENT_STA_CONNECTED)
    {
        ESP_LOGI(TAG, "Connected to AP");
        retryNum = 0; // Reset retry counter
    }
}

static void ipEventHandler(void* arg, esp_event_base_t eventBase,
                           int32_t eventId, void* eventData)
{
    if (eventBase == IP_EVENT && eventId == IP_EVENT_STA_GOT_IP)
    {
        ip_event_got_ip_t* event = (ip_event_got_ip_t*) eventData;
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

    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT,
                                                        ESP_EVENT_ANY_ID,
                                                        &wifiEventHandler,
                                                        NULL,
                                                        &wifiHandlerEventInstance));

    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT,
                                                        IP_EVENT_STA_GOT_IP,
                                                        &ipEventHandler,
                                                        NULL,
                                                        &gotIpEventInstance));

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifiConfig));
    ESP_ERROR_CHECK(esp_wifi_start());

    // Wait for Wi-Fi connection
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
void mqttStatus(void *pvParamaters) 
{
    esp_mqtt_client_handle_t client = *(esp_mqtt_client_handle_t *)pvParamaters;        
    while(1) 
    {
        cJSON *message = cJSON_CreateObject();
        if (message == NULL) 
        {
            ESP_LOGE(TAG, "Failed to create a JSON object");
        }
        cJSON_AddNumberToObject(message, "time", time(0));
        cJSON_AddNumberToObject(message, "uptime", esp_timer_get_time() / 1000000);
        wifi_ap_record_t ap;
        esp_wifi_sta_get_ap_info(&ap);
        cJSON_AddNumberToObject(message, "rssi", ap.rssi);
        cJSON_AddNumberToObject(message, "heapTotal", heap_caps_get_total_size(MALLOC_CAP_DEFAULT));
        cJSON_AddNumberToObject(message, "heapUsed", esp_get_free_heap_size());
        cJSON_AddNumberToObject(message, "deviceType", deviceType);
        char *jsonString = cJSON_PrintUnformatted(message);
        if (jsonString == NULL) 
        {
            ESP_LOGE(TAG, "Failed to print JSON");
        }

        int msg_id = esp_mqtt_client_publish(client, "devices/status", jsonString, 0, 1, 1);
        if (msg_id != -1) 
        {
            ESP_LOGI(TAG, "Sent keep-alive, msg_id=%d", msg_id);
        } else {
            ESP_LOGE(TAG, "Failed to send keep-alive");
        }
        cJSON_Delete(message);
        vTaskDelay(pdMS_TO_TICKS(KEEP_ALIVE_INTERVAL_IN_SECONDS * 1000));
    }
}

static void mqttEventHandler(void* arg, esp_event_base_t eventBase,
                             int32_t eventId, void* eventData) 
{
    ESP_LOGD(TAG, "Event dispatched from event loop base=%s, event_id=%" PRIi32, eventBase, eventId);
    esp_mqtt_event_handle_t event = eventData;
    esp_mqtt_client_handle_t client = event->client;
    int messageId;
    switch ((esp_mqtt_event_id_t)eventId) 
    {
        case MQTT_EVENT_BEFORE_CONNECT:
            ESP_LOGI(TAG, "MQTT_EVENT_BEFORE_CONNECT");
            break;
        case MQTT_EVENT_CONNECTED:
            ESP_LOGI(TAG, "MQTT_EVENT_CONNECTED");        
            cJSON *connectionMessage = cJSON_CreateObject();
            if (connectionMessage == NULL) 
            {
                ESP_LOGE(TAG, "Failed to create a JSON object");
            }
            cJSON_AddStringToObject(connectionMessage, "deviceID", deviceIdentifier);
            cJSON_AddNumberToObject(connectionMessage, "connected", 1);
            char *jsonString = cJSON_PrintUnformatted(connectionMessage);
            if (jsonString == NULL) 
            {
                ESP_LOGE(TAG, "Failed to print JSON");
            }

            esp_mqtt_client_publish(client, "devices/presence", jsonString, 0, 2, 0);
            cJSON_Delete(connectionMessage);
            xEventGroupSetBits(theEventGroup, MQTT_SUCCESS);
            break;
        case MQTT_EVENT_DISCONNECTED:
            ESP_LOGI(TAG, "MQTT_EVENT_DISCONNECTED");
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
            ESP_LOGI(TAG, "MQTT message recieved...");
            cJSON *recievedMessage = cJSON_Parse(event->data);
            if (recievedMessage == NULL) 
            {
                ESP_LOGW(TAG, "Failed to parse recieved JSON message");
                return;
            } 
            cJSON *recievedDeviceIdentifier = cJSON_GetObjectItemCaseSensitive(recievedMessage, "deviceID");
            
            if (cJSON_IsString(recievedDeviceIdentifier)) 
            {
                if (strncmp(recievedDeviceIdentifier->valuestring, deviceIdentifier, strlen(recievedDeviceIdentifier->valuestring)) == 0 ) 
                {
                    if (xQueueSend(mqttDeviceQueue, &recievedMessage, portMAX_DELAY) != pdTRUE) 
                    {
                        ESP_LOGW(TAG, "Failed to enqueue message");
                        cJSON_Delete(recievedMessage);  
                    }
                } 
                else 
                {
                    ESP_LOGI(TAG, "Device identifiers don't match, ignoring message");
                }
            } 
            else
            {
                ESP_LOGW(TAG, "Parsing the device identifier failed");
                return;                
            }

            break;
        case MQTT_EVENT_ERROR:
            ESP_LOGI(TAG, "MQTT_EVENT_ERROR");
            if (event->error_handle->error_type == MQTT_ERROR_TYPE_TCP_TRANSPORT) 
            {
                logErrorIfNonZero("reported from esp-tls", event->error_handle->esp_tls_last_esp_err);
                logErrorIfNonZero("reported from tls stack", event->error_handle->esp_tls_stack_err);
                logErrorIfNonZero("captured as transport's socket errno",  event->error_handle->esp_transport_sock_errno);
                ESP_LOGI(TAG, "Last errno string (%s)", strerror(event->error_handle->esp_transport_sock_errno));
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

    int i;
    for (i = 0; i < index; i++) 
    {
        base62Encoded[i] = buffer[index - i - 1];
    }
    base62Encoded[i] = '\0';  

    return base62Encoded;
}

static esp_mqtt_client_handle_t mqttAppStart(void)
{
    cJSON *lastWillAndTestament = cJSON_CreateObject();
    if (lastWillAndTestament == NULL) 
    {
        ESP_LOGE(TAG, "Failed to create JSON object");
    }
    cJSON_AddStringToObject(lastWillAndTestament, "deviceID", deviceIdentifier);
    cJSON_AddNumberToObject(lastWillAndTestament, "connected", 0);
    char lastWillAndTestamentFormatted[256] = {0};
    snprintf(lastWillAndTestamentFormatted, 256, cJSON_PrintUnformatted(lastWillAndTestament));
    const esp_mqtt_client_config_t mqttCfg = {
        .broker.address.uri = BROKER_URI,
        .broker.verification.psk_hint_key = &psk_hint_key,
        .session.last_will.msg = lastWillAndTestamentFormatted,
        .session.last_will.msg_len = strlen(lastWillAndTestamentFormatted),
        .session.last_will.qos = 1,
        .session.last_will.topic = "devices/presence",
        .session.last_will.retain = 1,
        .session.keepalive = 2
    };

    cJSON_Delete(lastWillAndTestament);
    esp_mqtt_client_handle_t client = esp_mqtt_client_init(&mqttCfg);
    esp_mqtt_client_register_event(client, ESP_EVENT_ANY_ID, mqttEventHandler, NULL);
    esp_mqtt_client_start(client);
    return client;
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

    if (voltage >= 3.11 && voltage <= 3.3) 
    {
        return 1;
    } 
    else if (voltage > 2.74 && voltage <= 3.01) 
    {
        return 2;
    } 
    else if (voltage > 2.52 && voltage <= 2.8) 
    {
        return 3;
    } 
    else if (voltage > 2.168 && voltage <= 2.447) 
    {
        return 4;
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
    esp_mqtt_client_subscribe_single(client, "devices/calls", 1);
    gpio_config_t io_conf = {
        .pin_bit_mask = (1ULL << GPIO_NUM_44),
        .mode = GPIO_MODE_OUTPUT,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .pull_up_en = GPIO_PULLUP_DISABLE,
        .intr_type = GPIO_INTR_DISABLE
    };
    gpio_config(&io_conf);

    while (1) 
    {
        cJSON *recievedMessage = NULL;
        if (xQueueReceive(mqttDeviceQueue, &recievedMessage, portMAX_DELAY) != pdTRUE) 
        { 
            ESP_LOGW(TAG, "Failed to receive enqueued message");
            continue; 
        }
        if (recievedMessage == NULL) 
        {
            ESP_LOGW(TAG, "JSON received by the switch task is invalid");
            continue; 
        } 

        cJSON *recievedCall = cJSON_GetObjectItemCaseSensitive(recievedMessage, "call");
        if (recievedCall == NULL || recievedCall->valuestring == NULL) 
        {
            ESP_LOGW(TAG, "Failed to parse call object or valuestring is NULL");
            cJSON_Delete(recievedMessage);
            continue;
        }

        if (strcmp(recievedCall->valuestring, "switch") != 0) 
        {
            ESP_LOGI(TAG, "Device is a switch, %s is incompatible", recievedCall->valuestring);
            cJSON_Delete(recievedMessage);
            continue;
        } 

        cJSON *recievedState = cJSON_GetObjectItemCaseSensitive(recievedMessage, "state");
        if (recievedState == NULL) 
        {
            ESP_LOGW(TAG, "Failed to parse switch state");
            cJSON_Delete(recievedMessage);
            continue;
        } 

        int state = recievedState->valueint;
        cJSON *switchResponse = cJSON_CreateObject();
        if (switchResponse == NULL)
        {
            ESP_LOGE(TAG, "Failed to create JSON object");
        }
        cJSON_AddNumberToObject(switchResponse, "time", time(0));
        cJSON_AddStringToObject(switchResponse, "deviceID", deviceIdentifier);
        cJSON_AddStringToObject(switchResponse, "call", "switch");
        switch (state) 
        {
            case 0:
                gpio_set_level(GPIO_NUM_44, 0);
                cJSON_AddNumberToObject(switchResponse, "state", 0);
                break;
            case 1:
                gpio_set_level(GPIO_NUM_44, 1);
                cJSON_AddNumberToObject(switchResponse, "state", 1);
                break;
            default:
                cJSON_AddNumberToObject(switchResponse, "state", -1);
                ESP_LOGW(TAG, "Unknown switch state");
        }
        char *buffer[256] = {0};
        sniprintf(buffer, 256, "%s", cJSON_PrintUnformatted(switchResponse));
        esp_mqtt_client_publish(client, "devices/responses", buffer, strlen(buffer), 1, 1);
        ESP_LOGI(TAG, "Switch message received %d", state);
        cJSON_Delete(switchResponse);
        cJSON_Delete(recievedMessage);
    }
}


void app_main(void)
{
    esp_log_level_set("wifi", ESP_LOG_DEBUG);
    setenv("TZ", TIMEZONE, 1);

    mqttDeviceQueue = xQueueCreate(10, sizeof(cJSON *));

    theEventGroup = xEventGroupCreate();

    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) 
    {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    connectWifi();

    initializeSNTP();

    deviceIdentifier = acquireIdentifier();
    ESP_LOGI(TAG, "Device identifier: %s", deviceIdentifier);

    EventBits_t timeBits = xEventGroupWaitBits(theEventGroup, TIME_SYNC_SUCCESS, pdFALSE, pdFALSE, portMAX_DELAY);
    if (!(timeBits & TIME_SYNC_SUCCESS)) 
    {
        ESP_LOGE(TAG, "Failed to sync RTC with NTP server");
    }

    esp_mqtt_client_handle_t client = mqttAppStart();

    
    EventBits_t wifiBits = xEventGroupWaitBits(theEventGroup, MQTT_SUCCESS, pdFALSE, pdFALSE, portMAX_DELAY);
    if (wifiBits & MQTT_SUCCESS)
    {
        ESP_LOGI(TAG, "Connected to mqtt broker");
        xTaskCreate(mqttStatus, "mqttStatus", 4096, &client, tskIDLE_PRIORITY + 1, &mqttKeepAliveTaskHandle);
    }
    else
    {
        ESP_LOGE(TAG, "Failed to connect to mqtt broker");
    }

    deviceType = identifyDevice();
    switch (deviceType) 
    {
        case 1:
            ESP_LOGI(TAG, "Detected device-type: %d", deviceType);
            xTaskCreate(smartSwitch, "smartSwitch", 4096, &client, tskIDLE_PRIORITY + 2, &deviceTaskHandle);
            break;
        case 2:
            ESP_LOGI(TAG, "Detected device-type: %d", deviceType); 
            ESP_LOGW(TAG, "This device-type is not implemented yet...");
            break;
        case 3:
            ESP_LOGI(TAG, "Detected device-type: %d", deviceType); 
            ESP_LOGW(TAG, "This device-type is not implemented yet...");
            break;
        case 4:
            ESP_LOGI(TAG, "Detected device-type: %d", deviceType); 
            ESP_LOGW(TAG, "This device-type is not implemented yet...");
            break;
        case 5:
            ESP_LOGI(TAG, "Detected device-type: %d", deviceType); 
            ESP_LOGW(TAG, "This device-type is not implemented yet...");
            break;
        case 6:
            ESP_LOGI(TAG, "Detected device-type: %d", deviceType); 
            ESP_LOGW(TAG, "This device-type is not implemented yet...");
            break;
        default:
            ESP_LOGE(TAG, "Unknown device type.");
            break;
    }

    while (1) 
    {
        vTaskDelay(pdMS_TO_TICKS(3000));
    }
    vEventGroupDelete(theEventGroup);
    ESP_ERROR_CHECK(esp_event_handler_instance_unregister(IP_EVENT, IP_EVENT_STA_GOT_IP, gotIpEventInstance));
    ESP_ERROR_CHECK(esp_event_handler_instance_unregister(WIFI_EVENT, ESP_EVENT_ANY_ID, wifiHandlerEventInstance));
}