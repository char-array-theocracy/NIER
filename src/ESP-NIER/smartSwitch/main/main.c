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
#include "driver/adc.h"
#include "esp_adc_cal.h"
#include "cJSON.h"
#include "esp_timer.h"

/* Definitions */
#define ADC_CHANNEL ADC1_CHANNEL_0
#define V_REF 3300                
#define ADC_ATTEN ADC_ATTEN_DB_12
#define BROKER_URI "mqtts://192.168.1.155"
#define WIFI_SUCCESS BIT0
#define MQTT_SUCCESS BIT0
#define MAX_FAILURES 10
#define KEEP_ALIVE_INTERVAL_IN_SECONDS 10

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

static const char base62Chars[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/* WiFi stuff */
static int wifiSuccessfulConnections = 0;
static esp_event_handler_instance_t wifiHandlerEventInstance;    
static esp_event_handler_instance_t gotIpEventInstance;
static EventGroupHandle_t wifiEventGroup;
static EventGroupHandle_t mqttEventGroup;
static int retryNum = 0;

/* Task Handles */
static TaskHandle_t deviceTaskHandle = NULL;
static TaskHandle_t mqttKeepAliveTaskHandle = NULL;

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
            xEventGroupClearBits(wifiEventGroup, WIFI_SUCCESS);
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
        xEventGroupSetBits(wifiEventGroup, WIFI_SUCCESS);
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
    EventBits_t bits = xEventGroupWaitBits(wifiEventGroup, WIFI_SUCCESS, pdFALSE, pdFALSE, portMAX_DELAY);
    if (bits & WIFI_SUCCESS)
    {
        ESP_LOGI(TAG, "Connected to Wi-Fi");
    }
    else
    {
        ESP_LOGE(TAG, "Failed to connect to Wi-Fi");
    }
}
void mqttKeepAlive(void *pvParamaters) 
{
    esp_mqtt_client_handle_t client = *(esp_mqtt_client_handle_t *)pvParamaters;        
    char *destination = calloc(strlen(deviceIdentifier) + 20, sizeof(char));
    snprintf(destination, strlen(deviceIdentifier) + 20, "device/%s/status", deviceIdentifier);
    while(1) 
    {
        cJSON *message = cJSON_CreateObject();
        if (message == NULL) 
        {
            ESP_LOGE(TAG, "Failed to create a JSON object");
        }
        cJSON_AddNumberToObject(message, "uptime", esp_timer_get_time() / 1000000);
        wifi_ap_record_t ap;
        esp_wifi_sta_get_ap_info(&ap);
        cJSON_AddNumberToObject(message, "rssi", ap.rssi);
        cJSON_AddNumberToObject(message, "heapTotal", heap_caps_get_total_size(MALLOC_CAP_DEFAULT));
        cJSON_AddNumberToObject(message, "heapUsed", esp_get_free_heap_size());
        cJSON_AddNumberToObject(message, "deviceType", deviceType);
        char *json_string = cJSON_PrintUnformatted(message);
        if (json_string == NULL) 
        {
            ESP_LOGE(TAG, "Failed to print JSON");
        }

        int msg_id = esp_mqtt_client_publish(client, destination, json_string, 0, 1, 1);
        if (msg_id != -1) 
        {
            ESP_LOGI(TAG, "Sent keep-alive, msg_id=%d", msg_id);
        } else {
            ESP_LOGE(TAG, "Failed to send keep-alive");
        }
        cJSON_Delete(message);
        vTaskDelay(pdMS_TO_TICKS(KEEP_ALIVE_INTERVAL_IN_SECONDS * 1000));
    }
    free(destination);
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
            messageId = esp_mqtt_client_subscribe(client, "/topic/qos0", 0);
            ESP_LOGI(TAG, "Sent subscribe successful, messageId=%d", messageId);

            messageId = esp_mqtt_client_subscribe(client, "/topic/qos1", 1);
            ESP_LOGI(TAG, "Sent subscribe successful, messageId=%d", messageId);

            messageId = esp_mqtt_client_unsubscribe(client, "/topic/qos1");
            ESP_LOGI(TAG, "Sent unsubscribe successful, messageId=%d", messageId);
            xEventGroupSetBits(mqttEventGroup, MQTT_SUCCESS);
            break;
        case MQTT_EVENT_DISCONNECTED:
            ESP_LOGI(TAG, "MQTT_EVENT_DISCONNECTED");
            break;

        case MQTT_EVENT_SUBSCRIBED:
            ESP_LOGI(TAG, "MQTT_EVENT_SUBSCRIBED, messageId=%d", event->msg_id);
            messageId = esp_mqtt_client_publish(client, "/topic/qos0", "data", 0, 0, 0);
            ESP_LOGI(TAG, "Sent publish successful, messageId=%d", messageId);
            break;
        case MQTT_EVENT_UNSUBSCRIBED:
            ESP_LOGI(TAG, "MQTT_EVENT_UNSUBSCRIBED, messageId=%d", event->msg_id);
            break;
        case MQTT_EVENT_PUBLISHED:
            ESP_LOGI(TAG, "MQTT_EVENT_PUBLISHED, messageId=%d", event->msg_id);
            break;
        case MQTT_EVENT_DATA:
            ESP_LOGI(TAG, "MQTT_EVENT_DATA");
            printf("TOPIC=%.*s\r\n", event->topic_len, event->topic);
            printf("DATA=%.*s\r\n", event->data_len, event->data);
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

esp_mqtt_client_handle_t mqttAppStart(void)
{
    const esp_mqtt_client_config_t mqttCfg = {
        .broker.address.uri = BROKER_URI,
        .broker.verification.psk_hint_key = &psk_hint_key,
    };

    esp_mqtt_client_handle_t client = esp_mqtt_client_init(&mqttCfg);
    esp_mqtt_client_register_event(client, ESP_EVENT_ANY_ID, mqttEventHandler, NULL);
    esp_mqtt_client_start(client);
    return client;
}

int identifyDevice(void) 
{
    esp_adc_cal_characteristics_t adcChars;
    adc1_config_width(ADC_WIDTH_BIT_12);
    adc1_config_channel_atten(ADC_CHANNEL, ADC_ATTEN);
    int raw;
    esp_adc_cal_characterize(ADC_UNIT_1, ADC_ATTEN, ADC_WIDTH_BIT_12, V_REF, &adcChars);
    raw = adc1_get_raw(ADC_CHANNEL);
    float voltage = (float)esp_adc_cal_raw_to_voltage(raw, &adcChars)/ 1000.0;

    if (voltage >= 3.05 && voltage <= 3.20) 
    {
        return 1;
    } 
    else if (voltage > 2.90 && voltage <= 3.05) 
    {
        return 2;
    } 
    else if (voltage > 2.75 && voltage <= 2.90) 
    {
        return 3;
    } 
    else if (voltage > 2.40 && voltage <= 2.60) 
    {
        return 4;
    } 
    else if (voltage > 2.00 && voltage <= 2.20) 
    {
        return 5;
    } 
    else if (voltage > 1.70 && voltage <= 1.90) 
    {
        return 6;
    } 
    else if (voltage > 1.50 && voltage <= 1.70) 
    {
        return 7;
    } 
    else if (voltage > 1.30 && voltage <= 1.50) 
    {
        return 8;
    } 
    else if (voltage > 1.10 && voltage <= 1.30) 
    {
        return 9;
    } 
    else if (voltage > 0.90 && voltage <= 1.10) 
    {
        return 10;
    } 
    else 
    {
        ESP_LOGE(TAG, "No valid device detected, either resistor is missing or something is broken.\n");
        return 0;
    }
}

void app_main(void)
{
    esp_log_level_set("wifi", ESP_LOG_DEBUG);

    wifiEventGroup = xEventGroupCreate();
    mqttEventGroup = xEventGroupCreate();

    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) 
    {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    connectWifi();

    esp_mqtt_client_handle_t client = mqttAppStart();
    deviceIdentifier = acquireIdentifier();
    ESP_LOGI(TAG, "Device identifier: %s", deviceIdentifier);

    deviceType = identifyDevice();
    switch (deviceType) 
    {
        case 1:
            ESP_LOGI(TAG, "Detected device-type: %d", deviceType);
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
        case 7:
            ESP_LOGI(TAG, "Detected device-type: %d", deviceType); 
            ESP_LOGW(TAG, "This device-type is not implemented yet...");
            break;
        case 8:
            ESP_LOGI(TAG, "Detected device-type: %d", deviceType); 
            ESP_LOGW(TAG, "This device-type is not implemented yet...");
            break;
        case 9:
            ESP_LOGI(TAG, "Detected device-type: %d", deviceType); 
            ESP_LOGW(TAG, "This device-type is not implemented yet...");
            break;
        case 10:
            ESP_LOGI(TAG, "Detected device-type: %d", deviceType); 
            ESP_LOGW(TAG, "This device-type is not implemented yet...");
            break;
        default:
            ESP_LOGE(TAG, "Unknown device type.");
            break;
    }
    EventBits_t bits = xEventGroupWaitBits(mqttEventGroup, MQTT_SUCCESS, pdFALSE, pdFALSE, portMAX_DELAY);
    if (bits & MQTT_SUCCESS)
    {
        ESP_LOGI(TAG, "Connected to mqtt broker");
        xTaskCreate(mqttKeepAlive, "mqttKeepAlive", 4096, &client, tskIDLE_PRIORITY + 1, &mqttKeepAliveTaskHandle);
    }
    else
    {
        ESP_LOGE(TAG, "Failed to connect to mqtt broker");
    }
    while (1) 
    {
        ESP_LOGI(TAG, "KEE{P}");
        vTaskDelay(pdMS_TO_TICKS(1000));
    }

    vEventGroupDelete(wifiEventGroup);
    ESP_ERROR_CHECK(esp_event_handler_instance_unregister(IP_EVENT, IP_EVENT_STA_GOT_IP, gotIpEventInstance));
    ESP_ERROR_CHECK(esp_event_handler_instance_unregister(WIFI_EVENT, ESP_EVENT_ANY_ID, wifiHandlerEventInstance));
    free(deviceIdentifier);
}
