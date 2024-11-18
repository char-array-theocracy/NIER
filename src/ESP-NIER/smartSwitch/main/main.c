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

#define BROKER_URI "mqtts://192.168.1.155"
#define WIFI_SUCCESS BIT0
#define MAX_FAILURES 10

static const uint8_t s_key[] = { 0x74, 0x65, 0x73, 0x74 }; // test
static const psk_hint_key_t psk_hint_key = {
        .key = s_key,
        .key_size = sizeof(s_key),
        .hint = "NIER"
        };



static const wifi_config_t wifiConfig = {
    .sta = {
        .ssid = "Art",
        .password = "13214227",
        .threshold.authmode = WIFI_AUTH_WPA2_PSK,
        .pmf_cfg = {
            .capable = true,
            .required = false
        },
    },
};

/* WiFi stuff*/
static int wifiSuccesfulConnections = 0;
static esp_event_handler_instance_t wifiHandlerEventInstance;    
static esp_event_handler_instance_t gotIpEventInstance;
static EventGroupHandle_t wifiEventGroup;
static int sRetryNum = 0;

static const char *TAG = "NIER";

static void logErrorIfNonZero(const char *message, int error_code)
{
    if (error_code != 0) {
        ESP_LOGE(TAG, "Last error %s: 0x%x", message, error_code);
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
        if (sRetryNum < MAX_FAILURES)
        {   
            xEventGroupClearBits(wifiEventGroup, WIFI_SUCCESS);
            if (wifiSuccesfulConnections > 0) 
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
            sRetryNum++;
            vTaskDelay(pdMS_TO_TICKS(3000));
        } 
        else 
        {
            ESP_LOGE(TAG, "Failed to reconnect to AP, rebooting ..."); 
            esp_restart();
        }
    }
}

static void ipEventHandler(void* arg, esp_event_base_t eventBase,
                           int32_t eventId, void* eventData)
{
    if (eventBase == IP_EVENT && eventId == IP_EVENT_STA_GOT_IP)
    {
        ip_event_got_ip_t* event = (ip_event_got_ip_t*) eventData;
        ESP_LOGI(TAG, "STA IP: " IPSTR, IP2STR(&event->ip_info.ip));
        sRetryNum = 0;
        xEventGroupSetBits(wifiEventGroup, WIFI_SUCCESS);
        wifiSuccesfulConnections++; 
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

    ESP_LOGI(TAG, "STA initialization complete");

}

static void mqttEventHandler(void* arg, esp_event_base_t eventBase,
                             int32_t eventId, void* eventData) 
{
    ESP_LOGD(TAG, "Event dispatched from event loop base=%s, event_id=%" PRIi32, eventBase, eventId);
    esp_mqtt_event_handle_t event = eventData;
    esp_mqtt_client_handle_t client = event->client;
    int messageId;
    switch ((esp_mqtt_event_id_t)eventId) {
    case MQTT_EVENT_CONNECTED:
        ESP_LOGI(TAG, "MQTT_EVENT_CONNECTED");
        messageId = esp_mqtt_client_subscribe(client, "/topic/qos0", 0);
        ESP_LOGI(TAG, "sent subscribe successful, messageId=%d", messageId);

        messageId = esp_mqtt_client_subscribe(client, "/topic/qos1", 1);
        ESP_LOGI(TAG, "sent subscribe successful, messageId=%d", messageId);

        messageId = esp_mqtt_client_unsubscribe(client, "/topic/qos1");
        ESP_LOGI(TAG, "sent unsubscribe successful, messageId=%d", messageId);
        break;
    case MQTT_EVENT_DISCONNECTED:
        ESP_LOGI(TAG, "MQTT_EVENT_DISCONNECTED");
        break;

    case MQTT_EVENT_SUBSCRIBED:
        ESP_LOGI(TAG, "MQTT_EVENT_SUBSCRIBED, messageId=%d", event->msg_id);
        messageId = esp_mqtt_client_publish(client, "/topic/qos0", "data", 0, 0, 0);
        ESP_LOGI(TAG, "sent publish successful, messageId=%d", messageId);
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
        if (event->error_handle->error_type == MQTT_ERROR_TYPE_TCP_TRANSPORT) {
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

static void mqttAppStart(void)
{
    const esp_mqtt_client_config_t mqtt_cfg = {
        .broker.address.uri = BROKER_URI,
        .broker.verification.psk_hint_key = &psk_hint_key,
    };

    ESP_LOGI(TAG, "[APP] Free memory: %" PRIu32 " bytes", esp_get_free_heap_size());
    esp_mqtt_client_handle_t client = esp_mqtt_client_init(&mqtt_cfg);
    esp_mqtt_client_register_event(client, ESP_EVENT_ANY_ID, mqttEventHandler, NULL);
    esp_mqtt_client_start(client);
}

void app_main(void)
{
    wifiEventGroup = xEventGroupCreate();

    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) 
    {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    connectWifi();

    mqttAppStart();

    while (1) 
    {
        vTaskDelay(pdMS_TO_TICKS(10000));
        ESP_LOGI(TAG, "KEEP-ALIVE");
    }
    vEventGroupDelete(wifiEventGroup);
    ESP_ERROR_CHECK(esp_event_handler_instance_unregister(IP_EVENT, IP_EVENT_STA_GOT_IP, gotIpEventInstance));
    ESP_ERROR_CHECK(esp_event_handler_instance_unregister(WIFI_EVENT, ESP_EVENT_ANY_ID, wifiHandlerEventInstance));

}
