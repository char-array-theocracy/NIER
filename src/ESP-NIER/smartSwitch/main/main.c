#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "nvs_flash.h"

#define WIFI_SUCCESS BIT0
#define MAX_FAILURES 10

static wifi_config_t wifiConfig = {
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

void connectWifi()
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

    while (1) 
    {
        vTaskDelay(pdMS_TO_TICKS(10000));
        ESP_LOGI(TAG, "KEEP-ALIVE");
    }
    vEventGroupDelete(wifiEventGroup);
    ESP_ERROR_CHECK(esp_event_handler_instance_unregister(IP_EVENT, IP_EVENT_STA_GOT_IP, gotIpEventInstance));
    ESP_ERROR_CHECK(esp_event_handler_instance_unregister(WIFI_EVENT, ESP_EVENT_ANY_ID, wifiHandlerEventInstance));

}
