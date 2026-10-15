#include "wifi_sniffer.h"
#include "esp_wifi.h"
#include "esp_log.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include <string.h>
#include <stdlib.h>

static const char *TAG = "wifi_sniffer";

// 全局嗅探信道：0 = 全信道跳频，非0 = 锁定该信道
uint8_t g_sniffer_channel = 0;
bool g_channel_updated = false;

// 供 Web 服务器调用，动态设置信道
void set_sniffer_channel(uint8_t channel) {
    g_sniffer_channel = channel;
    g_channel_updated = true;
    ESP_LOGI(TAG, "Sniffer channel updated to: %d", channel);
}

// Maximum number of packets to store
#define MAX_PACKETS_QUEUE 32
#define MAX_PACKET_SIZE 1024

// Structure to hold packet info
typedef struct {
    uint8_t data[MAX_PACKET_SIZE];
    uint16_t length;
    int8_t rssi;
    uint8_t channel;
    wifi_pkt_rx_ctrl_t rx_ctrl;
} packet_info_t;

// Global variables
static QueueHandle_t packet_queue = NULL;
static SemaphoreHandle_t sniffer_running_mutex = NULL;
static bool is_sniffer_running = false;
static uint8_t current_channel = 0;
static uint8_t current_filter = 0;
static TaskHandle_t channel_hopper_task_handle = NULL;

// Channel hopping settings
#define CHANNEL_HOP_INTERVAL_MS 200
static const uint8_t channels[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13};
static const uint8_t channels_count = sizeof(channels)/sizeof(channels[0]);

// Forward declaration
static void wifi_sniffer_packet_handler(void *buf, wifi_promiscuous_pkt_type_t type);
static void channel_hopper_task(void *pvParameters);

// Start WiFi sniffer
bool start_wifi_sniffer(uint8_t channel, uint8_t filter_type) {
    ESP_LOGI(TAG, "Starting WiFi sniffer on channel %d with filter type %d", channel, filter_type);
    
    // Create mutex if not already created
    if (sniffer_running_mutex == NULL) {
        sniffer_running_mutex = xSemaphoreCreateMutex();
        if (sniffer_running_mutex == NULL) {
            ESP_LOGI(TAG, "Failed to create sniffer mutex");
            return false;
        }
    }
    
    // Take mutex
    if (xSemaphoreTake(sniffer_running_mutex, portMAX_DELAY) != pdTRUE) {
        ESP_LOGI(TAG, "Failed to take sniffer mutex");
        return false;
    }
    
    // If sniffer is already running, stop it first
    if (is_sniffer_running) {
        ESP_LOGW(TAG, "Sniffer already running, stopping first");
        stop_wifi_sniffer();
    }
    
    // Create packet queue if not already created
    if (packet_queue == NULL) {
        packet_queue = xQueueCreate(MAX_PACKETS_QUEUE, sizeof(packet_info_t*));
        if (packet_queue == NULL) {
            ESP_LOGI(TAG, "Failed to create packet queue");
            xSemaphoreGive(sniffer_running_mutex);
            return false;
        }
    } else {
        // Queue exists, make sure it's empty
        packet_info_t *packet;
        while (xQueueReceive(packet_queue, &packet, 0) == pdTRUE) {
            if (packet) free(packet);
        }
    }
    
    // Save configuration
    current_channel = channel;
    current_filter = filter_type;
    set_sniffer_channel(channel);
    
    // Get current WiFi mode and save it
    wifi_mode_t original_mode;
    ESP_ERROR_CHECK(esp_wifi_get_mode(&original_mode));
    
    // Set to APSTA mode to ensure we keep the AP running while scanning
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA));
    
    // Set sniffer filter based on packet type
    wifi_promiscuous_filter_t filter = {0};
    switch (filter_type) {
        case 1: // Management frames
            filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT;
            break;
        case 2: // Data frames
            filter.filter_mask = WIFI_PROMIS_FILTER_MASK_DATA;
            break;
        case 3: // Control frames
            filter.filter_mask = WIFI_PROMIS_FILTER_MASK_CTRL;
            break;
        case 4: // Beacon frames only
            filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT;
            // We'll filter in the callback for beacon frames only
            break;
        case 5: // Probe frames only
            filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT;
            // We'll filter in the callback for probe frames only
            break;
        default: // All packets
            filter.filter_mask = WIFI_PROMIS_FILTER_MASK_ALL;
    }
    
    esp_wifi_set_promiscuous_filter(&filter);
    
    // Register packet handler
    esp_wifi_set_promiscuous_rx_cb(wifi_sniffer_packet_handler);
    
    // Enable promiscuous mode
    esp_wifi_set_promiscuous(true);
    
    // 统一创建信道管理任务
    // 不管 channel 是 0 还是具体信道，都交给 channel_hopper_task 处理
    if (channel_hopper_task_handle == NULL) {
        BaseType_t ret = xTaskCreate(
            channel_hopper_task,
            "channel_hopper",
            2048,
            NULL,
            5,
            &channel_hopper_task_handle
        );

        if (ret != pdPASS) {
            ESP_LOGE(TAG, "Failed to create channel hopper task");
            is_sniffer_running = false;
            xSemaphoreGive(sniffer_running_mutex);
            return false;
        }
    }

    is_sniffer_running = true;
    xSemaphoreGive(sniffer_running_mutex);

    ESP_LOGI(TAG, "WiFi sniffer started successfully");
    return true;
}

// Stop WiFi sniffer
bool stop_wifi_sniffer(void) {
    ESP_LOGI(TAG, "Stopping WiFi sniffer");
    
    // Take mutex
    if (sniffer_running_mutex == NULL || xSemaphoreTake(sniffer_running_mutex, portMAX_DELAY) != pdTRUE) {
        ESP_LOGI(TAG, "Failed to take sniffer mutex");
        return false;
    }
    
    // Check if sniffer is running
    if (!is_sniffer_running) {
        ESP_LOGW(TAG, "Sniffer not running");
        xSemaphoreGive(sniffer_running_mutex);
        return false;
    }
    
    // Disable promiscuous mode
    esp_wifi_set_promiscuous(false);
    
    // Stop channel hopping task if running
    if (channel_hopper_task_handle != NULL) {
        vTaskDelete(channel_hopper_task_handle);
        channel_hopper_task_handle = NULL;
    }
    
    is_sniffer_running = false;
    xSemaphoreGive(sniffer_running_mutex);
    
    ESP_LOGI(TAG, "WiFi sniffer stopped successfully");
    return true;
}

// Get captured packets
int get_captured_packets(void **packets, int max_packets) {
    // Take mutex
    if (sniffer_running_mutex == NULL || xSemaphoreTake(sniffer_running_mutex, portMAX_DELAY) != pdTRUE) {
        ESP_LOGI(TAG, "Failed to take sniffer mutex");
        return 0;
    }
    
    // Check if sniffer is running
    if (!is_sniffer_running) {
        xSemaphoreGive(sniffer_running_mutex);
        return 0;
    }
    
    // Get packets from queue (up to max_packets)
    int count = 0;
    packet_info_t *packet;
    
    while (count < max_packets && xQueueReceive(packet_queue, &packet, 0) == pdTRUE) {
        packets[count++] = packet;
    }
    
    xSemaphoreGive(sniffer_running_mutex);
    return count;
}

// Channel hopper task
static void channel_hopper_task(void *pvParameters) {
    int current_idx = 0;
    ESP_LOGI(TAG, "Channel hopper task started");

    while (1) {
        if (g_sniffer_channel != 0) {
            // 锁定到指定信道
            esp_err_t err = esp_wifi_set_channel(g_sniffer_channel, WIFI_SECOND_CHAN_NONE);
            if (err == ESP_OK) {
                ESP_LOGD(TAG, "Locked to channel %d", g_sniffer_channel);
            } else {
                ESP_LOGW(TAG, "Failed to lock channel %d: %s", g_sniffer_channel, esp_err_to_name(err));
            }
            vTaskDelay(pdMS_TO_TICKS(200)); // 锁定状态下稍作等待
        } else {
            // 全信道跳频
            uint8_t new_channel = channels[current_idx];
            esp_wifi_set_channel(new_channel, WIFI_SECOND_CHAN_NONE);
            current_idx = (current_idx + 1) % channels_count;
            vTaskDelay(CHANNEL_HOP_INTERVAL_MS / portTICK_PERIOD_MS);
        }
    }
}

// Packet handler
static void wifi_sniffer_packet_handler(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (!buf) return;
    
    // Check if sniffer is running
    if (!is_sniffer_running) return;
    
    wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t*)buf;
    wifi_pkt_rx_ctrl_t *rx_ctrl = &pkt->rx_ctrl;
    
    // If we have a specific filter for beacon or probe, check it here
    if (current_filter == 4 || current_filter == 5) {
        // Get frame control field to determine if it's a beacon or probe
        const uint8_t *frame = pkt->payload;
        uint16_t frame_control = frame[0] | (frame[1] << 8);
        uint8_t type = (frame_control & 0x000C) >> 2;
        uint8_t subtype = (frame_control & 0x00F0) >> 4;
        
        if (current_filter == 4) { // Beacon frames only
            if (!(type == 0 && subtype == 8)) { // Not a beacon
                return;
            }
        } else if (current_filter == 5) { // Probe frames only
            if (!(type == 0 && (subtype == 4 || subtype == 5))) { // Not a probe request/response
                return;
            }
        }
    }
    
    // Allocate memory for packet info
    packet_info_t *packet_info = malloc(sizeof(packet_info_t));
    if (!packet_info) {
        ESP_LOGI(TAG, "Failed to allocate memory for packet info");
        return;
    }
    
    // Copy packet data
    uint16_t payload_len = rx_ctrl->sig_len - 4; // Remove FCS
    if (payload_len > MAX_PACKET_SIZE) {
        payload_len = MAX_PACKET_SIZE;
    }
    
    // Fill packet info
    packet_info->rx_ctrl = *rx_ctrl;
    packet_info->length = payload_len;
    packet_info->rssi = rx_ctrl->rssi;
    packet_info->channel = rx_ctrl->channel;
    memcpy(packet_info->data, pkt->payload, payload_len);
    
    // Add to queue, if queue is full, discard oldest packet
    packet_info_t *old_packet;
    if (xQueueSend(packet_queue, &packet_info, 0) != pdTRUE) {
        if (xQueueReceive(packet_queue, &old_packet, 0) == pdTRUE) {
            if (old_packet) free(old_packet);
            xQueueSend(packet_queue, &packet_info, 0);
        } else {
            // This shouldn't happen, but free the packet if we can't add it
            free(packet_info);
        }
    }
}