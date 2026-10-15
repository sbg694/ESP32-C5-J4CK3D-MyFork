#ifndef WIFI_SNIFFER_H
#define WIFI_SNIFFER_H

#include <stdbool.h>
#include <stdint.h>
#include "esp_wifi_types.h"

/**
 * @brief Start WiFi packet sniffer
 * 
 * @param channel Channel to sniff on (0 for channel hopping)
 * @param filter_type Type of packets to capture:
 *                   0: All packets
 *                   1: Management frames only
 *                   2: Data frames only
 *                   3: Control frames only
 *                   4: Beacon frames only
 *                   5: Probe request/response only
 * @return true if sniffer started successfully
 */
bool start_wifi_sniffer(uint8_t channel, uint8_t filter_type);

/**
 * @brief Stop WiFi packet sniffer
 * 
 * @return true if sniffer stopped successfully
 */
bool stop_wifi_sniffer(void);

/**
 * @brief Get captured packets
 * 
 * @param packets Array of pointers to store packet data (must be freed by caller)
 * @param max_packets Maximum number of packets to retrieve
 * @return Number of packets retrieved
 */
int get_captured_packets(void **packets, int max_packets);

/* 全局变量：当前嗅探信道，0 表示跳频，1~13 表示固定信道 */
extern uint8_t g_sniffer_channel;

/**
 * @brief 设置嗅探器信道
 * @param channel 0 表示跳频，1~13 表示固定信道
 */
void set_sniffer_channel(uint8_t channel);

#endif /* WIFI_SNIFFER_H */ 