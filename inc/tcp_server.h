#pragma once

#include <stdint.h>
#include <stddef.h>

#include "lwip/ip4_addr.h"

typedef int32_t (*tcp_server_rx_cb_t)(const uint8_t *data, uint32_t len,
                                     uint16_t *consumed);   /* out: bytes the
                                     * decoder accepted; the tail must be re-fed */

typedef struct {
    bool enabled;
    uint16_t port;
    ip4_addr_t whitelist_ip;
    ip4_addr_t whitelist_mask;
} tcp_server_config_t;

void tcp_server_init(tcp_server_rx_cb_t cb);
int32_t tcp_server_send(const uint8_t *data, uint32_t len);
/* Zero-copy send: takes OWNERSHIP of an os_malloc'd buffer; it is queued for
 * netconn_write and freed by the tcps task (or here on queue-full). Returns
 * 0 on success -- on any failure the buffer is already freed. */
int32_t tcp_server_send_owned(uint8_t *os_buf, uint32_t len);
void tcp_server_config_load(tcp_server_config_t *cfg);
void tcp_server_config_save(const tcp_server_config_t *cfg);
void tcp_server_config_apply(const tcp_server_config_t *cfg);
bool tcp_server_get_client_info(ip4_addr_t* addr, uint16_t* port);
