#pragma once

#include <stdint.h>
#include <stdbool.h>

struct kiss_task_cfg {
    uint16_t tcp_port;      /* 0 -> default 8001 */
    uint8_t  kiss_port;     /* 0..15, default 0 */

    int32_t (*radio_tx)(const uint8_t *data, uint32_t len);

    void (*on_connect)(void);
    void (*on_disconnect)(void);
};

void kiss_task_init (const struct kiss_task_cfg *cfg);
int32_t kiss_radio_rx (const uint8_t *data, uint32_t len);
