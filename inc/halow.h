#pragma once

#include <stdint.h>
#include <stdbool.h>

struct hgic_rx_info;

typedef void (*halow_rx_cb)(
    struct hgic_rx_info *info,
    const uint8_t       *data,
    int32_t              len
);

bool halow_init(uint32_t rxbuf, uint32_t rxbuf_size,
                uint32_t tdma_buf, uint32_t tdma_buf_size);

void halow_set_rx_cb(halow_rx_cb cb);
bool halow_tx(const uint8_t *data, int32_t len);
