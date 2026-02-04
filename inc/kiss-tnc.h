#pragma once

#include <stdint.h>
#include <stdbool.h>

#define KISS_CMD_BUF_MAX 512

#define KISS_FEND   0xC0
#define KISS_FESC   0xDB
#define KISS_TFEND  0xDC
#define KISS_TFESC  0xDD

#define KISS_MASK_PORT 0xF0
#define KISS_MASK_CMD  0x0F

enum kiss_cmd {
    KISS_CMD_DATA        = 0x0,
    KISS_CMD_TXDELAY     = 0x1,
    KISS_CMD_PERSIST     = 0x2,
    KISS_CMD_SLOTTIME    = 0x3,
    KISS_CMD_TXTAIL      = 0x4,
    KISS_CMD_FULLDUPLEX  = 0x5,
    KISS_CMD_VENDOR      = 0x6,
    KISS_CMD_RETURN      = 0xF,
};

struct kiss_ctx {
    uint8_t  port;
    uint8_t  esc;
    uint32_t len;
    uint8_t  buf[KISS_CMD_BUF_MAX];
};

typedef void (*kiss_rx_cb_t)(
    void *user,
    uint8_t port,
    uint8_t cmd,
    const uint8_t *data,
    uint32_t len
);

void kiss_tnc_init(struct kiss_ctx *k, uint8_t port);
void kiss_tnc_reset(struct kiss_ctx *k);

void kiss_tnc_input_byte(
    struct kiss_ctx *k,
    uint8_t b,
    kiss_rx_cb_t cb,
    void *user
);

uint32_t kiss_tnc_encode(
    uint8_t port,
    uint8_t cmd,
    const uint8_t *data,
    uint32_t data_len,
    uint8_t *out,
    uint32_t out_size
);
