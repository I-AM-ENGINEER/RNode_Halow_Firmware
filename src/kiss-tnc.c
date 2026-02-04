#include "kiss-tnc.h"

static void kiss_tnc_dispatch(struct kiss_ctx *k, kiss_rx_cb_t cb, void *user) {
    if (k->len == 0) {
        return;
    }

    uint8_t instr = k->buf[0];
    uint8_t port  = (uint8_t)((instr & KISS_MASK_PORT) >> 4);
    uint8_t cmd   = (uint8_t)(instr & KISS_MASK_CMD);

    cb(
        user,
        port,
        cmd,
        &k->buf[1],
        (uint32_t)(k->len - 1)
    );
}

void kiss_tnc_init(struct kiss_ctx *k, uint8_t port) {
    k->port = port;
    k->esc  = 0;
    k->len  = 0;
}

void kiss_tnc_reset(struct kiss_ctx *k) {
    k->esc = 0;
    k->len = 0;
}

void kiss_tnc_input_byte(struct kiss_ctx *k, uint8_t b, kiss_rx_cb_t cb, void *user) {
    switch (b) {

    case KISS_FESC:
        if (k->esc) {
            kiss_tnc_reset(k);
        } else {
            k->esc = 1;
        }
        return;

    case KISS_FEND:
        if (k->len > 0) {
            kiss_tnc_dispatch(k, cb, user);
            kiss_tnc_reset(k);
        }
        return;

    case KISS_TFEND:
        if (k->esc) {
            b = KISS_FEND;
            k->esc = 0;
        }
        break;

    case KISS_TFESC:
        if (k->esc) {
            b = KISS_FESC;
            k->esc = 0;
        }
        break;

    default:
        if (k->esc) {
            kiss_tnc_reset(k);
            return;
        }
        break;
    }

    if (k->len < KISS_CMD_BUF_MAX) {
        k->buf[k->len++] = b;
    } else {
        kiss_tnc_reset(k);
    }
}

uint32_t kiss_tnc_encode(
    uint8_t port,
    uint8_t cmd,
    const uint8_t *data,
    uint32_t data_len,
    uint8_t *out,
    uint32_t out_size
){
    uint32_t pos = 0;

    if (!out || out_size < 3) {
        return 0;
    }

    out[pos++] = KISS_FEND;
    out[pos++] = (uint8_t)(((port << 4) & KISS_MASK_PORT) | (cmd & KISS_MASK_CMD));

    if (data && data_len) {
        for (uint32_t i = 0; i < data_len; i++) {
            uint8_t b = data[i];

            if ((pos + 2) >= out_size) {
                break;
            }

            if (b == KISS_FEND) {
                out[pos++] = KISS_FESC;
                out[pos++] = KISS_TFEND;
            } else if (b == KISS_FESC) {
                out[pos++] = KISS_FESC;
                out[pos++] = KISS_TFESC;
            } else {
                out[pos++] = b;
            }
        }
    }

    if (pos < out_size) {
        out[pos++] = KISS_FEND;
    }

    return pos;
}
