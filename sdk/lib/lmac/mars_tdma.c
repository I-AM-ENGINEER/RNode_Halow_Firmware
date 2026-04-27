// Auto-reconstructed: mars_tdma.c
#include "lib/lmac/mars_tdma.h"

#define TDMA_BASE  ((volatile uint32_t *)((1UL << 30) | 0x1000UL))
#define TDMA2_BASE ((volatile uint32_t *)((1UL << 30) | 0xB000UL))
#define TDMA_MAX_LEN ((1U << 20) - 1U)

int ah_tdma_set_mode(int mode, int enable) {
    volatile uint32_t *reg = TDMA_BASE;

    if (mode == 0) {
        uint32_t val = reg[0];
        val &= ~(1U << 2);
        reg[0] = val;
        if (enable == 0) {
            val = reg[0];
            val &= ~(1U << 4);
            reg[0] = val;
            return 0;
        } else if (enable == 1) {
            val = reg[0];
            val |= (1U << 4);
            reg[0] = val;
            return 0;
        } else {
            return -1;
        }
    } else if (mode == 1) {
        uint32_t val = reg[0];
        val |= (1U << 2);
        reg[0] = val;
        if (enable == 0) {
            val = reg[0];
            val &= ~(1U << 4);
            reg[0] = val;
            return 0;
        } else if (enable == 1) {
            val = reg[0];
            val |= (1U << 4);
            reg[0] = val;
            return 0;
        } else {
            return -1;
        }
    } else {
        return -1;
    }
}

int ah_tdma_enable_irq(void) {
    volatile uint32_t *reg = TDMA_BASE;
    uint32_t val = reg[0];
    val |= (1U << 3);
    reg[0] = val;
    return 0;
}

int ah_tdma_set_buff(void *buffer, uint32_t length) {
    if (length > TDMA_MAX_LEN) {
        return -1;
    }

    volatile uint32_t *reg = TDMA_BASE;
    reg[2] = (uint32_t)buffer;
    reg[3] = length;
    return 0;
}

int ah_tdma_set_trig_len(uint32_t len) {
    if (len > TDMA_MAX_LEN) {
        return -1;
    }

    volatile uint32_t *reg = TDMA_BASE;
    reg[5] = len;
    return 0;
}

int ah_tdma_start(void) {
    volatile uint32_t *reg = TDMA_BASE;
    uint32_t val = reg[0];
    val |= 1U;
    reg[0] = val;
    return 0;
}

int ah_tdma_abort(void) {
    volatile uint32_t *reg = TDMA_BASE;
    uint32_t val = reg[0];
    val |= (1U << 1);
    reg[0] = val;
    return 0;
}

uint32_t ah_tdma_get_pd(void) {
    volatile uint32_t *reg = TDMA_BASE;
    return reg[1] & 1U;
}

int ah_tdma_clear_pd(void) {
    volatile uint32_t *reg = TDMA_BASE;
    uint32_t val = reg[1];
    val |= 1U;
    reg[1] = val;
    return 0;
}

int ah_tdma2_set_mode(int mode, int enable) {
    volatile uint32_t *reg = TDMA2_BASE;

    if (mode == 0) {
        uint32_t val = reg[0];
        val &= ~(1U << 2);
        reg[0] = val;
        if (enable == 0) {
            val = reg[0];
            val &= ~(1U << 4);
            reg[0] = val;
            return 0;
        } else if (enable == 1) {
            val = reg[0];
            val |= (1U << 4);
            reg[0] = val;
            return 0;
        } else {
            return -1;
        }
    } else if (mode == 1) {
        uint32_t val = reg[0];
        val |= (1U << 2);
        reg[0] = val;
        if (enable == 0) {
            val = reg[0];
            val &= ~(1U << 4);
            reg[0] = val;
            return 0;
        } else if (enable == 1) {
            val = reg[0];
            val |= (1U << 4);
            reg[0] = val;
            return 0;
        } else {
            return -1;
        }
    } else {
        return -1;
    }
}

int ah_tdma2_enable_irq(void) {
    volatile uint32_t *reg = TDMA2_BASE;
    uint32_t val = reg[0];
    val |= (1U << 3);
    reg[0] = val;
    return 0;
}

int ah_tdma2_set_buff(void *buffer, uint32_t length) {
    if (length > TDMA_MAX_LEN) {
        return -1;
    }

    volatile uint32_t *reg = TDMA2_BASE;
    reg[2] = (uint32_t)buffer;
    reg[3] = length;
    return 0;
}

int ah_tdma2_set_trig_len(uint32_t len) {
    if (len > TDMA_MAX_LEN) {
        return -1;
    }

    volatile uint32_t *reg = TDMA2_BASE;
    reg[5] = len;
    return 0;
}

int ah_tdma2_start(void) {
    volatile uint32_t *reg = TDMA2_BASE;
    uint32_t val = reg[0];
    val |= 1U;
    reg[0] = val;
    return 0;
}

int ah_tdma2_abort(void) {
    volatile uint32_t *reg = TDMA2_BASE;
    uint32_t val = reg[0];
    val |= (1U << 1);
    reg[0] = val;
    return 0;
}

uint32_t ah_tdma2_get_pd(void) {
    volatile uint32_t *reg = TDMA2_BASE;
    return reg[1] & 1U;
}

int ah_tdma2_clear_pd(void) {
    volatile uint32_t *reg = TDMA2_BASE;
    uint32_t val = reg[1];
    val |= 1U;
    reg[1] = val;
    return 0;
}
