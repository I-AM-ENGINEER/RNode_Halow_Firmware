// Auto-reconstructed: mars_tdma.c
#include "sys_config.h"
#define LOG_LOCAL_LEVEL LOG_LEVEL_MARS_TDMA
#include "lib/logc/log.h"

#include "lib/lmac/mars_tdma.h"
#include "lib/lmac/lmac_regmap.h"

int ah_tdma_set_mode(int mode, int enable) {
    log_debug("ah_tdma_set_mode called with mode=%d, enable=%d\n", mode, enable);

    if ((unsigned)mode > 1 || (unsigned)enable > 1) {
        return -1;
    }

    if (mode) {
        LMAC_TDMA->CTRL |= LMAC_TDMA_MODE;
    } else {
        LMAC_TDMA->CTRL &= ~LMAC_TDMA_MODE;
    }

    if (enable) {
        LMAC_TDMA->CTRL |= LMAC_TDMA_MODE_EN;
    } else {
        LMAC_TDMA->CTRL &= ~LMAC_TDMA_MODE_EN;
    }

    return 0;
}

int ah_tdma_enable_irq(void) {
    log_debug("ah_tdma_enable_irq called\n");
    LMAC_TDMA->CTRL |= LMAC_TDMA_IRQ_EN;
    return 0;
}

int ah_tdma_set_buff(void *buffer, uint32_t length) {
    log_debug("ah_tdma_set_buff called with buffer=%p, length=%u\n", buffer, length);
    if (length > LMAC_TDMA_MAX_LEN) {
        return -1;
    }

    LMAC_TDMA->STADDR = (uint32_t)buffer;
    LMAC_TDMA->LEN    = length;
    return 0;
}

int ah_tdma_set_trig_len(uint32_t len) {
    log_debug("ah_tdma_set_trig_len called with len=%u\n", len);
    if (len > LMAC_TDMA_MAX_LEN) {
        return -1;
    }

    LMAC_TDMA->TRLEN = len;
    return 0;
}

int ah_tdma_start(void) {
    log_debug("ah_tdma_start called\n");
    LMAC_TDMA->CTRL |= LMAC_TDMA_START;
    return 0;
}

int ah_tdma_abort(void) {
    log_debug("ah_tdma_abort called\n");
    LMAC_TDMA->CTRL |= LMAC_TDMA_ABORT;
    return 0;
}

uint32_t ah_tdma_get_pd(void) {
    log_debug("ah_tdma_get_pd called\n");
    return LMAC_TDMA->STATUS & LMAC_TDMA_PD_BIT;
}

int ah_tdma_clear_pd(void) {
    log_debug("ah_tdma_clear_pd called\n");
    LMAC_TDMA->STATUS |= LMAC_TDMA_PD_BIT;
    return 0;
}

int ah_tdma2_set_mode(int mode, int enable) {
    log_debug("ah_tdma2_set_mode called with mode=%d, enable=%d\n", mode, enable);

    if ((unsigned)mode > 1 || (unsigned)enable > 1) {
        return -1;
    }

    if (mode) {
        LMAC_TDMA2->CTRL |= LMAC_TDMA_MODE;
    } else {
        LMAC_TDMA2->CTRL &= ~LMAC_TDMA_MODE;
    }

    if (enable) {
        LMAC_TDMA2->CTRL |= LMAC_TDMA_MODE_EN;
    } else {
        LMAC_TDMA2->CTRL &= ~LMAC_TDMA_MODE_EN;
    }

    return 0;
}

int ah_tdma2_enable_irq(void) {
    log_debug("ah_tdma2_enable_irq called\n");
    LMAC_TDMA2->CTRL |= LMAC_TDMA_IRQ_EN;
    return 0;
}

int ah_tdma2_set_buff(void *buffer, uint32_t length) {
    log_debug("ah_tdma2_set_buff called with buffer=%p, length=%u\n", buffer, length);
    if (length > LMAC_TDMA_MAX_LEN) {
        return -1;
    }

    LMAC_TDMA2->STADDR = (uint32_t)buffer;
    LMAC_TDMA2->LEN    = length;
    return 0;
}

int ah_tdma2_set_trig_len(uint32_t len) {
    log_debug("ah_tdma2_set_trig_len called with len=%u\n", len);
    if (len > LMAC_TDMA_MAX_LEN) {
        return -1;
    }

    LMAC_TDMA2->TRLEN = len;
    return 0;
}

int ah_tdma2_start(void) {
    log_debug("ah_tdma2_start called\n");
    LMAC_TDMA2->CTRL |= LMAC_TDMA_START;
    return 0;
}

int ah_tdma2_abort(void) {
    log_debug("ah_tdma2_abort called\n");
    LMAC_TDMA2->CTRL |= LMAC_TDMA_ABORT;
    return 0;
}

uint32_t ah_tdma2_get_pd(void) {
    log_debug("ah_tdma2_get_pd called\n");
    return LMAC_TDMA2->STATUS & LMAC_TDMA_PD_BIT;
}

int ah_tdma2_clear_pd(void) {
    log_debug("ah_tdma2_clear_pd called\n");
    LMAC_TDMA2->STATUS |= LMAC_TDMA_PD_BIT;
    return 0;
}
