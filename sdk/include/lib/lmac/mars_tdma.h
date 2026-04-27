// Auto-reconstructed: mars_tdma.h
#pragma once

#include <stdint.h>

int ah_tdma2_abort(void);
int ah_tdma2_clear_pd(void);
int ah_tdma2_enable_irq(void);
uint32_t ah_tdma2_get_pd(void);
int ah_tdma2_set_buff(void *buffer, uint32_t length);
int ah_tdma2_set_mode(int mode, int enable);
int ah_tdma2_set_trig_len(uint32_t len);
int ah_tdma2_start(void);

int ah_tdma_abort(void);
int ah_tdma_clear_pd(void);
int ah_tdma_enable_irq(void);
uint32_t ah_tdma_get_pd(void);
int ah_tdma_set_buff(void *buffer, uint32_t length);
int ah_tdma_set_mode(int mode, int enable);
int ah_tdma_set_trig_len(uint32_t len);
int ah_tdma_start(void);
