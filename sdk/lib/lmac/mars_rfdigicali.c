// Auto-reconstructed: mars_rfdigicali.c
#include "typesdef.h"
#include "lib/lmac/lmac_regmap.h"

extern void os_sleep_ms(uint32 ms);
extern void os_sleep_us(uint32 us);

#define RFDIGI LMAC_RFDIGICALI
#define RFDIGI_RX_LO_WORD(index_) (((volatile uint32_t *)&RFDIGI->RX1MDC0)[(index_)])
#define RFDIGI_RX_LO_PHASE_WORD_OFFSET 6U
#define RFDIGI_RX_HI_WORD(index_) (((volatile uint32_t *)&RFDIGI->RXFBDC0)[(index_)])
#define RFDIGI_RX_HI_PHASE_WORD_OFFSET 6U
#define RFDIGI_TX_DC_WORD(index_) (((volatile uint32_t *)&RFDIGI->TXDC0)[(index_)])
#define RFDIGI_TX_IMB_WORD(index_) (((volatile uint32_t *)&RFDIGI->TXIMB0)[(index_)])

void ah_rfdigicali_bknoise_calc_dis(void) {
    LMAC_CLEAR_BIT(RFDIGI->RFPWRCON0, LMAC_RFDIGI_BKNOISE_CLR | LMAC_RFDIGI_BKNOISE_EN);
}

void ah_rfdigicali_bknoise_calc_en(void) {
    LMAC_SET_BIT(RFDIGI->RFPWRCON0, LMAC_RFDIGI_BKNOISE_EN);
}

int8_t ah_rfdigicali_bknoise_get(void) {
    uint32_t bknoise_ctrl;

    if (!LMAC_RFDIGI_BKNOISE_IS_VALID()) {
        return -1;
    }
    int8_t result = (int8_t)RFDIGI->RFPWRCON1;
    bknoise_ctrl = RFDIGI->RFPWRCON0;
    LMAC_WRITE_REG(RFDIGI->RFPWRCON0, bknoise_ctrl | LMAC_RFDIGI_BKNOISE_VALID);
    return result;
}

void ah_rfdigicali_bknoise_hw_trig_dis(void) {
    LMAC_CLEAR_BIT(RFDIGI->RFPWRCON0, LMAC_RFDIGI_BKNOISE_HW_TRIG);
}

void ah_rfdigicali_bknoise_hw_trig_en(void) {
    LMAC_SET_BIT(RFDIGI->RFPWRCON0, LMAC_RFDIGI_BKNOISE_HW_TRIG);
}

void ah_rfdigicali_bknoise_valid_pd_clr(void) {
    LMAC_SET_BIT(RFDIGI->RFPWRCON0, LMAC_RFDIGI_BKNOISE_CLR);
}

uint32_t ah_rfdigicali_bknoise_valid_pd_get(void) {
    return LMAC_RFDIGI_BKNOISE_IS_VALID() ? LMAC_RFDIGI_BKNOISE_VALID : 0U;
}

void ah_rfdigicali_cfg_fb_comp(bool enable) {
    uint32_t val;
    val = RFDIGI->RFDCOCCON4;
    val &= ~LMAC_RFDIGI_IMB_FB_COMP_GATE;
    RFDIGI->RFDCOCCON4 = val;
    val = RFDIGI->RXPWRIDX;
    if (!enable) {
        val &= ~LMAC_RFDIGI_RX_FB_COMP_EN;
        RFDIGI->RXPWRIDX = val;
        val = RFDIGI->RXFILTER;
        val &= ~LMAC_RFDIGI_RX_FILTER_MANUAL;
        RFDIGI->RXFILTER = val;
        val = RFDIGI->RXFILTER;
        val |= LMAC_RFDIGI_RX_FILTER_AUTO;
        RFDIGI->RXFILTER = val;
    } else {
        val |= LMAC_RFDIGI_RX_FB_COMP_EN;
        RFDIGI->RXPWRIDX = val;
        val = RFDIGI->RXFILTER;
        val |= LMAC_RFDIGI_RX_FILTER_MANUAL;
        RFDIGI->RXFILTER = val;
    }
}

void ah_rfdigicali_config_hw_bknoise(uint16_t arg0, uint16_t arg1) {
    uint32_t val = 0xC000;  /* 192 << 7 = 0xC000 */
    RFDIGI->RFPWRCON0 = val;
    uint32_t bknoise_ctrl = RFDIGI->RFPWRCON0;
    uint32_t window_field = ((uint32_t)arg1 << 7) & 0x780;  /* 1920 = 0x780 */
    bknoise_ctrl |= 0x1000860;  /* 0x1000000 + 0x860 = 0x1000860 */
    bknoise_ctrl |= window_field;
    uint32_t step_field = ((uint32_t)arg1 << 1) & 0x1E;
    bknoise_ctrl |= step_field;
    uint32_t period_field = ((uint32_t)arg0 << 17) & 0xFFFC0000;  /* 0x3FFE0000 & 0xFFFC0000 = 0xFFFC0000 */
    bknoise_ctrl |= period_field;
    RFDIGI->RFPWRCON0 = bknoise_ctrl;
}

void ah_rfdigicali_config_hw_rx_dcoc(uint32_t arg0, uint32_t arg1, uint32_t arg2) {
    uint32_t dcoc_ctrl = RFDIGI->RFDCOCCON0;
    dcoc_ctrl &= 0xfc001e00;
    RFDIGI->RFDCOCCON0 = dcoc_ctrl;
    dcoc_ctrl = RFDIGI->RFDCOCCON0;
    uint32_t estimate_window = (arg1 >> 3) << 17;
    dcoc_ctrl |= 0xA704;
    dcoc_ctrl |= estimate_window;
    RFDIGI->RFDCOCCON0 = dcoc_ctrl;
    uint32_t dcoc_cfg0 = RFDIGI->RFDCOCCON1;
    dcoc_cfg0 &= 0xFF000000;
    RFDIGI->RFDCOCCON1 = dcoc_cfg0;
    uint32_t sum = arg1 + arg2;
    dcoc_cfg0 = RFDIGI->RFDCOCCON1;
    uint32_t mask = 0xFFFF00;
    uint32_t val = (sum << 5) & mask;
    dcoc_cfg0 |= arg0;
    dcoc_cfg0 |= val;
    RFDIGI->RFDCOCCON1 = dcoc_cfg0;
    RFDIGI->RFDCOCCON2 = 0;
    uint32_t imb_ctrl = RFDIGI->RFDCOCCON4;
    imb_ctrl &= 0xF1FFFFFF;
    RFDIGI->RFDCOCCON4 = imb_ctrl;
}

void ah_rfdigicali_config_rx_dcoc(uint16_t *rx_dcoc_res, uint8_t gain_step) {
    uint16_t i_val = rx_dcoc_res[0];
    uint16_t q_val = rx_dcoc_res[1];
    if (gain_step < 4) {
        uint32_t offset = (uint32_t)gain_step;
        offset = offset + offset;          /* offset*2 */
        offset = offset + (uint32_t)gain_step; /* offset*3 */
        offset = offset << 2;               /* offset*12 */
        uint32_t val = RFDIGI_RX_LO_WORD(offset);
        val &= 0xFFFF0000U;
        uint32_t q_field = ((uint32_t)q_val << 10) & 0x3FC00U;
        uint32_t i_field = (uint32_t)i_val & 0x3FFU;
        val |= q_field | i_field;
        RFDIGI_RX_LO_WORD(offset) = val;
    } else {
        uint32_t offset = (uint32_t)gain_step << 2; /* offset*4 */
        uint32_t val = RFDIGI_RX_HI_WORD(offset);
        val &= 0xFFFF0000U;
        uint32_t q_field = ((uint32_t)q_val << 10) & 0x3FC00U;
        uint32_t i_field = (uint32_t)i_val & 0x3FFU;
        val |= q_field | i_field;
        RFDIGI_RX_HI_WORD(offset) = val;
    }
    LMAC_SET_BIT(RFDIGI->RXPWRIDX, LMAC_RFDIGI_BUSY);
    LMAC_RFDIGI_WAIT_RX_READY();
}

void ah_rfdigicali_config_rx_filter(uint32_t arg0) {
    uint32_t val = arg0 << 1;
    val &= 6U;
    val |= 17U;
    RFDIGI->RXFILTER = 0xFFFFFFE0U;
    RFDIGI->RXFILTER = val;
}

void ah_rfdigicali_config_rx_filter_auto(void) {
    RFDIGI->RXFILTER = (uint32_t)(-26);
    RFDIGI->RXFILTER = 25U;
}

void ah_rfdigicali_config_rx_gain(uint32_t arg0, uint32_t arg1) {
    LMAC_CLEAR_BITS_RMW(RFDIGI->RXPWRIDX, ~0x300U);
    LMAC_SET_BITS_RMW(RFDIGI->RXPWRIDX, arg1 << 8);

    LMAC_CLEAR_BITS_RMW(RFDIGI->RXPWRIDX, 0xFFFFFFF8U);
    LMAC_SET_BITS_RMW(RFDIGI->RXPWRIDX, arg0);

    LMAC_CLEAR_BITS_RMW(RFDIGI->RXPWRIDX, 0xFFFFFF1FU);
    LMAC_SET_BITS_RMW(RFDIGI->RXPWRIDX, arg0 << 5);

    LMAC_SET_BIT(RFDIGI->RXPWRIDX, LMAC_RFDIGI_BUSY);
    LMAC_RFDIGI_WAIT_RX_READY();
}

void ah_rfdigicali_config_rx_gain_idx_src(uint32_t src) {
    uint32_t set_mask = (src << 4) & LMAC_RFDIGI_RX_GAIN_IDX_SRC;
    LMAC_CLEAR_BITS_RMW(RFDIGI->RXPWRIDX, ~LMAC_RFDIGI_RX_GAIN_IDX_SRC);
    LMAC_SET_BITS_RMW(RFDIGI->RXPWRIDX, set_mask);
}

void ah_rfdigicali_config_rx_imb(uint32_t arg0, uint32_t arg1, uint32_t arg2, uint32_t arg3) {
    uint32_t r0 = arg0;
    uint32_t r1 = arg1;
    uint32_t r2 = arg2;
    uint32_t r3 = arg3;
    uint32_t r12, r13;
    if (r1 >= 1025) {
        r12 = 128U << 15;
        r12 = r12 / r1;
    } else {
        r12 = 4095U;
    }
    r0 <<= 20;
    r13 = r12 << 12;
    r1 &= 0xFFFU;
    if (r3 >= 4) {
        uint32_t slot = r2;
        uint32_t val = RFDIGI_RX_HI_WORD(slot);
        val &= 0xC00FFFFFU;
        RFDIGI_RX_HI_WORD(slot) = val;
        val = RFDIGI_RX_HI_WORD(slot);
        r0 &= 0x3FF00000U;
        val |= r0;
        RFDIGI_RX_HI_WORD(slot) = val;
        val = RFDIGI_RX_HI_WORD(slot + RFDIGI_RX_HI_PHASE_WORD_OFFSET);
        val &= 0xFF000000U;
        RFDIGI_RX_HI_WORD(slot + RFDIGI_RX_HI_PHASE_WORD_OFFSET) = val;
        val = RFDIGI_RX_HI_WORD(slot + RFDIGI_RX_HI_PHASE_WORD_OFFSET);
        uint32_t mask = 0xFFFFF000U;
        r13 &= mask;
        val |= r1;
        val |= r13;
        RFDIGI_RX_HI_WORD(slot + RFDIGI_RX_HI_PHASE_WORD_OFFSET) = val;
    } else {
        int16_t idx = (int16_t)r3;
        uint32_t slot = idx + idx + idx;
        uint32_t val = RFDIGI_RX_LO_WORD(slot);
        val &= 0xC00FFFFFU;
        RFDIGI_RX_LO_WORD(slot) = val;
        val = RFDIGI_RX_LO_WORD(slot);
        r0 &= 0x3FF00000U;
        val |= r0;
        RFDIGI_RX_LO_WORD(slot) = val;
        val = RFDIGI_RX_LO_WORD(slot + RFDIGI_RX_LO_PHASE_WORD_OFFSET);
        val &= 0xFF000000U;
        RFDIGI_RX_LO_WORD(slot + RFDIGI_RX_LO_PHASE_WORD_OFFSET) = val;
        val = RFDIGI_RX_LO_WORD(slot + RFDIGI_RX_LO_PHASE_WORD_OFFSET);
        uint32_t mask = 0xFFFFF000U;
        r13 &= mask;
        val |= r1;
        val |= r13;
        RFDIGI_RX_LO_WORD(slot + RFDIGI_RX_LO_PHASE_WORD_OFFSET) = val;
    }
    uint32_t ctrl = RFDIGI->RXPWRIDX;
    LMAC_WRITE_REG(RFDIGI->RXPWRIDX, ctrl | LMAC_RFDIGI_BUSY);
    LMAC_RFDIGI_WAIT_RX_READY();
}

void ah_rfdigicali_config_tx_digi_gain(uint16_t gain, uint8_t idx) {
    uint32_t gain_val = (uint32_t)gain;
    if (gain_val > 2047) {
        gain_val = 2047;
    }
    if (idx >= 5) {
        idx = 4;
    }

    volatile uint32 *reg = &RFDIGI->TXDIGPWR01 + (idx >> 1);
    uint32_t clear_mask, set_mask;

    if (idx & 1) {
        clear_mask = ~LMAC_RFDIGI_TX_DIGI_GAIN_HI_MASK;
        set_mask = (gain_val << LMAC_RFDIGI_TX_DIGI_GAIN_HI_SHIFT) & LMAC_RFDIGI_TX_DIGI_GAIN_HI_MASK;
    } else {
        clear_mask = ~LMAC_RFDIGI_TX_DIGI_GAIN_MASK;
        set_mask = gain_val & LMAC_RFDIGI_TX_DIGI_GAIN_MASK;
    }

    LMAC_CLEAR_BITS_RMW(*reg, clear_mask);
    LMAC_SET_BITS_RMW(*reg, set_mask);

    LMAC_SET_BIT(RFDIGI->TXPWRIDX, LMAC_RFDIGI_BUSY);
    LMAC_RFDIGI_WAIT_TX_READY();
}

void ah_rfdigicali_config_tx_gain_idx_src(uint32_t src) {
    uint32_t val = RFDIGI->TXPWRIDX;
    val &= ~LMAC_RFDIGI_TX_GAIN_IDX_SRC;
    RFDIGI->TXPWRIDX = val;
    val = RFDIGI->TXPWRIDX;
    uint32_t src_bits = (src << 15) & LMAC_RFDIGI_TX_GAIN_IDX_SRC;
    val |= src_bits;
    RFDIGI->TXPWRIDX = val;
}

void ah_rfdigicali_config_tx_imb(uint32_t arg0, uint32_t arg1, uint32_t idx) {
    uint32_t slot = idx << 2;
    uint32_t tx_imb_gain_word = RFDIGI_TX_DC_WORD(slot);
    tx_imb_gain_word &= 0xE000FFFF;
    RFDIGI_TX_DC_WORD(slot) = tx_imb_gain_word;
    uint32_t gain_field = (arg0 << 20) & 0x1FF00000;
    tx_imb_gain_word = RFDIGI_TX_DC_WORD(slot);
    tx_imb_gain_word |= gain_field;
    RFDIGI_TX_DC_WORD(slot) = tx_imb_gain_word;
    uint32_t mask = 0xFF000000;
    uint32_t tx_imb_phase_word = RFDIGI_TX_IMB_WORD(slot);
    tx_imb_phase_word &= mask;
    RFDIGI_TX_IMB_WORD(slot) = tx_imb_phase_word;
    if (arg1 >= 1025) {
        uint32_t div = (128U << 15) / arg1;
        arg1 &= 0xFFF;
        tx_imb_phase_word = RFDIGI_TX_IMB_WORD(slot);
        tx_imb_phase_word |= arg1;
        uint32_t scaled = div << 12;
        scaled &= 0xFFF00000;
        tx_imb_phase_word |= scaled;
        RFDIGI_TX_IMB_WORD(slot) = tx_imb_phase_word;
    } else {
        arg1 = 0xFFF;
        tx_imb_phase_word = RFDIGI_TX_IMB_WORD(slot);
        tx_imb_phase_word |= arg1;
        RFDIGI_TX_IMB_WORD(slot) = tx_imb_phase_word;
    }
    uint32_t ctrl_val = RFDIGI->TXPWRIDX;
    LMAC_WRITE_REG(RFDIGI->TXPWRIDX, ctrl_val | LMAC_RFDIGI_BUSY);
    LMAC_RFDIGI_WAIT_TX_READY();
}

void ah_rfdigicali_dcoc_est_en(void) {
    RFDIGI->RFDCOCCON0 = 0x8540000;
    RFDIGI->RFDCOCCON1 = 0x1E02;
    RFDIGI->RFDCOCCON2 = 0x2;
}

void ah_rfdigicali_dcoc_est_kick_start(int32_t *result) {
    uint32_t dcoc_ctrl;
    uint32_t dcoc_result;

    dcoc_ctrl = RFDIGI->RFDCOCCON0;
    dcoc_ctrl |= 3U;
    RFDIGI->RFDCOCCON0 = dcoc_ctrl;
    os_sleep_ms(2);

    dcoc_ctrl = RFDIGI->RFDCOCCON0;
    dcoc_ctrl |= 0x40U;
    RFDIGI->RFDCOCCON0 = dcoc_ctrl;
    os_sleep_us(2);

    dcoc_result = RFDIGI->RFDCOCCON3;
    int32_t i_result = ((int32_t)(dcoc_result << 20)) >> 20;
    result[0] = i_result;

    dcoc_result = RFDIGI->RFDCOCCON3;
    int32_t q_result = ((int32_t)(dcoc_result << 8)) >> 20;
    result[1] = q_result;

    dcoc_ctrl = RFDIGI->RFDCOCCON0;
    dcoc_ctrl &= ~(1U << 0);
    dcoc_ctrl &= ~(1U << 1);
    RFDIGI->RFDCOCCON0 = dcoc_ctrl;

    dcoc_ctrl = RFDIGI->RFDCOCCON0;
    dcoc_ctrl &= ~(1U << 6);
    RFDIGI->RFDCOCCON0 = dcoc_ctrl;

    dcoc_ctrl = RFDIGI->RFDCOCCON0;
    dcoc_ctrl |= 0x8U;
    RFDIGI->RFDCOCCON0 = dcoc_ctrl;
}

void ah_rfdigicali_dcoc_imb_est_kick_start(void) {
    RFDIGI->RFDCOCCON4 = 0x20000;
    RFDIGI->RFPWRCON0 = 40;
    RFDIGI->RFDCOCCON0 |= 3;
}

int16_t ah_rfdigicali_dcoci_get(void) {
    uint32_t dcoc_ctrl = RFDIGI->RFDCOCCON0;
    if (LMAC_REG_IS_SET(dcoc_ctrl, LMAC_RFDIGI_DCOC_EN_I)) {
        return (int16_t)32767;
    }
    uint32_t dcoc_result = RFDIGI->RFDCOCCON3;
    uint32_t i_dcoc = dcoc_result & 0xFFFU;
    if (i_dcoc >= 2048U) {
        i_dcoc -= 4096U;
    }
    return (int16_t)i_dcoc;
}

int16_t ah_rfdigicali_dcocq_get(void) {
    uint32_t dcoc_ctrl = RFDIGI->RFDCOCCON0;
    if (LMAC_REG_IS_SET(dcoc_ctrl, LMAC_RFDIGI_DCOC_EN_Q)) {
        return (int16_t)32767;
    }
    uint32_t dcoc_result = RFDIGI->RFDCOCCON3;
    uint32_t q_dcoc = (dcoc_result >> 12) & 0xFFFU;
    if (q_dcoc < 2048U) {
        return (int16_t)q_dcoc;
    } else {
        return (int16_t)(q_dcoc - 4096U);
    }
}

void ah_rfdigicali_get_rx_dcoc(uint16_t *out, uint32_t idx) {
    if (idx < 4) {
        uint32_t offset = idx + (idx * 2);          // idx * 3
        offset = offset * 4;                        // idx * 12
        uint32_t val = RFDIGI_RX_LO_WORD(offset);
        out[0] = (uint16_t)(val & 0x3FF);
        out[1] = (uint16_t)((val >> 10) & 0x3FF);
    } else {
        uint32_t val = RFDIGI_RX_HI_WORD(idx);
        out[0] = (uint16_t)(val & 0x3FF);
        out[1] = (uint16_t)((val >> 10) & 0x3FF);
    }
}

void ah_rfdigicali_get_rx_imb(uint16_t *gain_out, uint16_t *phase_out, uint32_t idx) {
    uint32_t val;
    if (idx >= 4) {
        val = RFDIGI_RX_HI_WORD((idx - 4) * 3);
        *gain_out = (uint16_t)((val >> 20) & 0x3FF);
        val = RFDIGI_RX_HI_WORD(RFDIGI_RX_HI_PHASE_WORD_OFFSET + (idx - 4) * 3);
        *phase_out = (uint16_t)(val & 0xFFF);
    } else {
        val = RFDIGI_RX_LO_WORD(idx * 3);
        *gain_out = (uint16_t)((val >> 20) & 0x3FF);
        val = RFDIGI_RX_LO_WORD(RFDIGI_RX_LO_PHASE_WORD_OFFSET + idx * 3);
        *phase_out = (uint16_t)(val & 0xFFF);
    }
}

uint32_t ah_rfdigicali_get_tx_digi_gain(uint32_t idx) {
    switch (idx) {
    case 0:
        return RFDIGI->TXDIGPWR01 & LMAC_RFDIGI_TX_DIGI_GAIN_MASK;
    case 1:
        return (RFDIGI->TXDIGPWR01 >> LMAC_RFDIGI_TX_DIGI_GAIN_HI_SHIFT) & LMAC_RFDIGI_TX_DIGI_GAIN_MASK;
    case 2:
        return RFDIGI->TXDIGPWR23 & LMAC_RFDIGI_TX_DIGI_GAIN_MASK;
    case 3:
        return (RFDIGI->TXDIGPWR23 >> LMAC_RFDIGI_TX_DIGI_GAIN_HI_SHIFT) & LMAC_RFDIGI_TX_DIGI_GAIN_MASK;
    case 4:
        return RFDIGI->TXDIGPWR45 & LMAC_RFDIGI_TX_DIGI_GAIN_MASK;
    default:
        return (RFDIGI->TXDIGPWR45 >> LMAC_RFDIGI_TX_DIGI_GAIN_HI_SHIFT) & LMAC_RFDIGI_TX_DIGI_GAIN_MASK;
    }
}

uint32_t ah_rfdigicali_power_calc_kick_start(void) {
    uint32_t bknoise_ctrl;
    bknoise_ctrl = RFDIGI->RFPWRCON0;
    bknoise_ctrl |= 0x2000;
    RFDIGI->RFPWRCON0 = bknoise_ctrl;
    bknoise_ctrl = RFDIGI->RFPWRCON0;
    bknoise_ctrl |= 0x0001;
    RFDIGI->RFPWRCON0 = bknoise_ctrl;
    do {
        bknoise_ctrl = RFDIGI->RFPWRCON0;
    } while (LMAC_REG_IS_CLEAR(bknoise_ctrl, LMAC_RFDIGI_HW_BKNOISE_VALID_MASK));
    bknoise_ctrl = RFDIGI->RFPWRCON0;
    bknoise_ctrl |= 0x2000;
    RFDIGI->RFPWRCON0 = bknoise_ctrl;
    uint32_t result = RFDIGI->RFPWRCON1;
    bknoise_ctrl = RFDIGI->RFPWRCON0;
    bknoise_ctrl &= ~0x0001U;
    RFDIGI->RFPWRCON0 = bknoise_ctrl;
    result >>= 8;
    return result;
}

void ah_rfdigicali_rx_dcoc_hw_trig_dis(void) {
    uint32_t val = RFDIGI->RFDCOCCON0;
    val &= ~LMAC_RFDIGI_RX_DCOC_HW_TRIG;
    RFDIGI->RFDCOCCON0 = val;
}

void ah_rfdigicali_rx_dcoc_hw_trig_en(void) {
    uint32_t val = RFDIGI->RFDCOCCON0;
    LMAC_WRITE_REG(RFDIGI->RFDCOCCON0, val | LMAC_RFDIGI_RX_DCOC_HW_TRIG);
}

void ah_rfdigicali_stop_tx_cali(void) {
    uint32_t val = RFDIGI->RFDCOCCON0;
    val &= ~LMAC_RFDIGI_DCOC_EN_I;
    val &= ~LMAC_RFDIGI_DCOC_EN_Q;
    RFDIGI->RFDCOCCON0 = val;
    val = RFDIGI->RFDCOCCON0;
    val &= ~LMAC_RFDIGI_DCOC_KICK;
    RFDIGI->RFDCOCCON0 = val;
    val = RFDIGI->RFDCOCCON0;
    val |= LMAC_RFDIGI_DCOC_STOP;
    RFDIGI->RFDCOCCON0 = val;
}

void ah_rfdigicali_tx_dcoc(const int16_t *dcoc_data, uint32_t idx) {
    uint32_t slot = idx;
    uint32_t tx_dcoc_word = RFDIGI_TX_DC_WORD(slot);
    tx_dcoc_word &= 0xFFFF000F;
    RFDIGI_TX_DC_WORD(slot) = tx_dcoc_word;
    uint32_t i_val = (uint32_t)dcoc_data[1];
    i_val = (i_val << 10) & 0x000FFC00;
    tx_dcoc_word = RFDIGI_TX_DC_WORD(slot);
    tx_dcoc_word = (tx_dcoc_word & 0xFFF003FF) | i_val;
    uint32_t q_val = (uint32_t)dcoc_data[0];
    q_val &= 0x000003FF;
    tx_dcoc_word |= q_val;
    RFDIGI_TX_DC_WORD(slot) = tx_dcoc_word;
    LMAC_SET_BIT(RFDIGI->TXPWRIDX, LMAC_RFDIGI_BUSY);
    LMAC_RFDIGI_WAIT_TX_READY();
}

void ah_rfdigicali_tx_pwr(uint32_t arg0) {
    uint32_t val = RFDIGI->TXPWRIDX;
    val &= ~LMAC_RFDIGI_TX_GAIN_IDX_SRC;
    RFDIGI->TXPWRIDX = val;
    val = RFDIGI->TXPWRIDX;
    val &= ~LMAC_RFDIGI_TX_GAIN_LOW_MASK;
    val |= arg0;
    RFDIGI->TXPWRIDX = val;
    val = RFDIGI->TXPWRIDX;
    LMAC_WRITE_REG(RFDIGI->TXPWRIDX, val | LMAC_RFDIGI_BUSY);
    LMAC_RFDIGI_WAIT_TX_READY();
}
