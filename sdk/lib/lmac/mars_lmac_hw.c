// Auto-reconstructed: mars_lmac_hw.c
#include "sys_config.h"
#define LOG_LOCAL_LEVEL LOG_LEVEL_MARS_LMAC_HW
#include "lib/logc/log.h"

#include "typesdef.h"
#include "lib/lmac/lmac_regmap.h"

extern void lmac_rx_cleanup_info(void);

/* Global LMAC base pointer for compatibility with precompiled libs */
uint32 LMAC = LMAC_HW_BASE_ADDR;

void lhw_enable_irq_ac(void) {
    log_debug("lhw_enable_irq_ac called\n");
    volatile uint32 *base = (volatile uint32 *)LMAC;
    *(base + LMAC_REG_IDX(LMAC_REG_IRQ_EN)) |= 0x80U;
}

void lhw_start_rx(uint32 flags) {
    log_debug("lhw_start_rx called with flags=0x%x\n", flags);
    volatile uint32 *base = (volatile uint32 *)LMAC;
    uint32 val;

    if ((*(base + LMAC_REG_IDX(LMAC_REG_FSM_STATE)) & LMAC_FSM_BUSY_MASK) != 0) {
        return;
    }

    *(base + LMAC_REG_IDX(LMAC_REG_TIMING_CTRL)) &= 0xFFFF0000U;
    *(base + LMAC_REG_IDX(LMAC_REG_TIMING_CTRL)) |= flags << 8;
    val = *(base + LMAC_REG_IDX(LMAC_REG_FSM_CTRL));
    val &= ~LMAC_FSM_TX_SEL;
    val &= ~LMAC_FSM_RX_SEL;
    *(base + LMAC_REG_IDX(LMAC_REG_FSM_CTRL)) = val;
    *(base + LMAC_REG_IDX(LMAC_REG_FSM_CTRL)) |= LMAC_FSM_RX_SEL;
    *(base + LMAC_REG_IDX(LMAC_REG_FSM_CTRL)) |= LMAC_FSM_START;
    *(base + LMAC_REG_IDX(LMAC_REG_FSM_CTRL)) &= ~LMAC_FSM_RX_POST_CLEAR;
}

void lhw_abort_fsm(void) {
    log_debug("lhw_abort_fsm called\n");
    volatile uint32 *base = (volatile uint32 *)LMAC;
    uint32 val;

    *(base + LMAC_REG_IDX(LMAC_REG_IRQ_CLR)) = 0x1400U;
    val = *(base + LMAC_REG_IDX(LMAC_REG_IRQ_EN));
    val &= ~(1U << 10);
    val &= ~(1U << 12);
    *(base + LMAC_REG_IDX(LMAC_REG_IRQ_EN)) = val;
    *(base + LMAC_REG_IDX(LMAC_REG_IRQ_CLR)) = 0x1400U;
    *(base + LMAC_REG_IDX(LMAC_REG_FSM_CTRL)) |= LMAC_FSM_ABORT;

    for (uint32 i = 20; i != 0; i--) {
        __asm volatile ("nop");
    }

    lmac_rx_cleanup_info();

    *(base + LMAC_REG_IDX(LMAC_REG_FSM_CTRL)) |= LMAC_FSM_ABORT;
    *(base + LMAC_REG_IDX(LMAC_REG_IRQ_EN)) |= 1U << 10;
    *(base + LMAC_REG_IDX(LMAC_REG_IRQ_EN)) |= 1U << 12;
}

uint32 lhw_get_cca_remain(void) {
    log_debug("lhw_get_cca_remain called\n");
    volatile uint32 *base = (volatile uint32 *)LMAC;
    return *(base + LMAC_REG_IDX(LMAC_REG_CCA_CTRL)) & 0x7ffU;
}

void lhw_start_cca(uint32 bw, uint32 dur) {
    log_debug("lhw_start_cca called with bw=0x%x, dur=0x%x\n", bw, dur);
    volatile uint32 *base = (volatile uint32 *)LMAC;

    if (bw >= 16) {
        bw = 15;
    }
    if (dur >= 2048) {
        dur = 2047;
    }

    *(base + LMAC_REG_IDX(LMAC_REG_CCA_CTRL)) = ((uint8)bw << 12) + (uint16)dur + 2048U;
}

void lhw_start_tx(uint32 flags) {
    log_debug("lhw_start_tx called with flags=0x%x\n", flags);
    volatile uint32 *base = (volatile uint32 *)LMAC;
    uint32 val;

    *(base + LMAC_REG_IDX(LMAC_REG_TIMING_CTRL)) &= 0xffffff00U;
    *(base + LMAC_REG_IDX(LMAC_REG_TIMING_CTRL)) |= flags;
    val = *(base + LMAC_REG_IDX(LMAC_REG_FSM_CTRL));
    val &= ~LMAC_FSM_TX_SEL;
    val &= ~LMAC_FSM_RX_SEL;
    *(base + LMAC_REG_IDX(LMAC_REG_FSM_CTRL)) = val;
    *(base + LMAC_REG_IDX(LMAC_REG_FSM_CTRL)) |= LMAC_FSM_TX_SEL;
    *(base + LMAC_REG_IDX(LMAC_REG_FSM_CTRL)) |= LMAC_FSM_START;
}

void lhw_irq_init(void) {
    log_debug("lhw_irq_init called\n");
    volatile uint32 *base = (volatile uint32 *)LMAC;

    *(base + LMAC_REG_IDX(LMAC_REG_IRQ_EN)) = 0;
    *(base + LMAC_REG_IDX(LMAC_REG_IRQ_CLR)) = 0xffffffffU;
    *(base + LMAC_REG_IDX(LMAC_REG_IRQ_EN)) |= 0x80U;
    *(base + LMAC_REG_IDX(LMAC_REG_IRQ_EN)) |= 0x20U;
    *(base + LMAC_REG_IDX(LMAC_REG_IRQ_EN)) |= 0x04U;
    *(base + LMAC_REG_IDX(LMAC_REG_IRQ_EN)) |= 0x400U;
    *(base + LMAC_REG_IDX(LMAC_REG_IRQ_EN)) |= 0x8000U;
    *(base + LMAC_REG_IDX(LMAC_REG_IRQ_EN)) |= 0x2000U;
    *(base + LMAC_REG_IDX(LMAC_REG_IRQ_EN)) |= 0x4000U;
    *(base + LMAC_REG_IDX(LMAC_REG_IRQ_EN)) |= 1U << 18;
    *(base + LMAC_REG_IDX(LMAC_REG_END_TO_LIMIT)) = 25000U;
    *(base + LMAC_REG_IDX(LMAC_REG_IRQ_EN)) |= 1U << 20;
    *(base + LMAC_REG_IDX(LMAC_REG_IRQ_EN)) |= 0x1000U;
}

void lhw_cfg_sifs(uint32 sifs, uint32 slot, uint32 eifs) {
    log_debug("lhw_cfg_sifs called with sifs=0x%x, slot=0x%x, eifs=0x%x\n", sifs, slot, eifs);
    volatile uint32 *base = (volatile uint32 *)LMAC;

    *(base + LMAC_REG_IDX(LMAC_REG_TIMING_CTRL)) &= 0U;
    *(base + LMAC_REG_IDX(LMAC_REG_TIMING_CTRL)) |= sifs | (slot << 8) | (eifs << 24);
}

void lhw_cfg_tx_delay_before(uint32 unused, uint32 b, uint32 c, uint32 a) {
    log_debug("lhw_cfg_tx_delay_before called with b=0x%x, c=0x%x, a=0x%x\n", b, c, a);
    volatile uint32 *base = (volatile uint32 *)LMAC;
    uint32 val;
    (void)unused;

    *(base + LMAC_REG_IDX(LMAC_REG_TX_DELAY_BEFORE)) &= ~0x7fffU;
    val = (a & 0x1fU) | ((c & 0x1fU) << 5) | ((b & 0x1fU) << 10);
    *(base + LMAC_REG_IDX(LMAC_REG_TX_DELAY_BEFORE)) |= val;
}

void lhw_cfg_tx_delay_after(uint32 a, uint32 b, uint32 c, uint32 d) {
    log_debug("lhw_cfg_tx_delay_after called with a=0x%x, b=0x%x, c=0x%x, d=0x%x\n", a, b, c, d);
    volatile uint32 *base = (volatile uint32 *)LMAC;
    uint32 val;

    *(base + LMAC_REG_IDX(LMAC_REG_TX_DELAY_AFTER)) &= 0xc0c0c0c0U;
    val = ((a & 0x3fU) << 24) | ((b & 0x3fU) << 16) |
          ((c & 0x3fU) << 8) | (d & 0x3fU);
    *(base + LMAC_REG_IDX(LMAC_REG_TX_DELAY_AFTER)) |= val;
}

void lhw_cfg_tx_dalay_dac_rf(uint32 dac, uint32 rf, uint32 pa) {
    log_debug("lhw_cfg_tx_dalay_dac_rf called with dac=0x%x, rf=0x%x, pa=0x%x\n", dac, rf, pa);
    volatile uint32 *base = (volatile uint32 *)LMAC;
    uint32 val;

    *(base + LMAC_REG_IDX(LMAC_REG_TX_DAC_RF_DELAY)) &= ~0x0f3fU;
    val = ((dac & 0x0fU) << 8) | (rf & 0x0fU) | ((pa & 3U) << 4);
    *(base + LMAC_REG_IDX(LMAC_REG_TX_DAC_RF_DELAY)) |= val;
}

void lhw_cfg_phy_rx_delay(uint32 delay) {
    log_debug("lhw_cfg_phy_rx_delay called with delay=0x%x\n", delay);
    volatile uint32 *base = (volatile uint32 *)LMAC;

    *(base + LMAC_REG_IDX(LMAC_REG_PHY_RX_DELAY)) &= 0x0fffffffU;
    *(base + LMAC_REG_IDX(LMAC_REG_PHY_RX_DELAY)) |= delay << 28;
}

void lhw_cfg_dma_list_cnt(uint32 cnt) {
    log_debug("lhw_cfg_dma_list_cnt called with cnt=0x%x\n", cnt);
    volatile uint32 *base = (volatile uint32 *)LMAC;

    *(base + LMAC_REG_IDX(LMAC_REG_DMA_LIST_CNT)) &= ~0x7fU;
    *(base + LMAC_REG_IDX(LMAC_REG_DMA_LIST_CNT)) |= cnt & 0x7fU;
}

void lhw_cfg_tx_sub_frm(uint32 idx, uint32 v0, uint32 v1) {
    log_debug("lhw_cfg_tx_sub_frm called with idx=0x%x, v0=0x%x, v1=0x%x\n", idx, v0, v1);
    volatile uint32 *base = (volatile uint32 *)LMAC;
    *(base + LMAC_REG_IDX(LMAC_REG_TX_SUB_FRM_BASE + (idx << 3))) = v0;
    *(base + LMAC_REG_IDX(LMAC_REG_TX_SUB_FRM_BASE + 4 + (idx << 3))) = v1;
}

void lhw_cfg_tx_delay_pa(uint32 delay) {
    log_debug("lhw_cfg_tx_delay_pa called with delay=0x%x\n", delay);
    volatile uint32 *base = (volatile uint32 *)LMAC;

    *(base + LMAC_REG_IDX(LMAC_REG_TX_DAC_RF_DELAY)) &= 0xFFFE0000U;
    *(base + LMAC_REG_IDX(LMAC_REG_TX_DAC_RF_DELAY)) |= (delay & 0x1fU) << 12;
}

uint32 lhw_get_rx_frm_type(void) {
    log_debug("lhw_get_rx_frm_type called\n");
    volatile uint32 *base = (volatile uint32 *)LMAC;

    if ((*(base + LMAC_REG_IDX(LMAC_REG_RX_FRM_TYPE)) & 0x100U) == 0) {
        return 0;
    }

    return (*(base + LMAC_REG_IDX(LMAC_REG_RX_FRM_TYPE)) & 0x200U) ? 2U : 1U;
}

uint32 lhw_get_rx_ndp_ind(void) {
    log_debug("lhw_get_rx_ndp_ind called\n");
    volatile uint32 *base = (volatile uint32 *)LMAC;
    uint32 frm_type = lhw_get_rx_frm_type();

    if (frm_type == 2) {
        return 0;
    }

    if (frm_type == 0) {
        return (*(base + LMAC_REG_IDX(LMAC_REG_NDP2M_LO)) >> 25) & 1U;
    }

    return (*(base + LMAC_REG_IDX(LMAC_REG_NDP2M_HI)) >> 5) & 1U;
}

uint64 lhw_get_ndp2m(void) {
    log_debug("lhw_get_ndp2m called\n");
    volatile uint32 *base = (volatile uint32 *)LMAC;
    return ((uint64)*(base + LMAC_REG_IDX(LMAC_REG_NDP2M_HI)) << 32) | *(base + LMAC_REG_IDX(LMAC_REG_NDP2M_LO));
}

void lmac_rf_sw_ctrl(void) {
    log_debug("lmac_rf_sw_ctrl called\n");
    volatile uint32 *base = (volatile uint32 *)LMAC;
    *(base + LMAC_REG_IDX(LMAC_REG_RF_CTRL)) |= LMAC_RF_SW_CTRL;
}

void lmac_rf_hw_ctrl(void) {
    log_debug("lmac_rf_hw_ctrl called\n");
    volatile uint32 *base = (volatile uint32 *)LMAC;
    *(base + LMAC_REG_IDX(LMAC_REG_RF_CTRL)) &= ~LMAC_RF_SW_CTRL;
}

void lmac_cfg_rf_en(uint32 enable) {
    log_debug("lmac_cfg_rf_en called with enable=0x%x\n", enable);
    volatile uint32 *base = (volatile uint32 *)LMAC;
    if (enable) {
        *(base + LMAC_REG_IDX(LMAC_REG_RF_CTRL)) |= LMAC_RF_EN;
    } else {
        *(base + LMAC_REG_IDX(LMAC_REG_RF_CTRL)) &= ~LMAC_RF_EN;
    }
}

void lmac_cfg_tx_en(uint32 enable) {
    log_debug("lmac_cfg_tx_en called with enable=0x%x\n", enable);
    volatile uint32 *base = (volatile uint32 *)LMAC;
    if (enable) {
        *(base + LMAC_REG_IDX(LMAC_REG_RF_CTRL)) |= LMAC_RF_TX_EN;
    } else {
        *(base + LMAC_REG_IDX(LMAC_REG_RF_CTRL)) &= ~LMAC_RF_TX_EN;
    }
}

void lmac_cfg_rx_en(uint32 enable) {
    log_debug("lmac_cfg_rx_en called with enable=0x%x\n", enable);
    volatile uint32 *base = (volatile uint32 *)LMAC;
    if (enable) {
        *(base + LMAC_REG_IDX(LMAC_REG_RF_CTRL)) |= LMAC_RF_RX_EN;
    } else {
        *(base + LMAC_REG_IDX(LMAC_REG_RF_CTRL)) &= ~LMAC_RF_RX_EN;
    }
}

void lmac_cfg_pa_en(uint32 enable) {
    log_debug("lmac_cfg_pa_en called with enable=0x%x\n", enable);
    volatile uint32 *base = (volatile uint32 *)LMAC;
    if (enable) {
        *(base + LMAC_REG_IDX(LMAC_REG_RF_CTRL)) |= LMAC_RF_PA_EN;
    } else {
        *(base + LMAC_REG_IDX(LMAC_REG_RF_CTRL)) &= ~LMAC_RF_PA_EN;
    }
}

void lmac_cfg_dac_en(uint32 enable) {
    log_debug("lmac_cfg_dac_en called with enable=0x%x\n", enable);
    volatile uint32 *base = (volatile uint32 *)LMAC;
    if (enable) {
        *(base + LMAC_REG_IDX(LMAC_REG_RF_CTRL)) |= LMAC_RF_DAC_EN;
    } else {
        *(base + LMAC_REG_IDX(LMAC_REG_RF_CTRL)) &= ~LMAC_RF_DAC_EN;
    }
}

void lmac_cfg_end_to_limit(uint32 value) {
    log_debug("lmac_cfg_end_to_limit called with value=0x%x\n", value);
    volatile uint32 *base = (volatile uint32 *)LMAC;
    *(base + LMAC_REG_IDX(LMAC_REG_END_TO_LIMIT)) = value;
}

void lhw_set_bo_bypass(uint32 enable) {
    log_debug("lhw_set_bo_bypass called with enable=0x%x\n", enable);
    volatile uint32 *base = (volatile uint32 *)LMAC;
    if (enable) {
        *(base + LMAC_REG_IDX(LMAC_REG_FSM_CTRL)) |= LMAC_FSM_BO_BYPASS;
    } else {
        *(base + LMAC_REG_IDX(LMAC_REG_FSM_CTRL)) &= ~LMAC_FSM_BO_BYPASS;
    }
}

void lhw_set_tsf(uint32 low, uint32 high) {
    log_debug("lhw_set_tsf called with low=0x%x, high=0x%x\n", low, high);
    volatile uint32 *base = (volatile uint32 *)LMAC;
    *(base + LMAC_REG_IDX(0x10)) = low;
    *(base + LMAC_REG_IDX(0x14)) = high;
}

void lhw_start_cca_observ(uint32 mode) {
    log_debug("lhw_start_cca_observ called with mode=0x%x\n", mode);
    volatile uint32 *base = (volatile uint32 *)LMAC;
    *(base + LMAC_REG_IDX(LMAC_REG_CCA_OBSERV_CTRL)) = (mode << 1) & 0x0eU;
    *(base + LMAC_REG_IDX(LMAC_REG_CCA_OBSERV_CTRL)) |= 1U;
}

int32 lhw_get_cca_observ(uint32 *out) {
    log_debug("lhw_get_cca_observ called\n");
    volatile uint32 *base = (volatile uint32 *)LMAC;

    if ((*(base + LMAC_REG_IDX(LMAC_REG_CCA_OBSERV_CTRL)) & 0x10U) != 0) {
        out[0] = *(base + LMAC_REG_IDX(LMAC_REG_CCA_OBSERV0 + 0x00));
        out[1] = *(base + LMAC_REG_IDX(LMAC_REG_CCA_OBSERV0 + 0x04));
        out[2] = *(base + LMAC_REG_IDX(LMAC_REG_CCA_OBSERV0 + 0x08));
        out[3] = *(base + LMAC_REG_IDX(LMAC_REG_CCA_OBSERV0 + 0x0c));
        out[4] = *(base + LMAC_REG_IDX(LMAC_REG_CCA_OBSERV0 + 0x10));
        return 0;
    }

    out[0] = 0;
    out[1] = 0;
    out[2] = 0;
    out[3] = 0;
    out[4] = 0;
    return -1;
}
