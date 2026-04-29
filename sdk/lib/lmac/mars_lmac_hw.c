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
    LMAC_HW->IRQ_EN |= 0x80U;
}

void lhw_start_rx(uint32 flags) {
    log_debug("lhw_start_rx called with flags=0x%x\n", flags);

    if ((LMAC_HW->FSM_STATE & LMAC_FSM_BUSY_MASK) != 0) {
        return;
    }

    LMAC_HW->TIMING_CTRL = (LMAC_HW->TIMING_CTRL & ~0x0000FFFFU) | (flags << 8);

    uint32 val = LMAC_HW->FSM_CTRL;
    val &= ~(LMAC_FSM_TX_SEL | LMAC_FSM_RX_SEL);
    LMAC_HW->FSM_CTRL = val;
    LMAC_HW->FSM_CTRL |= LMAC_FSM_RX_SEL;
    LMAC_HW->FSM_CTRL |= LMAC_FSM_START;
    LMAC_HW->FSM_CTRL &= ~LMAC_FSM_RX_POST_CLEAR;
}

void lhw_abort_fsm(void) {
    log_debug("lhw_abort_fsm called\n");

    LMAC_HW->IRQ_CLR = 0x1400U;
    uint32 val = LMAC_HW->IRQ_EN;
    val &= ~(1U << 10);
    val &= ~(1U << 12);
    LMAC_HW->IRQ_EN = val;
    LMAC_HW->IRQ_CLR = 0x1400U;
    LMAC_HW->FSM_CTRL |= LMAC_FSM_ABORT;

    for (uint32 i = 20; i != 0; i--) {
        __asm volatile ("nop");
    }

    lmac_rx_cleanup_info();

    LMAC_HW->FSM_CTRL |= LMAC_FSM_ABORT;
    LMAC_HW->IRQ_EN   |= 1U << 10;
    LMAC_HW->IRQ_EN   |= 1U << 12;
}

uint32 lhw_get_cca_remain(void) {
    log_debug("lhw_get_cca_remain called\n");
    return LMAC_HW->CCA_CTRL & 0x7ffU;
}

void lhw_start_cca(uint32 bw, uint32 dur) {
    log_debug("lhw_start_cca called with bw=0x%x, dur=0x%x\n", bw, dur);

    if (bw >= 16) {
        bw = 15;
    }
    if (dur >= 2048) {
        dur = 2047;
    }

    LMAC_HW->CCA_CTRL = ((uint8)bw << 12) + (uint16)dur + 2048U;
}

void lhw_start_tx(uint32 flags) {
    log_debug("lhw_start_tx called with flags=0x%x\n", flags);

    LMAC_HW->TIMING_CTRL = (LMAC_HW->TIMING_CTRL & ~0x000000FFU) | flags;

    uint32 val = LMAC_HW->FSM_CTRL;
    val &= ~(LMAC_FSM_TX_SEL | LMAC_FSM_RX_SEL);
    LMAC_HW->FSM_CTRL = val;
    LMAC_HW->FSM_CTRL |= LMAC_FSM_TX_SEL;
    LMAC_HW->FSM_CTRL |= LMAC_FSM_START;
}

void lhw_irq_init(void) {
    log_debug("lhw_irq_init called\n");

    LMAC_HW->IRQ_EN  = 0;
    LMAC_HW->IRQ_CLR = 0xffffffffU;
    LMAC_HW->IRQ_EN  = 0x80U | 0x20U | 0x04U | 0x400U | 0x8000U | 0x2000U | 0x4000U | (1U << 18);
    LMAC_HW->END_TO_LIMIT = 25000U;
    LMAC_HW->IRQ_EN |= (1U << 20) | 0x1000U;
}

void lhw_cfg_sifs(uint32 sifs, uint32 slot, uint32 eifs) {
    log_debug("lhw_cfg_sifs called with sifs=0x%x, slot=0x%x, eifs=0x%x\n", sifs, slot, eifs);
    LMAC_HW->TIMING_CTRL = sifs | (slot << 8) | (eifs << 24);
}

void lhw_cfg_tx_delay_before(uint32 unused, uint32 b, uint32 c, uint32 a) {
    log_debug("lhw_cfg_tx_delay_before called with b=0x%x, c=0x%x, a=0x%x\n", b, c, a);
    (void)unused;
    uint32 val = (a & 0x1fU) | ((c & 0x1fU) << 5) | ((b & 0x1fU) << 10);
    LMAC_HW->TX_DELAY_BEFORE = (LMAC_HW->TX_DELAY_BEFORE & ~0x7fffU) | val;
}

void lhw_cfg_tx_delay_after(uint32 a, uint32 b, uint32 c, uint32 d) {
    log_debug("lhw_cfg_tx_delay_after called with a=0x%x, b=0x%x, c=0x%x, d=0x%x\n", a, b, c, d);
    uint32 val = ((a & 0x3fU) << 24) | ((b & 0x3fU) << 16) |
                 ((c & 0x3fU) << 8)  |  (d & 0x3fU);
    LMAC_HW->TX_DELAY_AFTER = (LMAC_HW->TX_DELAY_AFTER & ~0x3f3f3f3fU) | val;
}

void lhw_cfg_tx_dalay_dac_rf(uint32 dac, uint32 rf, uint32 pa) {
    log_debug("lhw_cfg_tx_dalay_dac_rf called with dac=0x%x, rf=0x%x, pa=0x%x\n", dac, rf, pa);
    uint32 val = ((dac & 0x0fU) << 8) | (rf & 0x0fU) | ((pa & 3U) << 4);
    LMAC_HW->TX_DAC_RF_DELAY = (LMAC_HW->TX_DAC_RF_DELAY & ~0x0f3fU) | val;
}

void lhw_cfg_phy_rx_delay(uint32 delay) {
    log_debug("lhw_cfg_phy_rx_delay called with delay=0x%x\n", delay);
    LMAC_HW->PHY_RX_DELAY = (LMAC_HW->PHY_RX_DELAY & ~0xf0000000U) | (delay << 28);
}

void lhw_cfg_dma_list_cnt(uint32 cnt) {
    log_debug("lhw_cfg_dma_list_cnt called with cnt=0x%x\n", cnt);
    LMAC_HW->DMA_LIST_CNT = (LMAC_HW->DMA_LIST_CNT & ~0x7fU) | (cnt & 0x7fU);
}

void lhw_cfg_tx_sub_frm(uint32 idx, uint32 v0, uint32 v1) {
    log_debug("lhw_cfg_tx_sub_frm called with idx=0x%x, v0=0x%x, v1=0x%x\n", idx, v0, v1);
    LMAC_HW->TX_SUB_FRM[idx * 2]     = v0;
    LMAC_HW->TX_SUB_FRM[idx * 2 + 1] = v1;
}

void lhw_cfg_tx_delay_pa(uint32 delay) {
    log_debug("lhw_cfg_tx_delay_pa called with delay=0x%x\n", delay);
    LMAC_HW->TX_DAC_RF_DELAY = (LMAC_HW->TX_DAC_RF_DELAY & ~0x0001FFFFU) | ((delay & 0x1fU) << 12);
}

uint32 lhw_get_rx_frm_type(void) {
    log_debug("lhw_get_rx_frm_type called\n");
    uint32 frm = LMAC_HW->RX_FRM_TYPE;

    if ((frm & 0x100U) == 0) {
        return 0;
    }

    return (frm & 0x200U) ? 2U : 1U;
}

uint32 lhw_get_rx_ndp_ind(void) {
    log_debug("lhw_get_rx_ndp_ind called\n");
    uint32 frm_type = lhw_get_rx_frm_type();

    if (frm_type == 2) {
        return 0;
    }

    if (frm_type == 0) {
        return (LMAC_HW->NDP2M_LO >> 25) & 1U;
    }

    return (LMAC_HW->NDP2M_HI >> 5) & 1U;
}

uint64 lhw_get_ndp2m(void) {
    log_debug("lhw_get_ndp2m called\n");
    return ((uint64)LMAC_HW->NDP2M_HI << 32) | LMAC_HW->NDP2M_LO;
}

void lmac_rf_sw_ctrl(void) {
    log_debug("lmac_rf_sw_ctrl called\n");
    LMAC_HW->RF_CTRL |= LMAC_RF_SW_CTRL;
}

void lmac_rf_hw_ctrl(void) {
    log_debug("lmac_rf_hw_ctrl called\n");
    LMAC_HW->RF_CTRL &= ~LMAC_RF_SW_CTRL;
}

void lmac_cfg_rf_en(uint32 enable) {
    log_debug("lmac_cfg_rf_en called with enable=0x%x\n", enable);
    if (enable) {
        LMAC_HW->RF_CTRL |= LMAC_RF_EN;
    } else {
        LMAC_HW->RF_CTRL &= ~LMAC_RF_EN;
    }
}

void lmac_cfg_tx_en(uint32 enable) {
    log_debug("lmac_cfg_tx_en called with enable=0x%x\n", enable);
    if (enable) {
        LMAC_HW->RF_CTRL |= LMAC_RF_TX_EN;
    } else {
        LMAC_HW->RF_CTRL &= ~LMAC_RF_TX_EN;
    }
}

void lmac_cfg_rx_en(uint32 enable) {
    log_debug("lmac_cfg_rx_en called with enable=0x%x\n", enable);
    if (enable) {
        LMAC_HW->RF_CTRL |= LMAC_RF_RX_EN;
    } else {
        LMAC_HW->RF_CTRL &= ~LMAC_RF_RX_EN;
    }
}

void lmac_cfg_pa_en(uint32 enable) {
    log_debug("lmac_cfg_pa_en called with enable=0x%x\n", enable);
    if (enable) {
        LMAC_HW->RF_CTRL |= LMAC_RF_PA_EN;
    } else {
        LMAC_HW->RF_CTRL &= ~LMAC_RF_PA_EN;
    }
}

void lmac_cfg_dac_en(uint32 enable) {
    log_debug("lmac_cfg_dac_en called with enable=0x%x\n", enable);
    if (enable) {
        LMAC_HW->RF_CTRL |= LMAC_RF_DAC_EN;
    } else {
        LMAC_HW->RF_CTRL &= ~LMAC_RF_DAC_EN;
    }
}

void lmac_cfg_end_to_limit(uint32 value) {
    log_debug("lmac_cfg_end_to_limit called with value=0x%x\n", value);
    LMAC_HW->END_TO_LIMIT = value;
}

void lhw_set_bo_bypass(uint32 enable) {
    log_debug("lhw_set_bo_bypass called with enable=0x%x\n", enable);
    if (enable) {
        LMAC_HW->FSM_CTRL |= LMAC_FSM_BO_BYPASS;
    } else {
        LMAC_HW->FSM_CTRL &= ~LMAC_FSM_BO_BYPASS;
    }
}

void lhw_set_tsf(uint32 low, uint32 high) {
    log_debug("lhw_set_tsf called with low=0x%x, high=0x%x\n", low, high);
    LMAC_HW->TSF_LO = low;
    LMAC_HW->TSF_HI = high;
}

void lhw_start_cca_observ(uint32 mode) {
    log_debug("lhw_start_cca_observ called with mode=0x%x\n", mode);
    LMAC_HW->CCA_OBSERV_CTRL  = (mode << 1) & 0x0eU;
    LMAC_HW->CCA_OBSERV_CTRL |= 1U;
}

int32 lhw_get_cca_observ(uint32 *out) {
    log_debug("lhw_get_cca_observ called\n");

    if (LMAC_HW->CCA_OBSERV_CTRL & 0x10U) {
        for (uint32 i = 0; i < 5; i++) {
            out[i] = LMAC_HW->CCA_OBSERV[i];
        }
        return 0;
    }

    for (uint32 i = 0; i < 5; i++) {
        out[i] = 0;
    }
    return -1;
}
