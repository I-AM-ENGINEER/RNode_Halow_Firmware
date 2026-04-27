// Auto-reconstructed: mars_lmac_hw.c
#include "typesdef.h"

uint32 LMAC = 0x40008000UL;

extern void lmac_rx_cleanup_info(void);

static inline volatile uint32 *lmac_regs(void)
{
    return (volatile uint32 *)LMAC;
}

void lhw_enable_irq_ac(void)
{
    volatile uint32 *reg = lmac_regs();
    reg[0x44 / 4] |= 0x80U;
}

void lhw_start_rx(uint32 flags)
{
    volatile uint32 *reg = lmac_regs();
    uint32 val;

    if ((reg[0x34 / 4] & 0x00f000f0U) != 0) {
        return;
    }

    reg[0x1c / 4] &= 0xffffff00U;
    reg[0x1c / 4] |= flags << 8;
    val = reg[0x30 / 4];
    val &= ~(1U << 4);
    val &= ~(1U << 5);
    reg[0x30 / 4] = val;
    reg[0x30 / 4] |= 1U << 5;
    reg[0x30 / 4] |= 1U;
    reg[0x30 / 4] &= ~(1U << 13);
}

void lhw_abort_fsm(void)
{
    volatile uint32 *reg = lmac_regs();
    uint32 val;

    reg[0x48 / 4] = 0x1400U;
    val = reg[0x44 / 4];
    val &= ~(1U << 10);
    val &= ~(1U << 12);
    reg[0x44 / 4] = val;
    reg[0x48 / 4] = 0x1400U;
    reg[0x30 / 4] |= 2U;

    for (uint32 i = 20; i != 0; i--) {
        __asm volatile ("nop");
    }

    lmac_rx_cleanup_info();

    reg = lmac_regs();
    reg[0x30 / 4] |= 2U;
    reg[0x44 / 4] |= 1U << 10;
    reg[0x44 / 4] |= 1U << 12;
}

uint32 lhw_get_cca_remain(void)
{
    return lmac_regs()[0x20 / 4] & 0x7ffU;
}

void lhw_start_cca(uint32 bw, uint32 dur)
{
    volatile uint32 *reg = lmac_regs();

    if (bw >= 16) {
        bw = 15;
    }
    if (dur >= 2048) {
        dur = 2047;
    }

    reg[0x20 / 4] = ((uint8)bw << 12) + (uint16)dur + 2048U;
}

void lhw_start_tx(uint32 flags)
{
    volatile uint32 *reg = lmac_regs();
    uint32 val;

    reg[0x1c / 4] &= 0xffffff00U;
    reg[0x1c / 4] |= flags;
    val = reg[0x30 / 4];
    val &= ~(1U << 4);
    val &= ~(1U << 5);
    reg[0x30 / 4] = val;
    reg[0x30 / 4] |= 1U << 4;
    reg[0x30 / 4] |= 1U;
}

void lhw_irq_init(void)
{
    volatile uint32 *reg = lmac_regs();

    reg[0x44 / 4] = 0;
    reg[0x48 / 4] = 0xffffffffU;
    reg[0x44 / 4] |= 0x80U;
    reg[0x44 / 4] |= 0x20U;
    reg[0x44 / 4] |= 0x04U;
    reg[0x44 / 4] |= 0x400U;
    reg[0x44 / 4] |= 0x8000U;
    reg[0x44 / 4] |= 0x2000U;
    reg[0x44 / 4] |= 0x4000U;
    reg[0x44 / 4] |= 1U << 18;
    reg[0x5c / 4] = 25000U;
    reg[0x44 / 4] |= 1U << 20;
    reg[0x44 / 4] |= 0x1000U;
}

void lhw_cfg_sifs(uint32 sifs, uint32 slot, uint32 eifs)
{
    volatile uint32 *reg = lmac_regs();

    reg[0x1c / 4] = 0;
    reg[0x1c / 4] |= sifs | (slot << 8) | (eifs << 24);
}

void lhw_cfg_tx_delay_before(uint32 unused, uint32 b, uint32 c, uint32 a)
{
    volatile uint32 *reg = lmac_regs();
    uint32 val;
    (void)unused;

    reg[0x78 / 4] &= ~0x7fffU;
    val = (a & 0x1fU) | ((c & 0x1fU) << 5) | ((b & 0x1fU) << 10);
    reg[0x78 / 4] |= val;
}

void lhw_cfg_tx_delay_after(uint32 a, uint32 b, uint32 c, uint32 d)
{
    volatile uint32 *reg = lmac_regs();
    uint32 val;

    reg[0x84 / 4] &= 0xc0c0c0c0U;
    val = ((a & 0x3fU) << 24) | ((b & 0x3fU) << 16) |
          ((c & 0x3fU) << 8) | (d & 0x3fU);
    reg[0x84 / 4] |= val;
}

void lhw_cfg_tx_dalay_dac_rf(uint32 dac, uint32 rf, uint32 pa)
{
    volatile uint32 *reg = lmac_regs();
    uint32 val;

    reg[0x8c / 4] &= ~0x0f3fU;
    val = ((dac & 0x0fU) << 8) | (rf & 0x0fU) | ((pa & 3U) << 4);
    reg[0x8c / 4] |= val;
}

void lhw_cfg_phy_rx_delay(uint32 delay)
{
    volatile uint32 *reg = lmac_regs();

    reg[0xa0 / 4] &= 0x0fffffffU;
    reg[0xa0 / 4] |= delay << 28;
}

void lhw_cfg_dma_list_cnt(uint32 cnt)
{
    volatile uint32 *reg = lmac_regs();

    reg[0x100 / 4] &= ~0x7fU;
    reg[0x100 / 4] |= cnt & 0x7fU;
}

void lhw_cfg_tx_sub_frm(uint32 idx, uint32 v0, uint32 v1)
{
    volatile uint32 *reg = lmac_regs();

    *(volatile uint32 *)((uint32)reg + ((idx + 36U) << 3)) = v0;
    *(volatile uint32 *)((uint32)reg + (idx << 3) + 0x124U) = v1;
}

void lhw_cfg_tx_delay_pa(uint32 delay)
{
    volatile uint32 *reg = lmac_regs();

    reg[0x8c / 4] &= 0xf8000000U;
    reg[0x8c / 4] |= (delay & 0x1fU) << 12;
}

uint32 lhw_get_rx_frm_type(void)
{
    volatile uint32 *reg = lmac_regs();

    if ((reg[0xb4 / 4] & 0x100U) == 0) {
        return 0;
    }

    return (reg[0xb4 / 4] & 0x200U) ? 2U : 1U;
}

uint32 lhw_get_rx_ndp_ind(void)
{
    volatile uint32 *reg;
    uint32 frm_type = lhw_get_rx_frm_type();

    if (frm_type == 2) {
        return 0;
    }

    reg = lmac_regs();
    if (frm_type == 0) {
        return (reg[0xa4 / 4] >> 25) & 1U;
    }

    return (reg[0xa8 / 4] >> 5) & 1U;
}

uint64 lhw_get_ndp2m(void)
{
    volatile uint32 *reg = lmac_regs();
    return ((uint64)reg[0xa8 / 4] << 32) | reg[0xa4 / 4];
}

void lmac_rf_sw_ctrl(void)
{
    lmac_regs()[0x40 / 4] |= 0x200U;
}

void lmac_rf_hw_ctrl(void)
{
    lmac_regs()[0x40 / 4] &= ~(1U << 9);
}

void lmac_cfg_rf_en(uint32 enable)
{
    volatile uint32 *reg = lmac_regs();
    if (enable) {
        reg[0x40 / 4] |= 0x100U;
    } else {
        reg[0x40 / 4] &= ~0x100U;
    }
}

void lmac_cfg_tx_en(uint32 enable)
{
    volatile uint32 *reg = lmac_regs();
    if (enable) {
        reg[0x40 / 4] |= 0x400U;
    } else {
        reg[0x40 / 4] &= ~0x400U;
    }
}

void lmac_cfg_rx_en(uint32 enable)
{
    volatile uint32 *reg = lmac_regs();
    if (enable) {
        reg[0x40 / 4] |= 0x800U;
    } else {
        reg[0x40 / 4] &= ~0x800U;
    }
}

void lmac_cfg_pa_en(uint32 enable)
{
    volatile uint32 *reg = lmac_regs();
    if (enable) {
        reg[0x40 / 4] |= 1U << 16;
    } else {
        reg[0x40 / 4] &= ~(1U << 16);
    }
}

void lmac_cfg_dac_en(uint32 enable)
{
    volatile uint32 *reg = lmac_regs();
    if (enable) {
        reg[0x40 / 4] |= 1U << 17;
    } else {
        reg[0x40 / 4] &= ~(1U << 17);
    }
}

void lmac_cfg_end_to_limit(uint32 value)
{
    lmac_regs()[0x5c / 4] = value;
}

void lhw_set_bo_bypass(uint32 enable)
{
    volatile uint32 *reg = lmac_regs();
    if (enable) {
        reg[0x30 / 4] |= 0x100U;
    } else {
        reg[0x30 / 4] &= ~0x100U;
    }
}

void lhw_set_tsf(uint32 low, uint32 high)
{
    volatile uint32 *reg = lmac_regs();
    reg[0x10 / 4] = low;
    reg[0x14 / 4] = high;
}

void lhw_start_cca_observ(uint32 mode)
{
    volatile uint32 *reg = lmac_regs();
    reg[0x630 / 4] = (mode << 1) & 0x0eU;
    reg[0x630 / 4] |= 1U;
}

int32 lhw_get_cca_observ(uint32 *out)
{
    volatile uint32 *reg = lmac_regs();

    if ((reg[0x630 / 4] & 0x10U) != 0) {
        out[0] = reg[0x634 / 4];
        out[1] = reg[0x638 / 4];
        out[2] = reg[0x63c / 4];
        out[3] = reg[0x640 / 4];
        out[4] = reg[0x644 / 4];
        return 0;
    }

    out[0] = 0;
    out[1] = 0;
    out[2] = 0;
    out[3] = 0;
    out[4] = 0;
    return -1;
}
