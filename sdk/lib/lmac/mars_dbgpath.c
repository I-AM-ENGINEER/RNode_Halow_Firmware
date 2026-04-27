// Auto-reconstructed: mars_dbgpath.c
#include "typesdef.h"

#define DBGPATH_REGS ((volatile uint32 *)0x40005000UL)

extern const uint32 ndbgpathcfg[];

void ah_init_dbgpath_device(void) {
    volatile uint32 *reg = DBGPATH_REGS;
    const uint32 *cfg = ndbgpathcfg;

    reg[0] = cfg[0];
    reg[4] = cfg[1];
    reg[5] = cfg[2];
    reg[6] = cfg[3];
    reg[7] = cfg[4];
    reg[8] = cfg[5];
    reg[9] = cfg[6];
    reg[10] = cfg[7];
    reg[11] = cfg[8];
    reg[12] = cfg[9];
    reg[13] = cfg[10];
    reg[14] = cfg[11];
    reg[15] = cfg[12];
    reg[16] = cfg[13];
    reg[17] = cfg[14];
    reg[18] = cfg[15];
    reg[19] = cfg[16];
    reg[20] = cfg[17];
    reg[21] = cfg[18];
    reg[22] = cfg[19];
    reg[23] = cfg[20];
    reg[28] = cfg[21];
}

void ah_set_dbgpath_device_tx_dly(uint32 delay) {
    volatile uint32 *reg = DBGPATH_REGS;
    uint32 val = reg[0];
    val &= ~0x7c0U;
    reg[0] = val;
    val = reg[0];
    val |= (delay << 6) & 0x7c0U;
    reg[0] = val;
}

void ah_set_dbgpath_device_rx_dly(uint32 delay) {
    volatile uint32 *reg = DBGPATH_REGS;
    uint32 val = reg[0];
    val &= ~0xf800U;
    reg[0] = val;
    val = reg[0];
    val |= (delay << 11) & 0xf800U;
    reg[0] = val;
}

static inline __attribute__((always_inline)) void ah_set_dbgpath_device_extspi_word(uint32 index, uint32 high, uint32 low) {
    volatile uint32 *reg = DBGPATH_REGS;
    uint32 val = reg[index];
    val &= 0xffc00000U;
    reg[index] = val;
    val = reg[index];
    val |= high << 8;
    reg[index] = val;
    val = reg[index];
    val &= 0xffffff00U;
    reg[index] = val;
    val = reg[index];
    val |= low;
    reg[index] = val;
    val = reg[index];
    val |= 0x00800000U;
    reg[index] = val;
}

void ah_set_dbgpath_device_extspi_tx_pwr(uint8 tx_pwr, uint8 rx_gain) {
    ah_set_dbgpath_device_extspi_word(4, tx_pwr, rx_gain);
}

void ah_set_dbgpath_device_extspi_rx_gain(uint32 high, uint32 low) {
    ah_set_dbgpath_device_extspi_word(5, high, low);
}

void ah_set_dbgpath_device_extspi_dpd_gain(uint32 high, uint32 low) {
    ah_set_dbgpath_device_extspi_word(6, high, low);
}

void ah_enable_dbgpath_device_ext_dpd_gain(void) {
    volatile uint32 *reg = DBGPATH_REGS;
    uint32 val = reg[0];
    val &= ~(1U << 21);
    reg[0] = val;
    val = reg[0];
    val |= (1U << 21);
    reg[0] = val;
}

void ah_disable_dbgpath_device_ext_dpd_gain(void) {
    volatile uint32 *reg = DBGPATH_REGS;
    uint32 val = reg[0];
    val &= ~(1U << 21);
    reg[0] = val;
}

uint32 ah_get_dbgpath_device_stop_pos(uint32 divisor) {
    volatile uint32 *reg = DBGPATH_REGS;
    uint32 val = reg[3];
    return val - ((val / divisor) * divisor);
}

void ah_set_dbgpath_device_path_mode(uint32 mode) {
    volatile uint32 *reg = DBGPATH_REGS;
    uint32 val = reg[0];
    val &= ~7U;
    reg[0] = val;
    val = reg[0];
    val |= mode & 7U;
    reg[0] = val;
}

void ah_set_dbgpath_device_tdma2_en_bit(uint32 enable) {
    volatile uint32 *reg = DBGPATH_REGS;
    uint32 val = reg[9];
    val &= 0x7fffffffU;
    reg[9] = val;
    val = reg[9];
    val |= enable << 31;
    reg[9] = val;
}

void ah_trig_dbgpath_device_dma(void) {
    volatile uint32 *reg = DBGPATH_REGS;
    uint32 val = reg[0];
    val &= ~(1U << 4);
    reg[0] = val;
    val = reg[0];
    val |= (1U << 4);
    reg[0] = val;
    while ((reg[0] & (1U << 4)) == 0) {}
}

void ah_trig_dbgpath_device_dma2(void) {
    volatile uint32 *reg = DBGPATH_REGS;
    uint32 val = reg[0];
    val &= ~(1U << 22);
    reg[0] = val;
    val = reg[0];
    val |= (1U << 22);
    reg[0] = val;
    while ((reg[0] & (128U << 15)) == 0) {}
}

void ah_abort_dbgpath_device_dma(void) {
    volatile uint32 *reg = DBGPATH_REGS;
    uint32 val = reg[0];
    val &= ~(1U << 5);
    reg[0] = val;
    val = reg[0];
    val |= (1U << 5);
    reg[0] = val;
    while ((reg[0] & (1U << 5)) == 0) {}
}

void ah_abort_dbgpath_device_dma2(void) {
    volatile uint32 *reg = DBGPATH_REGS;
    uint32 val = reg[0];
    val &= ~(1U << 23);
    reg[0] = val;
    val = reg[0];
    val |= (1U << 23);
    reg[0] = val;
    while ((reg[0] & (128U << 16)) == 0) {}
}

void ah_config_dbgpath_device_dmaend_cond(uint32 cond) {
    volatile uint32 *reg = DBGPATH_REGS;
    uint32 val = reg[0];
    val &= ~(1U << 18);
    val &= ~(1U << 19);
    reg[0] = val;
    val = reg[0];
    val |= (cond << 18) & 0x000c0000U;
    reg[0] = val;
}

void ah_config_dbgpath_device_ext_path(uint32 enable) {
    volatile uint32 *reg = DBGPATH_REGS;
    uint32 val = reg[0];

    if (enable) {
        val |= (1U << 20);
        val |= (1U << 21);
    } else {
        val &= ~(1U << 20);
        val &= ~(1U << 21);
    }

    reg[0] = val;
}

void ah_config_dbgpath_device_dbg_out(uint32 device, uint32 value) {
    volatile uint32 *reg = DBGPATH_REGS;
    uint32 val;

    switch (device) {
    case 0:
        val = reg[10];
        val &= 0xffffff00U;
        reg[10] = val;
        val = reg[10] | value;
        reg[10] = val;
        break;
    case 1:
        val = reg[10];
        val &= 0xffff00ffU;
        reg[10] = val;
        val = reg[10] | (value << 8);
        reg[10] = val;
        break;
    case 2:
        val = reg[10];
        val &= 0xff00ffffU;
        reg[10] = val;
        val = reg[10] | (value << 16);
        reg[10] = val;
        break;
    case 3:
        val = reg[10];
        val &= 0x00ffffffU;
        reg[10] = val;
        val = reg[10] | (value << 24);
        reg[10] = val;
        break;
    case 4:
        val = reg[11];
        val &= 0xffffff00U;
        reg[11] = val;
        val = reg[11] | value;
        reg[11] = val;
        break;
    case 5:
        val = reg[11];
        val &= 0xffff00ffU;
        reg[11] = val;
        val = reg[11] | (value << 8);
        reg[11] = val;
        break;
    case 6:
        val = reg[11];
        val &= 0xff00ffffU;
        reg[11] = val;
        val = reg[11] | (value << 16);
        reg[11] = val;
        break;
    default:
        val = reg[11];
        val &= 0x00ffffffU;
        reg[11] = val;
        val = reg[11] | (value << 24);
        reg[11] = val;
        break;
    }
}

void ah_config_dbgpath_device_enable_bits(uint32 bits) {
    volatile uint32 *reg = DBGPATH_REGS;
    uint32 val = reg[7];
    val &= 0x0000ff00U;
    val |= bits & 0xffffU;
    reg[7] = val;
    reg[10] = ((bits >> 16) & 0xffffU) << 3;

    val = reg[12];
    val &= ~(1U << 29);
    reg[12] = val;
    val = reg[12];
    val |= (bits << 12) & (128U << 22);
    reg[12] = val;

    val = reg[14];
    val &= ~(1U << 29);
    reg[14] = val;
    val = reg[14];
    val |= ((bits >> 18) & 1U) << 29;
    reg[14] = val;

    val = reg[16];
    val &= ~(1U << 29);
    reg[16] = val;
    val = reg[16];
    val |= ((bits >> 19) & 1U) << 29;
    reg[16] = val;

    val = reg[18];
    val &= ~(1U << 29);
    reg[18] = val;
    val = reg[18];
    val |= ((bits >> 20) & 1U) << 29;
    reg[18] = val;

    val = reg[20];
    val &= ~(1U << 29);
    reg[20] = val;
    val = reg[20];
    val |= ((bits >> 21) & 1U) << 29;
    reg[20] = val;

    val = reg[22];
    val &= ~(1U << 29);
    reg[22] = val;
    val = reg[22];
    val |= ((bits >> 22) & 1U) << 29;
    reg[22] = val;
}

uint32 ah_get_dbgpath_device_rfmipi_err_info(void) {
    volatile uint32 *reg = DBGPATH_REGS;
    return reg[7] & 0xfffU;
}

void ah_clear_dbgpath_device_rfmipi_err_info(void) {
    volatile uint32 *reg = DBGPATH_REGS;
    uint32 val = reg[7];
    val &= ~(1U << 10);
    reg[7] = val;
    val = reg[7];
    val |= (1U << 10);
    reg[7] = val;
}
