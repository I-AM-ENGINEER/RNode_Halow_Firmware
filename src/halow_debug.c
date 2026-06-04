#include <stdint.h>

extern void ah_rfspi_write(uint16_t addr, uint32_t data);
extern uint16_t ah_rfspi_read(uint16_t addr);
extern uint16_t ah_rfspi_write_and_read(uint32_t addr, uint32_t data);
extern void delay_us(uint32_t us);

static int pll_calibrate(void)
{
    for (int i = 5; i != 0; i--) {
        ah_rfspi_write(0x810, 0x30);
        ah_rfspi_write(0x810, 0x31);
        delay_us(200);
    }

    int timeout = 100;
    uint16_t status;
    for (;;) {
        delay_us(800);
        status = ah_rfspi_read(0x811);
        if (status & 0x400u)
            break;
        if (status & 0x200u) {
            if (--timeout <= 0)
                break;
            continue;
        }
        break;
    }

    uint16_t calib = ah_rfspi_read(0x811) & 0x1FFu;
    ah_rfspi_write_and_read(0x603, calib);
    return (status & 0x400u) ? -1 : (timeout <= 0) ? -2 : 0;
}

int __wrap_ah_rf_lo_freq_set(uint32_t freq_khz)
{
    float val = (float)freq_khz * 0.5f / 1000.0f * 0.125f;
    uint16_t int_part = (uint16_t)(uint32_t)val;
    float frac = val - (float)(uint32_t)int_part;
    uint32_t frac_part = (uint32_t)(frac * 4194301.0f);

    ah_rfspi_write(0x610, ah_rfspi_read(0x610) | 0xFFu);
    ah_rfspi_write(0x600, int_part);
    ah_rfspi_write(0x601, (uint16_t)(frac_part & 0xFFFFu));
    ah_rfspi_write(0x602, (uint16_t)((frac_part >> 16) & 0xFFFFu));

    pll_calibrate();
    return 0;
}

int __wrap_ah_rf_lo_freq_set(uint32_t freq_khz);

int __wrap_ah_rf_lo_table_cfg(const uint32_t *freq_list, uint8_t count)
{
    if (count >= 0x11)
        return -1;

    for (uint8_t i = 0; i < count; i++) {
        int ret = __wrap_ah_rf_lo_freq_set(freq_list[i]);
        if (ret != 0)
            return ret;

        uint16_t table_addr = (uint16_t)(i * 0x10 + 0x500);
        for (uint16_t spi_addr = 0x92E; spi_addr < 0x932; spi_addr++) {
            uint16_t val = ah_rfspi_read(spi_addr);
            ah_rfspi_write(table_addr, val);
            table_addr++;
        }
    }
    return 0;
}
