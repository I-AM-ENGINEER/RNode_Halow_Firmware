#include <stdint.h>
#include "sys_config.h"
#define LOG_LOCAL_LEVEL LOG_WARN
#include "lib/logc/log.h"
#include "typesdef.h"
#include "osal/time.h"
#include "osal/csky/sleep.h"   /* os_jiffies_to_msecs macro */

extern void ah_rfspi_write(uint16_t addr, uint32_t data);
extern uint16_t ah_rfspi_read(uint16_t addr);
extern uint16_t ah_rfspi_write_and_read(uint32_t addr, uint32_t data);
extern void delay_us(uint32_t us);

/* ---- ADC measurement throttling ----
 * Each SAR-ADC read (analog-mux/PMU switching) deafens the radio long enough
 * to kill one in-flight frame, and the binary lmac_chip_monitor asks for all
 * four measurements every 500 ms. Throttle the real conversions to one per
 * 60 s under traffic (15 s when idle) and serve cached values in between. */
#define MEAS_REFRESH_BUSY_MS 60000u
#define MEAS_REFRESH_IDLE_MS 15000u
/* A temperature jump of >=10 C since the last calibration forces one coherent
 * fresh snapshot of all four measurements on the same monitor pass. */
#define MEAS_DELTA_FORCE_C 10u
extern bool halow_ack_radio_quiet( void );

static bool g_meas_force_full;          /* set by the delta rule */
static int32_t g_meas_temp_last_cal;    /* tsensor value at last real pass */

extern int32_t __real_tsensor_meas(uint8_t sensor_idx);
int32_t __wrap_tsensor_meas(uint8_t sensor_idx)
{
    static int32_t  cached[4] = {33, 33, 33, 33};
    static uint64_t last_ms[4];
    uint64_t now = os_jiffies_to_msecs(os_jiffies());
    if (sensor_idx < 4u && (last_ms[sensor_idx] == 0u ||
                            now - last_ms[sensor_idx] >= (halow_ack_radio_quiet() ? MEAS_REFRESH_IDLE_MS : MEAS_REFRESH_BUSY_MS))) {
        int32_t fresh = __real_tsensor_meas(sensor_idx);
        if (last_ms[sensor_idx] != 0u) {
            int32_t d = fresh - g_meas_temp_last_cal;
            if (d < 0) d = -d;
            if ((uint32_t)d >= MEAS_DELTA_FORCE_C) {
                g_meas_force_full = true;
                log_warn("recal: temp jump %d -> %d C, forcing full refresh",
                         (int)g_meas_temp_last_cal, (int)fresh);
            }
        }
        g_meas_temp_last_cal = fresh;
        cached[sensor_idx]  = fresh;
        last_ms[sensor_idx] = now;
    }
    return (sensor_idx < 4u) ? cached[sensor_idx] : __real_tsensor_meas(sensor_idx);
}

extern float __real_vcc_meas(void);
float __wrap_vcc_meas(void)
{
    static float   cached = 3.3f;
    static uint64_t last_ms;
    uint64_t now = os_jiffies_to_msecs(os_jiffies());
    if (last_ms == 0u || g_meas_force_full ||
        now - last_ms >= (halow_ack_radio_quiet() ? MEAS_REFRESH_IDLE_MS : MEAS_REFRESH_BUSY_MS)) {
        cached  = __real_vcc_meas();
        last_ms = now;
    }
    return cached;
}

extern float __real_vdd13b_meas(void);
float __wrap_vdd13b_meas(void)
{
    static float   cached = 1.3f;
    static uint64_t last_ms;
    uint64_t now = os_jiffies_to_msecs(os_jiffies());
    if (last_ms == 0u || g_meas_force_full ||
        now - last_ms >= (halow_ack_radio_quiet() ? MEAS_REFRESH_IDLE_MS : MEAS_REFRESH_BUSY_MS)) {
        cached  = __real_vdd13b_meas();
        last_ms = now;
    }
    return cached;
}

extern float __real_vdd13c_meas(void);
float __wrap_vdd13c_meas(void)
{
    static float   cached = 1.3f;
    static uint64_t last_ms;
    uint64_t now = os_jiffies_to_msecs(os_jiffies());
    if (last_ms == 0u || g_meas_force_full ||
        now - last_ms >= (halow_ack_radio_quiet() ? MEAS_REFRESH_IDLE_MS : MEAS_REFRESH_BUSY_MS)) {
        cached  = __real_vdd13c_meas();
        last_ms = now;
        g_meas_force_full = false;   /* vdd13c is the last of the pass */
    }
    return cached;
}

static int pll_calibrate(void)
{
    /* Original (mars_ahrf.S ah_rf_lo_freq_set): kick the PLL calib up to 5
     * times UNTIL status bit 0x200 SETS; 0x400 set means "locked" (NOT an
     * error); the calib word is ALWAYS written to 0x603 and 0 is returned. */
    for (int i = 5; i != 0; i--) {
        ah_rfspi_write(0x810, 0x30);
        ah_rfspi_write(0x810, 0x31);
        delay_us(200);
        if (ah_rfspi_read(0x811) & 0x200u)
            break;
    }
    delay_us(800);
    uint16_t calib = ah_rfspi_read(0x811) & 0x1FFu;
    ah_rfspi_write_and_read(0x603, calib);
    return 0;
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
