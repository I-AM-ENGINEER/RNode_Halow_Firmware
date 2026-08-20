#include "sys_config.h"
#include "basic_include.h"
#include "halow.h"
#include "lib/lmac/lmac_ctx.h"
#include "lib/logc/log.h"
#include <stdint.h>
#include <string.h>

#define GP_WINDOW_S          2u
#define GP_DEBRIS_THRESH     15
#define GP_PROD_KEEP_PCT     70
#define GP_PROBE_EVERY_S     45u
#define GP_PROBE_MAX_PROD    2
#define GP_STABLE4_EXIT_PCT  30
#define GP_STABLE4_EXIT_WIN  10u

extern void lmac_rx_gain_cfg(uint32 gain);
extern volatile uint32_t g_rx_cls_internal, g_rx_cls_notmine, g_rx_cls_data;
bool halow_ack_link_busy(void);

enum {
    GP_MANUAL = 0,
    GP_G5 = 1,
    GP_TRIAL4 = 2,
    GP_STABLE4 = 3,
    GP_PROBE5 = 4,
};

static uint8_t g_gp_state = GP_G5;
static bool    g_gp_enabled = true;

static int32_t g_gp_debris_x;
static int32_t g_gp_prod_x;
static int32_t g_gp_prod_base_x;

static uint32_t gp_window_cnt;
static uint32_t gp_stable4_s;
static uint8_t  gp_debris_strikes;
static uint8_t  gp_starve_windows;

static uint32_t gp_read_rx_good(void)
{
    return *(volatile uint32_t *)((uint8_t *)&ah_lmac + 0x73C);
}

static uint32_t gp_read_cls(void)
{
    return g_rx_cls_internal + g_rx_cls_notmine + g_rx_cls_data;
}

static uint8_t gp_cur_gain(void)
{
    return (uint8_t)((ah_lmac.rx_gain_cfg_bits & 0x7ffu) >> 4);
}

static void gp_set_gain(uint32_t g)
{
    if (gp_cur_gain() != g) {
        lmac_rx_gain_cfg(g);
        log_info("gain pilot: -> %u (debris %d prod %d)", g,
                 (int)g_gp_debris_x, (int)g_gp_prod_x);
    }
}

void halow_gain_pilot_set(bool enable)
{
    g_gp_enabled = enable;
    if (!enable) {
        g_gp_state = GP_MANUAL;
    } else if (g_gp_state == GP_MANUAL) {
        g_gp_state = GP_G5;
        gp_debris_strikes = 0;
    }
}

bool halow_gain_pilot_enabled(void)
{
    return g_gp_enabled;
}

uint8_t halow_gain_pilot_state(void)
{
    return g_gp_state;
}

void halow_gain_pilot_dbg(int32_t *debris_x, int32_t *prod_x, int32_t *base_x)
{
    if (debris_x) *debris_x = g_gp_debris_x;
    if (prod_x) *prod_x = g_gp_prod_x;
    if (base_x) *base_x = g_gp_prod_base_x;
}

void halow_gain_pilot_tick(void)
{
    static uint32_t last_rx_good, last_cls;

    if (!g_gp_enabled) {
        return;
    }
    if (ah_lmac.cca_agc_ctrl_flags & 0x08u) {
        return;
    }

    gp_window_cnt++;
    if (gp_window_cnt < GP_WINDOW_S) {
        return;
    }
    gp_window_cnt = 0;

    uint32_t rx_good = gp_read_rx_good();
    uint32_t cls = gp_read_cls();
    int32_t debris = ((int32_t)(rx_good - last_rx_good)
                      - (int32_t)(cls - last_cls)) / (int32_t)GP_WINDOW_S;
    int32_t prod = (int32_t)(cls - last_cls) / (int32_t)GP_WINDOW_S;
    last_rx_good = rx_good;
    last_cls = cls;
    g_gp_debris_x = debris;
    g_gp_prod_x = prod;

    switch (g_gp_state) {
    case GP_G5:
        if (gp_cur_gain() != 5u) {
            gp_set_gain(5);
        }
        if (debris > GP_DEBRIS_THRESH) {
            if (++gp_debris_strikes >= 2u) {
                gp_debris_strikes = 0;
                g_gp_state = GP_TRIAL4;
                gp_set_gain(4);
            }
        } else {
            gp_debris_strikes = 0;
            if (prod > g_gp_prod_base_x) {
                g_gp_prod_base_x = prod;
            }
        }
        break;

    case GP_TRIAL4:
        if (g_gp_prod_base_x > 0 &&
            prod * 100 < g_gp_prod_base_x * (int32_t)GP_PROD_KEEP_PCT) {
            g_gp_state = GP_G5;
            gp_set_gain(5);
        } else {
            g_gp_state = GP_STABLE4;
            gp_stable4_s = 0;
            gp_starve_windows = 0;
        }
        break;

    case GP_STABLE4:
        gp_stable4_s += GP_WINDOW_S;
        if (prod > g_gp_prod_base_x) {
            g_gp_prod_base_x = prod;
        }
        if (g_gp_prod_base_x > 0 &&
            prod * 100 < g_gp_prod_base_x * (int32_t)GP_STABLE4_EXIT_PCT) {
            if (++gp_starve_windows >= GP_STABLE4_EXIT_WIN) {
                gp_starve_windows = 0;
                g_gp_state = GP_G5;
                gp_set_gain(5);
                break;
            }
        } else {
            gp_starve_windows = 0;
        }
        if (gp_stable4_s >= GP_PROBE_EVERY_S && prod < (int32_t)GP_PROBE_MAX_PROD &&
            !halow_ack_link_busy()) {
            g_gp_state = GP_PROBE5;
            g_gp_prod_base_x = 0;
            gp_set_gain(5);
        }
        break;

    case GP_PROBE5:
        if (prod > g_gp_prod_base_x) {
            g_gp_prod_base_x = prod;
        }
        if (debris > GP_DEBRIS_THRESH) {
            g_gp_state = GP_STABLE4;
            gp_stable4_s = 0;
            gp_set_gain(4);
        } else {
            g_gp_state = GP_G5;
        }
        break;

    default:
        g_gp_state = GP_G5;
        break;
    }
}
