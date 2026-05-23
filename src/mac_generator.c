#include "mac_generator.h"
#include "basic_include.h"
#include "configdb.h"
#include "osal/sleep.h"
#include "chip/txw4002ack803/sysctrl.h"
#include <string.h>

#define CFG_PREFIX   CONFIGDB_ADD_MODULE("privacy")
#define KEY_ROT      CFG_PREFIX ".rot"
#define KEY_BC       CFG_PREFIX ".bc"
#define KEY_WMAC     CFG_PREFIX ".wmac"

static mac_generator_config_t g_cfg;
static uint8_t g_wmac[6];
static uint8_t g_efuse[6];
static uint32_t g_rot_next_ms;

static void gen_random_mac(uint8_t mac[6]) {
    uint32_t s = (uint32_t)os_jiffies();
    for (int i = 0; i < 6; i++) {
        s = s * 1103515245u + 12345u + g_efuse[i];
        mac[i] = (uint8_t)(s >> 16);
    }
    mac[0] = (mac[0] & 0xFC) | 0x02;
}

static void load_or_create_wmac(uint8_t mac[6]) {
    if (configdb_get_blob(KEY_WMAC, mac, 6) == 0) {
        for (int i = 0; i < 6; i++) if (mac[i]) return;
    }
    gen_random_mac(mac);
    configdb_set_blob(KEY_WMAC, mac, 6);
}

void get_mac(uint8_t mac[6]) {
    static bool loaded;
    if (!loaded) {
        sysctrl_efuse_mac_addr_calc(g_efuse);
        loaded = true;
    }
    memcpy(mac, g_efuse, 6);
}

void mac_generator_init(void) {
    get_mac(g_efuse);
    mac_generator_config_load(&g_cfg);
    load_or_create_wmac(g_wmac);
    g_rot_next_ms = 0;
}

void mac_generator_config_load(mac_generator_config_t *cfg) {
    if (!cfg) return;
    configdb_get_i16(KEY_ROT, (int16_t *)&cfg->rotation_minutes);
    configdb_get_i8(KEY_BC, (int8_t *)&cfg->broadcast_mac);
}

void mac_generator_config_save(const mac_generator_config_t *cfg) {
    if (!cfg) return;
    configdb_set_i16(KEY_ROT, (int16_t *)&cfg->rotation_minutes);
    configdb_set_i8(KEY_BC, (int8_t *)&cfg->broadcast_mac);
}

void mac_generator_config_apply(const mac_generator_config_t *cfg) {
    if (!cfg) return;
    g_cfg = *cfg;
    load_or_create_wmac(g_wmac);
    g_rot_next_ms = 0;
}

void mac_generator_get(uint8_t mac[6]) {
    if (g_cfg.broadcast_mac) {
        memset(mac, 0xFF, 6);
        return;
    }
    if (g_cfg.rotation_minutes != 0) {
        uint32_t now = (uint32_t)(os_jiffies() * OS_MS_PERIOD_TICK);
        if (now >= g_rot_next_ms) {
            gen_random_mac(g_wmac);
            g_rot_next_ms = now + (uint32_t)g_cfg.rotation_minutes * 60000u;
        }
    }
    memcpy(mac, g_wmac, 6);
}
