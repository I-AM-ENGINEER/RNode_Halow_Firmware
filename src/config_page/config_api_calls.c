#include "sys_config.h"
#include "build_info_gen.h"
#define LOG_LOCAL_LEVEL LOG_LEVEL_CONFIG_API_CALLS

#include "basic_include.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "cJSON.h"
#include "lwip/netif.h"
#include "lwip/ip4_addr.h"

#include "config_page/config_api_calls.h"
#include "config_page/config_api_dispatch.h"

#include "halow.h"
#include "halow_lbt.h"
#include "halow_cca.h"
#include "halow_ack.h"
#include "rns/link_db.h"
#include "net_ip.h"
#include "tcp_server.h"
#include "utils.h"
#include "device.h"
#include "statistics.h"
#include "telemetry.h"
#include "hal/spi_nor.h"
#include "ota.h"
#include "nearby_detect.h"
#include "mac_generator.h"
#include "lib/logc/log.h"
#include "uart_slip.h"
#include "net_log.h"
#include "chip/txw4002ack803/sysctrl.h"
#include "halow_pkg_handler.h"
#include "lib/lmac/lmac_ctx.h"

extern struct netif *netif_default;
extern struct spi_nor_flash flash0;

/* -------------------------------------------------------------------------- */
/* JSON helpers (local, minimal)                                              */
/* -------------------------------------------------------------------------- */

static bool json_get_bool( const cJSON *o, const char *k, bool *out ){
    const cJSON *v;

    if (o == NULL || k == NULL || out == NULL) {
        return false;
    }
    v = cJSON_GetObjectItemCaseSensitive((cJSON *)o, k);
    if (!cJSON_IsBool(v)) {
        return false;
    }
    *out = cJSON_IsTrue(v) ? true : false;
    return true;
}

static bool json_get_int( const cJSON *o, const char *k, int *out ){
    const cJSON *v;

    if (o == NULL || k == NULL || out == NULL) {
        return false;
    }
    v = cJSON_GetObjectItemCaseSensitive((cJSON *)o, k);
    if (!cJSON_IsNumber(v)) {
        return false;
    }
    *out = v->valueint;
    return true;
}

static bool json_get_double( const cJSON *o, const char *k, double *out ){
    const cJSON *v;

    if (o == NULL || k == NULL || out == NULL) {
        return false;
    }
    v = cJSON_GetObjectItemCaseSensitive((cJSON *)o, k);
    if (!cJSON_IsNumber(v)) {
        return false;
    }
    *out = v->valuedouble;
    return true;
}

static bool json_get_string( const cJSON *o, const char *k, char *out, size_t out_sz ){
    const cJSON *v;

    if (o == NULL || k == NULL || out == NULL || out_sz == 0) {
        return false;
    }
    v = cJSON_GetObjectItemCaseSensitive((cJSON *)o, k);
    if (!cJSON_IsString(v) || v->valuestring == NULL) {
        return false;
    }

    strncpy(out, v->valuestring, out_sz - 1);
    out[out_sz - 1] = 0;
    return true;
}

static int32_t api_err( cJSON *out, int32_t rc, const char *msg ){
    if (out != NULL && msg != NULL) {
        (void)cJSON_DeleteItemFromObject(out, "err");
        (void)cJSON_AddStringToObject(out, "err", msg);
    }
    return rc;
}

static bool json_get_float( const cJSON *o, const char *k, float *out ){
    const cJSON *v;

    if ((o == NULL) || (k == NULL) || (out == NULL)) {
        return false;
    }

    v = cJSON_GetObjectItemCaseSensitive(o, k);
    if (!cJSON_IsNumber(v)) {
        return false;
    }

    *out = (float)v->valuedouble;
    return true;
}

/* -------------------------------------------------------------------------- */
/* /api/ok                                                                    */
/* -------------------------------------------------------------------------- */

int32_t web_api_ok_get( const cJSON *in, cJSON *out ){
    (void)in;

    if (out == NULL) {
        return WEB_API_RC_BAD_REQUEST;
    }

    (void)cJSON_AddBoolToObject(out, "ok", 1);
    return WEB_API_RC_OK;
}

/* -------------------------------------------------------------------------- */
/* /api/halow_cfg                                                             */
/* -------------------------------------------------------------------------- */

int32_t web_api_halow_cfg_get( const cJSON *in, cJSON *out ){
    halow_config_t cfg;
    char bndw[16];
    char mcs[8];
    int power_dbm;

    (void)in;

    if (out == NULL) {
        return WEB_API_RC_BAD_REQUEST;
    }

    halow_config_load(&cfg);

    (void)snprintf(bndw, sizeof(bndw), "%d MHz", (int)cfg.bandwidth);
    (void)cJSON_AddStringToObject(out, "bandwidth", bndw);
    (void)cJSON_AddNumberToObject(out, "central_freq", ((double)cfg.central_freq) / 10.0);

    power_dbm = (int)cfg.rf_power;
    if (cfg.rf_super_power) {
        power_dbm += 5;
    }
    (void)cJSON_AddNumberToObject(out, "power_dbm", (double)power_dbm);

    (void)snprintf(mcs, sizeof(mcs), "MCS%d", (int)cfg.mcs);
    (void)cJSON_AddStringToObject(out, "mcs_index", mcs);

    return WEB_API_RC_OK;
}

int32_t web_api_halow_cfg_post(const cJSON *in, cJSON *out) {
    halow_config_t cfg;
    int i;
    double d;
    const cJSON *j;

    if (in == NULL || !cJSON_IsObject(in) || out == NULL) {
        log_warn("halow_cfg_post bad json");
        return api_err(out, WEB_API_RC_BAD_REQUEST, "bad json");
    }

    halow_config_load(&cfg);

    j = cJSON_GetObjectItemCaseSensitive(in, "bandwidth");
    if (j != NULL && cJSON_IsString(j) && j->valuestring != NULL) {
        const char *s_bw = j->valuestring;
        int bw = atoi(s_bw);

        if (bw > 0 && bw < 64) {
            cfg.bandwidth = (int8_t)bw;
        }

        log_debug("halow_cfg bandwidth json='%s' -> %d", s_bw, bw);
    }

    j = cJSON_GetObjectItemCaseSensitive(in, "mcs_index");
    if (j != NULL && cJSON_IsString(j) && j->valuestring != NULL) {
        const char *s_mcs = j->valuestring;

        if (s_mcs[0] == 'M' && s_mcs[1] == 'C' && s_mcs[2] == 'S') {
            int m = atoi(&s_mcs[3]);
            if (m >= 0 && (m <= 7 || m == 10)) {
                cfg.mcs = (int8_t)m;
            }
        }
    }

    if (cJSON_GetObjectItemCaseSensitive(in, "super_power") != NULL) {
        log_debug("halow_cfg_post ignore legacy super_power");
    }

    if (json_get_int(in, "power_dbm", &i)) {
        if (i < 1 || i > 25) {
            log_warn("halow_cfg_post bad power_dbm=%d", i);
            return api_err(out, WEB_API_RC_BAD_REQUEST,
                           "power_dbm must be in range 1..25 dBm");
        }

        if (i > 20) {
            cfg.rf_super_power = 1;
            cfg.rf_power = (int8_t)(i - 5);
        } else {
            cfg.rf_super_power = 0;
            cfg.rf_power = (int8_t)i;
        }

        log_debug("halow_cfg power_dbm=%d -> rf_power=%d, super_power=%d",
                  i, cfg.rf_power, cfg.rf_super_power);
    }

    if (json_get_double(in, "central_freq", &d)) {
        if (d > 0.0) {
            cfg.central_freq = (uint16_t)(d * 10.0 + 0.5);
        }
    }

    halow_config_apply(&cfg);
    halow_config_save(&cfg);

    log_debug("halow_cfg updated");


    return web_api_halow_cfg_get(NULL, out);
}

/* -------------------------------------------------------------------------- */
/* /api/slip_cfg                                                              */
/* -------------------------------------------------------------------------- */

int32_t web_api_slip_cfg_get( const cJSON *in, cJSON *out ){
    uart_slip_config_t cfg;
    char ip[16];
    char mask[16];
    char gw[16];

    (void)in;

    if( out == NULL ){
        return WEB_API_RC_BAD_REQUEST;
    }

    uart_slip_config_load(&cfg);

    ip4addr_ntoa_r(&cfg.ip,   ip,   sizeof(ip));
    ip4addr_ntoa_r(&cfg.mask, mask, sizeof(mask));
    ip4addr_ntoa_r(&cfg.gw,   gw,   sizeof(gw));

    (void)cJSON_AddBoolToObject(out, "enable", cfg.enabled ? 1 : 0);
    (void)cJSON_AddNumberToObject(out, "baud", (double)cfg.baud);
    (void)cJSON_AddStringToObject(out, "ip", ip);
    (void)cJSON_AddStringToObject(out, "mask", mask);
    (void)cJSON_AddStringToObject(out, "gw", gw);

    return WEB_API_RC_OK;
}

int32_t web_api_slip_cfg_post(const cJSON *in, cJSON *out) {
    uart_slip_config_t cfg;
    bool b;
    int v;
    const cJSON *j;

    if (in == NULL || !cJSON_IsObject(in) || out == NULL) {
        log_warn("uart_slip_cfg_post bad json");
        return api_err(out, WEB_API_RC_BAD_REQUEST, "bad json");
    }

    uart_slip_config_load(&cfg);

    if (json_get_bool(in, "enable", &b)) {
        cfg.enabled = b ? true : false;
    }

    if (json_get_int(in, "baud", &v)) {
        if (v < 1) {
            log_warn("uart_slip_cfg_post bad baud=%d", v);
            return api_err(out, WEB_API_RC_BAD_REQUEST, "bad baud");
        }
        cfg.baud = (uint32_t)v;
    }

    j = cJSON_GetObjectItemCaseSensitive(in, "ip");
    if (j != NULL) {
        if (!cJSON_IsString(j) || j->valuestring == NULL ||
            !ip4addr_aton(j->valuestring, &cfg.ip)) {
            log_warn("uart_slip_cfg_post bad ip");
            return api_err(out, WEB_API_RC_BAD_REQUEST, "bad ip");
        }
    }

    j = cJSON_GetObjectItemCaseSensitive(in, "mask");
    if (j != NULL) {
        if (!cJSON_IsString(j) || j->valuestring == NULL ||
            !ip4addr_aton(j->valuestring, &cfg.mask)) {
            log_warn("uart_slip_cfg_post bad mask");
            return api_err(out, WEB_API_RC_BAD_REQUEST, "bad mask");
        }
    }

    j = cJSON_GetObjectItemCaseSensitive(in, "gw");
    if (j != NULL) {
        if (!cJSON_IsString(j) || j->valuestring == NULL ||
            !ip4addr_aton(j->valuestring, &cfg.gw)) {
            log_warn("uart_slip_cfg_post bad gw");
            return api_err(out, WEB_API_RC_BAD_REQUEST, "bad gw");
        }
    }

    uart_slip_config_save(&cfg);
    uart_slip_config_apply(&cfg);

    log_debug("uart_slip cfg updated enable=%d baud=%lu",
              cfg.enabled ? 1 : 0,
              (unsigned long)cfg.baud);


    return web_api_slip_cfg_get(NULL, out);
}

/* -------------------------------------------------------------------------- */
/* /api/log_cfg                                                               */
/* -------------------------------------------------------------------------- */

int32_t web_api_log_cfg_get(const cJSON *in, cJSON *out) {
    char host[16];
    net_log_config_t cfg;

    (void)in;

    if (out == NULL) {
        return WEB_API_RC_BAD_REQUEST;
    }

    net_log_config_load(&cfg);

    ip4addr_ntoa_r(&cfg.ip, host, sizeof(host));

    (void)cJSON_AddBoolToObject(out, "udp_enable", cfg.enable ? 1 : 0);
    (void)cJSON_AddBoolToObject(out, "enable", cfg.enable ? 1 : 0);
    (void)cJSON_AddStringToObject(out, "host", host);
    (void)cJSON_AddStringToObject(out, "ip_address", host);
    (void)cJSON_AddNumberToObject(out, "port", (double)cfg.port);

    return WEB_API_RC_OK;
}

int32_t web_api_log_cfg_post(const cJSON *in, cJSON *out) {
    net_log_config_t cfg;
    bool b;
    int v;
    const cJSON *j;

    if (in == NULL || !cJSON_IsObject(in) || out == NULL) {
        log_warn("log_cfg_post bad json");
        return api_err(out, WEB_API_RC_BAD_REQUEST, "bad json");
    }

    net_log_config_load(&cfg);

    if (json_get_bool(in, "udp_enable", &b)) {
        cfg.enable = b ? true : false;
    } else if (json_get_bool(in, "enable", &b)) {
        cfg.enable = b ? true : false;
    }

    j = cJSON_GetObjectItemCaseSensitive(in, "host");
    if (j == NULL) {
        j = cJSON_GetObjectItemCaseSensitive(in, "ip_address");
    }

    if (j != NULL) {
        if (!cJSON_IsString(j) || j->valuestring == NULL ||
            !ip4addr_aton(j->valuestring, &cfg.ip)) {
            log_warn("log_cfg_post bad host/ip_address");
            return api_err(out, WEB_API_RC_BAD_REQUEST, "bad host");
        }
    }

    if (json_get_int(in, "port", &v)) {
        if (v < 1 || v > 65535) {
            log_warn("log_cfg_post bad port=%d", v);
            return api_err(out, WEB_API_RC_BAD_REQUEST, "bad port");
        }
        cfg.port = (uint16_t)v;
    }

    net_log_config_save(&cfg);
    net_log_config_apply(&cfg);

    log_debug("log_cfg updated enable=%d port=%u",
              cfg.enable ? 1 : 0,
              (unsigned)cfg.port);


    return web_api_log_cfg_get(NULL, out);
}

/* -------------------------------------------------------------------------- */
/* /api/net_cfg                                                               */
/* -------------------------------------------------------------------------- */

int32_t web_api_net_cfg_get( const cJSON *in, cJSON *out ){
    net_ip_config_t cfg;
    char ip[16];
    char gw[16];
    char mask[16];

    (void)in;

    if (out == NULL) {
        return WEB_API_RC_BAD_REQUEST;
    }

    net_ip_config_load(&cfg);

    if (cfg.mode == NET_IP_MODE_DHCP) {
        net_ip_config_fill_runtime_addrs(&cfg);
    }

    ip4addr_ntoa_r(&cfg.ip,   ip,   sizeof(ip));
    ip4addr_ntoa_r(&cfg.gw,   gw,   sizeof(gw));
    ip4addr_ntoa_r(&cfg.mask, mask, sizeof(mask));

    (void)cJSON_AddBoolToObject(out, "dhcp", (cfg.mode == NET_IP_MODE_DHCP) ? 1 : 0);
    (void)cJSON_AddStringToObject(out, "ip_address", ip);
    (void)cJSON_AddStringToObject(out, "gw_address", gw);
    (void)cJSON_AddStringToObject(out, "netmask", mask);

    return WEB_API_RC_OK;
}

int32_t web_api_net_cfg_post( const cJSON *in, cJSON *out ){
    net_ip_config_t cfg;
    bool dhcp = false;
    char ip[16];
    char gw[16];
    char mask[16];

    if (in == NULL || !cJSON_IsObject(in) || out == NULL) {
        log_warn("net_cfg_post bad json");
        return api_err(out, WEB_API_RC_BAD_REQUEST, "bad json");
    }

    ip[0] = 0;
    gw[0] = 0;
    mask[0] = 0;

    (void)json_get_bool(in, "dhcp", &dhcp);
    (void)json_get_string(in, "ip_address", ip, sizeof(ip));
    (void)json_get_string(in, "gw_address", gw, sizeof(gw));
    (void)json_get_string(in, "netmask", mask, sizeof(mask));

    if (cJSON_GetObjectItemCaseSensitive(in, "dhcp") != NULL) {
        net_ip_config_set_default(&cfg);
        cfg.mode = dhcp ? NET_IP_MODE_DHCP : NET_IP_MODE_STATIC;

        if (cfg.mode == NET_IP_MODE_STATIC) {
            if (!ip4addr_aton(ip, &cfg.ip)) {
                log_warn("net_cfg_post bad ip_address '%s'", ip);
                return api_err(out, WEB_API_RC_BAD_REQUEST, "bad ip_address");
            }
            if (!ip4addr_aton(mask, &cfg.mask)) {
                log_warn("net_cfg_post bad netmask '%s'", mask);
                return api_err(out, WEB_API_RC_BAD_REQUEST, "bad netmask");
            }
            if (!ip4addr_aton(gw, &cfg.gw)) {
                log_warn("net_cfg_post bad gw_address '%s'", gw);
                return api_err(out, WEB_API_RC_BAD_REQUEST, "bad gw_address");
            }
        }
    } else {
        net_ip_config_load(&cfg);
    }

    net_ip_config_apply(&cfg);
    net_ip_config_save(&cfg);

    log_debug("net_cfg updated dhcp=%d", dhcp ? 1 : 0);


    return web_api_net_cfg_get(NULL, out);
}

/* -------------------------------------------------------------------------- */
/* /api/tcp_server_cfg                                                        */
/* -------------------------------------------------------------------------- */

int32_t web_api_tcp_server_cfg_get( const cJSON *in, cJSON *out ){
    tcp_server_config_t cfg;
    ip4_addr_t client_addr;
    uint16_t client_port;
    char whitelist[32];
    char connected[32];

    (void)in;

    if (out == NULL) {
        return WEB_API_RC_BAD_REQUEST;
    }

    tcp_server_config_load(&cfg);

    utils_ip_mask_to_cidr(whitelist, sizeof(whitelist),
                          &cfg.whitelist_ip, &cfg.whitelist_mask);

    if (tcp_server_get_client_info(&client_addr, &client_port)) {
        char ipbuf[16];
        ip4addr_ntoa_r(&client_addr, ipbuf, sizeof(ipbuf));
        snprintf(connected, sizeof(connected), "%s:%u", ipbuf, (unsigned)client_port);
    } else {
        snprintf(connected, sizeof(connected), "no connection");
    }

    (void)cJSON_AddBoolToObject(out, "enable", cfg.enabled ? 1 : 0);
    (void)cJSON_AddNumberToObject(out, "port", (double)cfg.port);
    (void)cJSON_AddStringToObject(out, "whitelist", whitelist);
    (void)cJSON_AddStringToObject(out, "connected", connected);

    return WEB_API_RC_OK;
}

int32_t web_api_tcp_server_cfg_post( const cJSON *in, cJSON *out ){
    tcp_server_config_t cfg;
    bool enable = false;
    int port = 0;
    char whitelist[32];
    ip4_addr_t ip;
    ip4_addr_t mask;

    if (in == NULL || !cJSON_IsObject(in) || out == NULL) {
        log_warn("tcp_server_cfg_post bad json");
        return api_err(out, WEB_API_RC_BAD_REQUEST, "bad json");
    }

    whitelist[0] = 0;

    (void)json_get_bool(in, "enable", &enable);
    (void)json_get_int(in, "port", &port);
    (void)json_get_string(in, "whitelist", whitelist, sizeof(whitelist));

    tcp_server_config_load(&cfg);

    if (cJSON_GetObjectItemCaseSensitive(in, "enable") != NULL) {
        cfg.enabled = enable ? true : false;
    }

    if (port >= 1 && port <= 65535) {
        cfg.port = (uint16_t)port;
    }

    /* Only touch the whitelist when the key was actually present: the old
     * else-branch wiped a configured whitelist to accept-all (0.0.0.0/0) on
     * any partial POST that omitted it. */
    if (json_get_string(in, "whitelist", whitelist, sizeof(whitelist)) &&
        whitelist[0] != '\0' &&
        utils_cidr_to_ip(whitelist, &ip) && utils_cidr_to_mask(whitelist, &mask)) {
        cfg.whitelist_ip   = ip;
        cfg.whitelist_mask = mask;
    }

    tcp_server_config_apply(&cfg);
    tcp_server_config_save(&cfg);

    log_debug("tcp_server_cfg updated enable=%d port=%u",
              cfg.enabled ? 1 : 0,
              (unsigned)cfg.port);


    return web_api_tcp_server_cfg_get(NULL, out);
}

/* -------------------------------------------------------------------------- */
/* /api/lbt_cfg (placeholders)                                                */
/* -------------------------------------------------------------------------- */

// /api/lbt (config)
// Keys:
//  en    - LBT enable (bool)
//  sw    - short window samples (u16)
//  lw    - long window samples (u16)
//  lp    - lowest percent for long window (u8)
//  roff  - relative offset dBm (i8)
//  abusy - absolute busy dBm (i8)
//  txgr  - TX grace us (u16)
//  txmax - max continuous TX ms (u16)
//  bmin  - backoff min us (u16)
//  bmax  - backoff max us (u16)
//  uen   - util enable (bool)
//  umax  - util max % (u8)
//  uwin  - util window ms (u32)
//  uburst- util burst ms (u16)

int32_t web_api_lbt_cfg_get( const cJSON *in, cJSON *out ){
    halow_lbt_config_t cfg;

    (void)in;

    if (out == NULL) {
        return WEB_API_RC_BAD_REQUEST;
    }

    halow_lbt_config_load(&cfg);

    (void)cJSON_AddBoolToObject(out,   "en",    (cfg.lbt_enabled != 0) ? 1 : 0);

    (void)cJSON_AddNumberToObject(out, "sw",    (double)cfg.noise_short_window_samples);
    (void)cJSON_AddNumberToObject(out, "lw",    (double)cfg.noise_long_window_samples);
    (void)cJSON_AddNumberToObject(out, "lp",    (double)cfg.noise_long_low_percent);

    (void)cJSON_AddNumberToObject(out, "roff",  (double)cfg.noise_relative_offset_dbm);
    (void)cJSON_AddNumberToObject(out, "abusy", (double)cfg.noise_absolute_busy_dbm);

    (void)cJSON_AddNumberToObject(out, "txgr",  (double)cfg.tx_skip_check_time_us);
    (void)cJSON_AddNumberToObject(out, "txmax", (double)cfg.tx_max_continuous_time_ms);

    (void)cJSON_AddNumberToObject(out, "bmin",  (double)cfg.backoff_random_min_us);
    (void)cJSON_AddNumberToObject(out, "bmax",  (double)cfg.backoff_random_max_us);

    (void)cJSON_AddBoolToObject(out,   "uen",   (cfg.util_enabled != 0) ? 1 : 0);
    (void)cJSON_AddNumberToObject(out, "umax",  (double)cfg.util_max_percent);
    (void)cJSON_AddNumberToObject(out, "uwin",  (double)cfg.util_refill_window_ms);
    (void)cJSON_AddNumberToObject(out, "uburst",(double)cfg.util_bucket_capacity_ms);

    return WEB_API_RC_OK;
}

int32_t web_api_lbt_cfg_post( const cJSON *in, cJSON *out ){
    halow_lbt_config_t cfg;
    bool b;
    int v;

    if (in == NULL || !cJSON_IsObject(in) || out == NULL) {
        log_warn("lbt_cfg_post bad json");
        return api_err(out, WEB_API_RC_BAD_REQUEST, "bad json");
    }

    halow_lbt_config_load(&cfg);

    if (json_get_bool(in, "en", &b))    { cfg.lbt_enabled  = b ? 1 : 0; }

    if (json_get_int(in, "sw", &v))    { if (v >= 1 && v <= 4096) cfg.noise_short_window_samples = (uint16_t)v; }
    if (json_get_int(in, "lw", &v))    { if (v >= 1 && v <= 4096) cfg.noise_long_window_samples  = (uint16_t)v; }
    if (json_get_int(in, "lp", &v))    { if (v >= 0 && v <= 100)   cfg.noise_long_low_percent     = (uint8_t)v;  }

    if (json_get_int(in, "roff", &v))  { if (v >= -128 && v <= 127) cfg.noise_relative_offset_dbm = (int8_t)v; }
    if (json_get_int(in, "abusy", &v)) { if (v >= -128 && v <= 127) cfg.noise_absolute_busy_dbm   = (int8_t)v; }

    if (json_get_int(in, "txgr", &v))  { if (v >= 0 && v <= 65535) cfg.tx_skip_check_time_us       = (uint16_t)v; }
    if (json_get_int(in, "txmax", &v)) { if (v >= 0 && v <= 65535) cfg.tx_max_continuous_time_ms   = (uint16_t)v; }

    if (json_get_int(in, "bmin", &v))  { if (v >= 0 && v <= 65535) cfg.backoff_random_min_us       = (uint16_t)v; }
    if (json_get_int(in, "bmax", &v))  { if (v >= 0 && v <= 65535) cfg.backoff_random_max_us       = (uint16_t)v; }

    if (json_get_bool(in, "uen", &b))  { cfg.util_enabled = b ? 1 : 0; }
    if (json_get_int(in, "umax", &v))  { if (v >= 0 && v <= 100)   cfg.util_max_percent           = (uint8_t)v;  }
    if (json_get_int(in, "uwin", &v))  { if (v >= 1)               cfg.util_refill_window_ms      = (uint32_t)v; }
    if (json_get_int(in, "uburst",&v)) { if (v >= 0 && v <= 65535) cfg.util_bucket_capacity_ms    = (uint16_t)v; }

    halow_lbt_config_apply(&cfg);
    halow_lbt_config_save(&cfg);

    log_debug("lbt_cfg updated");

    return web_api_lbt_cfg_get(NULL, out);
}

int32_t web_api_cca_cfg_get( const cJSON *in, cJSON *out ){
    halow_cca_config_t cfg;

    (void)in;

    if (out == NULL) {
        return WEB_API_RC_BAD_REQUEST;
    }

    halow_cca_config_load(&cfg);

    (void)cJSON_AddNumberToObject(out, "en",     (double)cfg.cca_enabled);
    (void)cJSON_AddNumberToObject(out, "ftpct",  (double)cfg.cca_force_tx_pct / 10.0);
    (void)cJSON_AddNumberToObject(out, "dlpct",  (double)cfg.duty_limit_pct / 10.0);
    (void)cJSON_AddNumberToObject(out, "cwmin",  (double)cfg.cw_min);
    (void)cJSON_AddNumberToObject(out, "cwmax",  (double)cfg.cw_max);
    (void)cJSON_AddNumberToObject(out, "thdyn",  (double)cfg.cca_threshold_dynamic);
    (void)cJSON_AddNumberToObject(out, "sens",   (double)cfg.cca_sensitivity);

    return WEB_API_RC_OK;
}

int32_t web_api_cca_cfg_post( const cJSON *in, cJSON *out ){
    halow_cca_config_t cfg;
    int v;

    if (in == NULL || !cJSON_IsObject(in) || out == NULL) {
        log_warn("cca_cfg_post bad json");
        return api_err(out, WEB_API_RC_BAD_REQUEST, "bad json");
    }

    halow_cca_config_load(&cfg);

    if (json_get_int(in, "en",     &v)) { cfg.cca_enabled = (v != 0) ? 1u : 0u; }
    { double d; if (json_get_double(in, "ftpct", &d)) { int t = (int)(d * 10.0 + 0.5); if (t >= 1 && t <= 1000) cfg.cca_force_tx_pct = (uint16_t)t; } }
    { double d; if (json_get_double(in, "dlpct", &d)) { int t = (int)(d * 10.0 + 0.5); if (t >= 0 && t <= 1000) cfg.duty_limit_pct = (uint16_t)t; } }
    if (json_get_int(in, "cwmin",  &v)) { if (v >= 1 && v <= 2047) cfg.cw_min = (uint16_t)v; }
    if (json_get_int(in, "cwmax",  &v)) { if (v >= 1 && v <= 2047) cfg.cw_max = (uint16_t)v; }
    if (json_get_int(in, "thdyn",  &v)) { cfg.cca_threshold_dynamic = (v != 0) ? 1u : 0u; }
    if (json_get_int(in, "sens",   &v)) { if (v >= 0 && v <= 10) cfg.cca_sensitivity = (uint8_t)v; }

    halow_cca_config_apply(&cfg);
    halow_cca_config_save(&cfg);

    log_debug("cca_cfg updated");

    return web_api_cca_cfg_get(NULL, out);
}

/* -------------------------------------------------------------------------- */
/* /api/dev_stat + /api/radio_stat (placeholders)                             */
/* -------------------------------------------------------------------------- */

int32_t web_api_dev_stat_get( const cJSON *in, cJSON *out ){
    char s[64];
    const char *hostname = "";
    struct netif *nif;

    (void)in;

    if (out == NULL) {
        return WEB_API_RC_BAD_REQUEST;
    }

    statistics_uptime_get(s, sizeof(s));
    (void)cJSON_AddStringToObject(out, "uptime", s);

    nif = netif_default;
    if (nif != NULL) {
        if (nif->hostname != NULL) {
            hostname = nif->hostname;
        }
        ip4addr_ntoa_r(netif_ip4_addr(nif), s, sizeof(s));
    } else {
        s[0] = '\0';
    }

    (void)cJSON_AddStringToObject(out, "hostname", hostname);
    (void)cJSON_AddStringToObject(out, "ip", s);
    (void)cJSON_AddStringToObject(out, "ver", FW_BUILD_VERSION);

    if (nif != NULL) {
        snprintf(s, sizeof(s),
                 "%02X:%02X:%02X:%02X:%02X:%02X",
                 nif->hwaddr[0],
                 nif->hwaddr[1],
                 nif->hwaddr[2],
                 nif->hwaddr[3],
                 nif->hwaddr[4],
                 nif->hwaddr[5]);
    } else {
        s[0] = '\0';
    }

    (void)cJSON_AddStringToObject(out, "mac", s);

    {
        uint8_t wmac[6];
        get_mac(wmac);
        snprintf(s, sizeof(s),
                 "%02X:%02X:%02X:%02X:%02X:%02X",
                 wmac[0], wmac[1], wmac[2],
                 wmac[3], wmac[4], wmac[5]);
    }
    (void)cJSON_AddStringToObject(out, "wmac", s);

    snprintf(s, sizeof(s), "%d Mbit", flash0.size * 8 / 1024 / 1024);
    (void)cJSON_AddStringToObject(out, "flashs", s);
    
    statistics_cpu_load_get(s, sizeof(s));
    (void)cJSON_AddStringToObject(out, "cpu", s);

    statistics_heap_usage_get(s, sizeof(s));
    (void)cJSON_AddStringToObject(out, "heap", s);

    snprintf(s, sizeof(s), "%d C", (int)tsensor_meas(0));
    (void)cJSON_AddStringToObject(out, "chip_temp", s);

    /* Supply/core rail monitor: brownout or a failing PSU shows up here long
     * before it becomes "the link is flaky". Values come from the throttled
     * ADC wrappers (real conversion at most once per MEAS_REFRESH_MS, cached
     * otherwise) so polling the dashboard never deafens the radio. */
    snprintf(s, sizeof(s), "%.2f V", (double)vcc_meas());
    (void)cJSON_AddStringToObject(out, "vcc", s);
    snprintf(s, sizeof(s), "%.2f V", (double)vdd13b_meas());
    (void)cJSON_AddStringToObject(out, "vdd13b", s);
    snprintf(s, sizeof(s), "%.2f V", (double)vdd13c_meas());
    (void)cJSON_AddStringToObject(out, "vdd13c", s);

    return WEB_API_RC_OK;
}

int32_t web_api_radio_stat_get( const cJSON *in, cJSON *out ){
    statistics_radio_t st;
    double v;
    char buf[32];

    (void)in;

    if (out == NULL) {
        return WEB_API_RC_BAD_REQUEST;
    }

    st = statistics_radio_get();

    /* -------- RX bytes -------- */
    v = (double)st.rx_bytes / 1024.0;   /* KiB */
    if (v < 1024.0) {
        snprintf(buf, sizeof(buf), "%.2f KiB", v);
    } else if (v < 1024.0 * 1024.0) {
        snprintf(buf, sizeof(buf), "%.2f MiB", v / 1024.0);
    } else {
        snprintf(buf, sizeof(buf), "%.2f GiB", v / (1024.0 * 1024.0));
    }
    (void)cJSON_AddStringToObject(out, "rx_bytes", buf);

    /* -------- TX bytes -------- */
    v = (double)st.tx_bytes / 1024.0;   /* KiB */
    if (v < 1024.0) {
        snprintf(buf, sizeof(buf), "%.2f KiB", v);
    } else if (v < 1024.0 * 1024.0) {
        snprintf(buf, sizeof(buf), "%.2f MiB", v / 1024.0);
    } else {
        snprintf(buf, sizeof(buf), "%.2f GiB", v / (1024.0 * 1024.0));
    }
    (void)cJSON_AddStringToObject(out, "tx_bytes", buf);

    /* -------- packets -------- */
    (void)cJSON_AddNumberToObject(out, "rx_packets", (double)st.rx_packets);
    (void)cJSON_AddNumberToObject(out, "tx_packets", (double)st.tx_packets);

    /* -------- speed (kbit/s) -------- */
    v = (double)st.rx_bitps / 1000.0;
    snprintf(buf, sizeof(buf), "%.2f kbit/s", v);
    (void)cJSON_AddStringToObject(out, "rx_speed", buf);

    v = (double)st.tx_bitps / 1000.0;
    snprintf(buf, sizeof(buf), "%.2f kbit/s", v);
    (void)cJSON_AddStringToObject(out, "tx_speed", buf);

    (void)snprintf(buf, sizeof(buf), "%.1f %%", (double)(st.airtime*100.0f));
    (void)cJSON_AddStringToObject(out, "airtime", buf);

    (void)snprintf(buf, sizeof(buf), "%.1f %%", (double)(st.ch_util*100.0f));
    (void)cJSON_AddStringToObject(out, "ch_util", buf);

    (void)snprintf(buf, sizeof(buf), "%.1f dBm", (double)st.bkgnd_noise_dbm);
    (void)cJSON_AddStringToObject(out, "bg_pwr_dbm", buf);
    
    (void)snprintf(buf, sizeof(buf), "%.1f dBm", (double)st.bkgnd_noise_dbm_now);
    (void)cJSON_AddStringToObject(out, "bg_pwr_now_dbm", buf);

    return WEB_API_RC_OK;
}

int32_t web_api_radio_stat_post( const cJSON *in, cJSON *out ){
    (void)in;
    statistics_radio_reset();

    cJSON_AddBoolToObject(out, "reset", 1);
    return WEB_API_RC_OK;
}

/* Diagnostic: TX-path health. Live tx_end/sub_state counters plus the LMAC TX
 * machine snapshot captured the moment a hard wedge was detected (before the
 * purge). The primary tool to root-cause lost TX-completes under saturation
 * without a debugger attached. */
int32_t web_api_tx_dbg_get( const cJSON *in, cJSON *out ){
    halow_tx_dbg_t d;
    cJSON *subs;

    (void)in;
    if (out == NULL) return WEB_API_RC_BAD_REQUEST;

    halow_tx_dbg_get(&d);

    cJSON_AddNumberToObject(out, "tx_end",    (double)d.tx_end_count);
    cJSON_AddNumberToObject(out, "tx_end_err",(double)d.tx_end_err);
    cJSON_AddNumberToObject(out, "tx_tmo",    (double)d.tx_tmo_count);
    cJSON_AddNumberToObject(out, "bo_tmo",    (double)d.bo_tmo_recov);
    cJSON_AddNumberToObject(out, "complete",  (double)d.complete_seq);
    cJSON_AddNumberToObject(out, "wedges",    (double)d.wedge_count);
    /* loss counters: every TX/RX-path drop must be visible somewhere */
    cJSON_AddNumberToObject(out, "tx_drop_budget", (double)d.tx_drop_budget);
    cJSON_AddNumberToObject(out, "tx_drop_alloc",  (double)d.tx_drop_alloc);
    cJSON_AddNumberToObject(out, "tx_drop_lmac",   (double)d.tx_drop_lmac);
    cJSON_AddNumberToObject(out, "rx_frag_drop",   (double)d.rx_frag_drop);
    cJSON_AddNumberToObject(out, "rf_tcp_dropped", (double)d.rf_tcp_dropped);
    cJSON_AddNumberToObject(out, "tx_mcs_bump",    (double)d.tx_mcs_bump);
    cJSON_AddNumberToObject(out, "tx_drop_oversize",(double)d.tx_drop_oversize);
    cJSON_AddNumberToObject(out, "tcps_beat", (double)d.tcps_beat);
    cJSON_AddNumberToObject(out, "tcps_last_err", (double)d.tcps_last_err);
    cJSON_AddNumberToObject(out, "tcps_recv_ok", (double)d.tcps_recv_ok);
    cJSON_AddNumberToObject(out, "tcps_fed", (double)d.tcps_fed);
    cJSON_AddNumberToObject(out, "tcps_held", (double)d.tcps_held);
    /* live machine state */
    cJSON_AddNumberToObject(out, "ac_pd",     (double)d.ac_pd);
    { extern volatile uint32_t g_ack_tick_count;   /* dedicated tick task heartbeat */
      cJSON_AddNumberToObject(out, "tick", (double)g_ack_tick_count); }
    cJSON_AddNumberToObject(out, "budget",    (double)d.budget_live);
    cJSON_AddNumberToObject(out, "bo_ftype",  (double)d.bo_ftype_live);
    cJSON_AddNumberToObject(out, "bo_sub",    (double)d.bo_sub_live);
    cJSON_AddNumberToObject(out, "airtime_x10",  (double)d.airtime_pct_x10);
    cJSON_AddNumberToObject(out, "ch_util_x10",  (double)d.ch_util_pct_x10);
    { cJSON *ql = cJSON_AddArrayToObject(out, "q_live");
      for (uint32_t i = 0; i < 4u; i++) cJSON_AddItemToArray(ql, cJSON_CreateNumber((double)d.q_live[i])); }
    { cJSON *sl = cJSON_AddArrayToObject(out, "sel_live");
      for (uint32_t i = 0; i < 4u; i++) cJSON_AddItemToArray(sl, cJSON_CreateNumber((double)d.sel_live[i])); }
    subs = cJSON_AddArrayToObject(out, "sub");
    for (uint32_t i = 0; i < 8u; i++){
        cJSON_AddItemToArray(subs, cJSON_CreateNumber((double)d.tx_end_sub[i]));
    }
    cJSON_AddNumberToObject(out, "snap_jiffies", (double)d.snap_jiffies);
    cJSON_AddNumberToObject(out, "snap_complete",(double)d.snap_complete_seq);
    cJSON_AddNumberToObject(out, "snap_tx_end",  (double)d.snap_tx_end_count);
    cJSON_AddNumberToObject(out, "snap_budget",  (double)d.snap_budget);
    cJSON_AddNumberToObject(out, "snap_tx_stat", (double)d.snap_tx_stat);
    cJSON_AddNumberToObject(out, "snap_fsm",    (double)d.snap_fsm);
    cJSON_AddNumberToObject(out, "snap_comn",   (double)d.snap_comn);
    cJSON_AddNumberToObject(out, "snap_irqpd",  (double)d.snap_irqpd);
    cJSON_AddNumberToObject(out, "snap_bocnt",  (double)d.snap_bocnt);
    cJSON_AddNumberToObject(out, "snap_ac",      (double)d.snap_ac);
    cJSON_AddNumberToObject(out, "snap_sub",     (double)d.snap_sub);
    cJSON_AddNumberToObject(out, "snap_bo_ftype",(double)d.snap_bo_ftype);
    cJSON_AddNumberToObject(out, "snap_flags",   (double)d.snap_ctrl_flags);
    cJSON *q = cJSON_AddArrayToObject(out, "snap_q");
    for (uint32_t i = 0; i < 4u; i++){
        cJSON_AddItemToArray(q, cJSON_CreateNumber((double)d.snap_q_ac[i]));
    }
    cJSON *s = cJSON_AddArrayToObject(out, "snap_sel");
    for (uint32_t i = 0; i < 4u; i++){
        cJSON_AddItemToArray(s, cJSON_CreateNumber((double)d.snap_sel[i]));
    }
    return WEB_API_RC_OK;
}

int32_t web_api_rf_dbg_get( const cJSON *in, cJSON *out ){
    extern void lmac_rx_gain_cfg(uint32 gain);
    cJSON *refs;
    uint8_t *ctx = (uint8_t *)&ah_lmac;

    (void)in;
    if (out == NULL) return WEB_API_RC_BAD_REQUEST;

    cJSON_AddNumberToObject(out, "agc_info_704", (double)ah_lmac.tx_state_704);
    cJSON_AddBoolToObject(out, "agc_auto", (ah_lmac.cca_agc_ctrl_flags & 0x08u) ? 1 : 0);
        cJSON_AddNumberToObject(out, "gain_live", (double)((ah_lmac.rx_gain_cfg_bits & 0x7ffu) >> 4));
    cJSON_AddNumberToObject(out, "rx_gain_cfg_bits", (double)ah_lmac.rx_gain_cfg_bits);
    cJSON_AddNumberToObject(out, "cca_agc_ctrl_flags", (double)ah_lmac.cca_agc_ctrl_flags);
    cJSON_AddNumberToObject(out, "cca_ctrl_low_byte", (double)ah_lmac.cca_ctrl_low_byte);
    cJSON_AddNumberToObject(out, "hw_0x308", (double)ctx[0x308]);
    cJSON_AddNumberToObject(out, "agc_th_high", (double)ah_lmac.agc_threshold_high);
    cJSON_AddNumberToObject(out, "agc_th_low", (double)ah_lmac.agc_threshold_low);
    cJSON_AddNumberToObject(out, "cca_th_base", (double)ah_lmac.cca_threshold_base);
    cJSON_AddNumberToObject(out, "cca_th_offset", (double)ah_lmac.cca_threshold_offset);
    cJSON_AddNumberToObject(out, "cca_th_max", (double)ah_lmac.cca_threshold_max);
    cJSON_AddNumberToObject(out, "bss_bw", (double)ah_lmac.bss_bw);
    refs = cJSON_AddArrayToObject(out, "bknoise_gain_ref");
    for (uint32_t i = 0; i < 6u; i++){
        cJSON_AddItemToArray(refs, cJSON_CreateNumber((double)ah_lmac.bknoise_gain_ref[i]));
    }
    cJSON_AddNumberToObject(out, "bknoise_base_offset", (double)ah_lmac.bknoise_base_offset);
    cJSON_AddNumberToObject(out, "noise_short_dbm", (double)halow_lbt_background_short_dbm_get());
    cJSON_AddNumberToObject(out, "noise_floor_dbm", (double)halow_lbt_background_long_dbm_get());
        { int16_t cfo_raw; int8_t cfo_div;
      memcpy(&cfo_raw, &ctx[0x14C], sizeof(cfo_raw));
      memcpy(&cfo_div, &ctx[0x8B8], sizeof(cfo_div));
      cJSON_AddNumberToObject(out, "rx_cfo_raw", (double)cfo_raw);
      cJSON_AddNumberToObject(out, "rx_cfo_div1000", (double)cfo_div); }
        { uint32_t rx_err, rx_last_err, rx_good, rx_dur;
      memcpy(&rx_err, &ctx[0x788], sizeof(rx_err));
      memcpy(&rx_last_err, &ctx[0x78C], sizeof(rx_last_err));
      memcpy(&rx_good, &ctx[0x73C], sizeof(rx_good));
      memcpy(&rx_dur, &ctx[0x76C], sizeof(rx_dur));
      cJSON_AddNumberToObject(out, "rx_phy_err", (double)rx_err);
      cJSON_AddNumberToObject(out, "rx_last_wphy_err", (double)rx_last_err);
      cJSON_AddNumberToObject(out, "rx_good_frames", (double)rx_good);
      cJSON_AddNumberToObject(out, "rx_dur_acc", (double)rx_dur); }
        { extern volatile uint32_t g_rx_cls_internal, g_rx_cls_notmine, g_rx_cls_data;
      extern volatile uint8_t g_rx_cap[8][16];
      cJSON_AddNumberToObject(out, "rx_cls_internal", (double)g_rx_cls_internal);
      cJSON_AddNumberToObject(out, "rx_cls_notmine", (double)g_rx_cls_notmine);
      cJSON_AddNumberToObject(out, "rx_cls_data", (double)g_rx_cls_data);
      cJSON *cap = cJSON_AddArrayToObject(out, "rx_cap_hex");
      for (uint32_t i = 0; i < 8u; i++) {
          char hex[33];
          for (uint32_t j = 0; j < 16u; j++) {
              sprintf(&hex[j * 2], "%02x", g_rx_cap[i][j]);
          }
          hex[32] = '\0';
          cJSON_AddItemToArray(cap, cJSON_CreateString(hex));
      } }
    { int32_t debris = 0, prod = 0, base = 0;
      halow_gain_pilot_dbg(&debris, &prod, &base);
      cJSON_AddNumberToObject(out, "gain_pilot_en", halow_gain_pilot_enabled() ? 1 : 0);
      cJSON_AddNumberToObject(out, "gain_pilot_state", (double)halow_gain_pilot_state());
      cJSON_AddNumberToObject(out, "gain_pilot_debris_x", (double)debris);
      cJSON_AddNumberToObject(out, "gain_pilot_prod_x", (double)prod);
      cJSON_AddNumberToObject(out, "gain_pilot_base_x", (double)base); }
    return WEB_API_RC_OK;
}

int32_t web_api_rf_dbg_post( const cJSON *in, cJSON *out ){
    extern void lmac_rx_gain_cfg(uint32 gain);
    int v;
    const cJSON *j;

    if (in == NULL || !cJSON_IsObject(in) || out == NULL) {
        return api_err(out, WEB_API_RC_BAD_REQUEST, "bad json");
    }

    j = cJSON_GetObjectItemCaseSensitive(in, "agc_th_high");
    if (j != NULL && cJSON_IsNumber(j)) {
        int hi = (int)j->valuedouble;
        if (hi < -128) hi = -128;
        if (hi > 127) hi = 127;
        ah_lmac.agc_threshold_high = (int8_t)hi;
    }
    j = cJSON_GetObjectItemCaseSensitive(in, "agc_th_low");
    if (j != NULL && cJSON_IsNumber(j)) {
        int lo = (int)j->valuedouble;
        if (lo < -128) lo = -128;
        if (lo > 127) lo = 127;
        ah_lmac.agc_threshold_low = (int8_t)lo;
    }

    return web_api_rf_dbg_get(NULL, out);
}

/* Diagnostic: per-task runtime breakdown over the interval since the last
 * os_task_runtime read (shared with get_stat via cpu_loading_tick). Used to find
 * which task(s) burn idle CPU so we can target them instead of guessing. */
int32_t web_api_cpu_dump_get( const cJSON *in, cJSON *out ){
    extern __bobj uint64 cpu_loading_tick;
    /* static: 16*28 = 448 B -- a third of the old httpd stack; only this
     * handler (httpd task) touches it, and pollers hit this endpoint often */
    static struct os_task_info tsk[16];
    int32_t i, count;
    uint64 jiff = os_jiffies();
    uint32_t diff = DIFF_JIFFIES(cpu_loading_tick, jiff);
    uint32_t sum_pct = 0u;
    cJSON *arr;

    (void)in;
    if (out == NULL) return WEB_API_RC_BAD_REQUEST;

    cpu_loading_tick = jiff;
    count = os_task_runtime(tsk, 16);
    if (diff == 0u) diff = 1u;

    arr = cJSON_CreateArray();
    for (i = 0; i < count; i++){
        uint32_t pct = (tsk[i].time * 100u) / diff;
        cJSON *o = cJSON_CreateObject();
        sum_pct += pct;
        cJSON_AddStringToObject(o, "name", tsk[i].name ? (const char *)tsk[i].name : (const char *)"----");
        cJSON_AddNumberToObject(o, "pct", (double)pct);
        cJSON_AddNumberToObject(o, "ms", (double)tsk[i].time);
        cJSON_AddNumberToObject(o, "prio", (double)tsk[i].prio);
        cJSON_AddItemToArray(arr, o);
    }
    cJSON_AddItemToObject(out, "tasks", arr);
    cJSON_AddNumberToObject(out, "interval_ms", (double)diff);
    cJSON_AddNumberToObject(out, "sum_task_pct", (double)sum_pct);
    return WEB_API_RC_OK;
}

int32_t web_api_online_ota_get( const cJSON *in, cJSON *out ){
    return 0;
}

int32_t web_api_online_ota_post( const cJSON *in, cJSON *out ){
    return 0;
}

int32_t web_api_stat_get( const cJSON *in, cJSON *out ){
    cJSON *dev   = NULL;
    cJSON *radio = NULL;
    int32_t rc;

    (void)in;

    if (out == NULL) {
        return WEB_API_RC_BAD_REQUEST;
    }

    dev   = cJSON_CreateObject();
    radio = cJSON_CreateObject();

    if (!dev || !radio) {
        rc = WEB_API_RC_INTERNAL;
        goto fail;
    }

    rc = web_api_dev_stat_get(NULL, dev);
    if (rc != WEB_API_RC_OK) goto fail;

    rc = web_api_radio_stat_get(NULL, radio);
    if (rc != WEB_API_RC_OK) goto fail;

    cJSON_AddItemToObject(out, "device", dev);    dev = NULL;
    cJSON_AddItemToObject(out, "radio",  radio);  radio = NULL;

    return WEB_API_RC_OK;

fail:
    cJSON_Delete(dev);
    cJSON_Delete(radio);
    return rc;
}

int32_t web_api_telemetry_cfg_get( const cJSON *in, cJSON *out ){
    telemetry_config_t cfg;
    char lxmf_hex[33];

    (void)in;

    if (out == NULL) {
        return WEB_API_RC_BAD_REQUEST;
    }

    telemetry_config_load(&cfg);

    cJSON_AddBoolToObject(out, "en",  cfg.enabled);
    cJSON_AddBoolToObject(out, "ext", cfg.extended_enabled);
    cJSON_AddNumberToObject(out, "prd",  (double)cfg.send_period_s);
    cJSON_AddStringToObject(out, "host", cfg.domain);
    cJSON_AddNumberToObject(out, "port", (double)cfg.port);
    cJSON_AddNumberToObject(out, "lat", cfg.latitude);
    cJSON_AddNumberToObject(out, "lon", cfg.longitude);
    cJSON_AddBoolToObject(out, "dir_en", cfg.directional);
    cJSON_AddNumberToObject(out, "dir",  (double)cfg.direction);
    cJSON_AddStringToObject(out, "usr", cfg.username);
    cJSON_AddStringToObject(out, "pwd", cfg.password);
    cJSON_AddStringToObject(out, "top", cfg.topic);
    cJSON_AddStringToObject(out, "name", cfg.nodename);

    bin16_to_hex32(cfg.lxmf, lxmf_hex);
    cJSON_AddStringToObject(out, "lxmf", lxmf_hex);

    return WEB_API_RC_OK;
}

int32_t web_api_telemetry_cfg_post( const cJSON *in, cJSON *out ){
    telemetry_config_t cfg;
    bool b;
    int v;
    float f;
    char lxmf_hex[33];

    if (in == NULL || !cJSON_IsObject(in) || out == NULL) {
        log_warn("telemetry_cfg_post bad json");
        return api_err(out, WEB_API_RC_BAD_REQUEST, "bad json");
    }

    telemetry_config_load(&cfg);

    if (json_get_bool(in, "en", &b))      { cfg.enabled = b ? 1 : 0; }
    if (json_get_bool(in, "ext", &b))     { cfg.extended_enabled = b ? 1 : 0; }

    if (json_get_int(in, "prd", &v))      { if (v >= 1) cfg.send_period_s = (uint32_t)v; }
    if (json_get_int(in, "port", &v))     { if (v >= 0 && v <= 65535) cfg.port = (uint16_t)v; }

    if (json_get_float(in, "lat", &f))    { cfg.latitude = f; }
    if (json_get_float(in, "lon", &f))    { cfg.longitude = f; }

    if (json_get_bool(in, "dir_en", &b))  { cfg.directional = b ? 1 : 0; }
    if (json_get_int(in, "dir", &v))      { if (v >= -32768 && v <= 32767) cfg.direction = (int16_t)v; }

    (void)json_get_string(in, "host", cfg.domain,   sizeof(cfg.domain));
    (void)json_get_string(in, "usr",  cfg.username, sizeof(cfg.username));
    (void)json_get_string(in, "pwd",  cfg.password, sizeof(cfg.password));
    (void)json_get_string(in, "top",  cfg.topic,    sizeof(cfg.topic));
    (void)json_get_string(in, "name", cfg.nodename, sizeof(cfg.nodename));

    if (json_get_string(in, "lxmf", lxmf_hex, sizeof(lxmf_hex))) {
        if (strlen(lxmf_hex) == 32) {
            (void)hex32_to_bin16(lxmf_hex, cfg.lxmf);
        }
    }

    telemetry_config_save(&cfg);

    /* Toggling telemetry on must take effect immediately, not after the next
     * reboot: schedule the worker like telemetry_init does on boot. */
    if (cfg.enabled) {
        extern void telemetry_kick( void );
        telemetry_kick();
    }

    log_debug("telemetry_cfg updated en=%d ext=%d prd=%lu port=%u",
              cfg.enabled ? 1 : 0,
              cfg.extended_enabled ? 1 : 0,
              (unsigned long)cfg.send_period_s,
              (unsigned)cfg.port);

    return web_api_telemetry_cfg_get(NULL, out);
}

int32_t web_api_telemetry_send_post( const cJSON *in, cJSON *out ){
    (void)in;
    (void)out;

    log_debug("telemetry_send");
    telemetry_send_now();
    return 0;
}

int32_t web_api_reset_to_default_post( const cJSON *in, cJSON *out ){
    return 0;
}

int32_t web_api_all_get( const cJSON *in, cJSON *out ){
    cJSON *halow = NULL;
    cJSON *net   = NULL;
    cJSON *tcp   = NULL;
    cJSON *lbt   = NULL;
    cJSON *cca   = NULL;
    cJSON *ota   = NULL;
    cJSON *slip  = NULL;
    cJSON *log   = NULL;

    cJSON *stat  = NULL;
    cJSON *dev   = NULL;
    cJSON *radio = NULL;
    cJSON *telemetry = NULL;

    int32_t rc;

    (void)in;

    if (out == NULL) {
        return WEB_API_RC_BAD_REQUEST;
    }

    halow = cJSON_CreateObject();
    net   = cJSON_CreateObject();
    tcp   = cJSON_CreateObject();
    lbt   = cJSON_CreateObject();
    cca   = cJSON_CreateObject();
    ota   = cJSON_CreateObject();
    slip  = cJSON_CreateObject();
    log   = cJSON_CreateObject();

    stat  = cJSON_CreateObject();
    dev   = cJSON_CreateObject();
    radio = cJSON_CreateObject();
    telemetry = cJSON_CreateObject();

    if (!halow || !net || !tcp || !lbt || !cca || !ota || !slip || !log || !telemetry || !stat || !dev || !radio) {
        rc = WEB_API_RC_INTERNAL;
        goto fail;
    }

    rc = web_api_halow_cfg_get(NULL, halow);
    if (rc != WEB_API_RC_OK) goto fail;

    rc = web_api_net_cfg_get(NULL, net);
    if (rc != WEB_API_RC_OK) goto fail;

    rc = web_api_tcp_server_cfg_get(NULL, tcp);
    if (rc != WEB_API_RC_OK) goto fail;

    rc = web_api_lbt_cfg_get(NULL, lbt);
    if (rc != WEB_API_RC_OK) goto fail;

    rc = web_api_cca_cfg_get(NULL, cca);
    if (rc != WEB_API_RC_OK) goto fail;

    rc = web_api_online_ota_get(NULL, ota);
    if (rc != WEB_API_RC_OK) goto fail;

    rc = web_api_slip_cfg_get(NULL, slip);
    if (rc != WEB_API_RC_OK) goto fail;

    rc = web_api_log_cfg_get(NULL, log);
    if (rc != WEB_API_RC_OK) goto fail;

    rc = web_api_dev_stat_get(NULL, dev);
    if (rc != WEB_API_RC_OK) goto fail;

    rc = web_api_radio_stat_get(NULL, radio);
    if (rc != WEB_API_RC_OK) goto fail;

    rc = web_api_telemetry_cfg_get(NULL, telemetry);
    if (rc != WEB_API_RC_OK) goto fail;

    cJSON_AddItemToObject(stat, "device", dev);    dev = NULL;
    cJSON_AddItemToObject(stat, "radio",  radio);  radio = NULL;

    cJSON_AddItemToObject(out, "halow", halow);   halow = NULL;
    cJSON_AddItemToObject(out, "net",   net);     net   = NULL;
    cJSON_AddItemToObject(out, "tcp",   tcp);     tcp   = NULL;
    cJSON_AddItemToObject(out, "lbt",   lbt);     lbt   = NULL;
    cJSON_AddItemToObject(out, "cca",   cca);     cca   = NULL;
    cJSON_AddItemToObject(out, "ota",   ota);     ota   = NULL;
    cJSON_AddItemToObject(out, "slip",  slip);    slip  = NULL;
    cJSON_AddItemToObject(out, "log",   log);     log   = NULL;
    cJSON_AddItemToObject(out, "telemetry", telemetry); telemetry = NULL;

    cJSON_AddItemToObject(out, "stat",  stat);    stat  = NULL;

    return WEB_API_RC_OK;

fail:
    cJSON_Delete(halow);
    cJSON_Delete(net);
    cJSON_Delete(tcp);
    cJSON_Delete(lbt);
    cJSON_Delete(cca);
    cJSON_Delete(ota);
    cJSON_Delete(slip);
    cJSON_Delete(log);

    cJSON_Delete(stat);
    cJSON_Delete(dev);
    cJSON_Delete(radio);
    cJSON_Delete(telemetry);
    return rc;
}

int32_t web_api_reboot_post( const cJSON *in, cJSON *out ){
    (void)in;

    if( ota_fw_active() || ota_wota_active() ){
        return api_err(out, WEB_API_RC_BAD_REQUEST, "ota active");
    }
    log_warn("api reboot");
    device_reboot();
    return 0;
}

int32_t web_api_default_reset( const cJSON *in, cJSON *out ){
    (void)in;

    if( ota_fw_active() || ota_wota_active() ){
        return api_err(out, WEB_API_RC_BAD_REQUEST, "ota active");
    }
    log_warn("api default reset");
    ota_reset_to_default();
    device_reboot();
    return 0;
}

int32_t web_api_nearby_modems_get( const cJSON *in, cJSON *out ){
    cJSON *arr = NULL;
    cJSON *row = NULL;
    nearby_modem_t *m;
    uint32_t i;

    (void)in;

    if (out == NULL) {
        return WEB_API_RC_BAD_REQUEST;
    }

    halow_config_t hcfg;
    halow_config_load(&hcfg);
    uint8_t default_tx_mcs = hcfg.mcs;
    int32_t now_s = (int32_t)time(NULL);

    /* Each row is a self-describing JSON object describing ONE peer MAC, built
     * by projecting two complementary MAC-keyed stores into a single view:
     *   - nearby_modem_db : RX discovery (rssi/snr/rx-mcs + RX counters)
     *   - halow_ack_peers : TX session   (tx-mcs/evm + TX counters + RA state)
     * has_rx/has_tx flag which halves are valid so the UI can render "--" for
     * the missing direction (a heard-only neighbour has no TX stats and vice
     * versa). Field names use rx_/tx_ prefixes to mirror rns_link_db_link_t
     * (rx_bytes/tx_bytes/lastrx...); the schema is documented here in one place
     * so adding a field never requires syncing positional indices. */
    arr = cJSON_AddArrayToObject(out, "d");
    if (arr == NULL) {
        return WEB_API_RC_INTERNAL;
    }

    for (i = 0; i < nearby_modem_count_get(); i++) {
        m = nearby_modem_get_by_index(i);
        if (m == NULL) {
            continue;
        }

        char mac[13];
        snprintf(mac, sizeof(mac), "%02X%02X%02X%02X%02X%02X",
                 m->mac[0], m->mac[1], m->mac[2],
                 m->mac[3], m->mac[4], m->mac[5]);

        row = cJSON_CreateObject();
        if (row == NULL) {
            return WEB_API_RC_INTERNAL;
        }
        cJSON_AddStringToObject(row, "mac", mac);

        /* ---- RX half (always present: this row comes from nearby) ---- */
        cJSON_AddBoolToObject(row, "has_rx", 1);
        cJSON_AddNumberToObject(row, "rx_rssi",   (double)m->last_rssi);
        cJSON_AddNumberToObject(row, "rx_snr",    (double)m->last_snr);
        cJSON_AddNumberToObject(row, "rx_mcs",    (double)m->mcs);
        cJSON_AddNumberToObject(row, "rx_bytes",  (double)m->rx_bytes);
        cJSON_AddNumberToObject(row, "rx_packets",(double)m->rx_packets);
        cJSON_AddNumberToObject(row, "rx_last_age",
                                (double)(now_s - m->lastrx_timestamp_s));

        /* ---- TX half (overlay; absent for a heard-only neighbour) ---- */
        halow_ack_peer_stats_t ps;
        bool has_peer = halow_ack_peer_stats_by_mac(m->mac, &ps);
        /* has_tx = we have actually transmitted data to this peer (not merely
         * created an ack_peer slot by hearing them, which the RX path also
         * does for ACK coalescing). Without this distinction every heard
         * neighbour would show a misleading "TX Loss 0% / 0 bytes" row. */
        bool has_tx = has_peer && (ps.tx_frames > 0u || ps.last_tx_s > 0);
        cJSON_AddBoolToObject(row, "has_tx", has_tx ? 1 : 0);
        /* Always emit the TX keys so the UI has stable shape; zeros/-- when the
         * peer has no TX session. tx_mcs resolves the RA "default" sentinel to
         * the configured default so the UI can render a concrete number. */
        uint8_t tx_mcs = has_tx ? ((ps.tx_mcs == HALOW_MCS_DEFAULT) ? default_tx_mcs : ps.tx_mcs)
                                : default_tx_mcs;
        cJSON_AddNumberToObject(row, "tx_mcs",          (double)tx_mcs);
        cJSON_AddNumberToObject(row, "compat",          (double)ps.compat);
        cJSON_AddNumberToObject(row, "l0_falls",        (double)ps.l0_falls);
        cJSON_AddNumberToObject(row, "tx_evm",          (double)(has_tx ? ps.evm : 0));
        cJSON_AddNumberToObject(row, "tx_frames",       (double)(has_tx ? ps.tx_frames : 0));
        cJSON_AddNumberToObject(row, "tx_bytes",        (double)(has_tx ? ps.tx_bytes : 0));
        cJSON_AddNumberToObject(row, "tx_acked",        (double)(has_tx ? ps.acked : 0));
        cJSON_AddNumberToObject(row, "tx_dropped",      (double)(has_tx ? ps.dropped : 0));
        cJSON_AddNumberToObject(row, "tx_retransmitted",(double)(has_tx ? ps.retransmitted : 0));
        cJSON_AddNumberToObject(row, "tx_last_age",
                                (double)((has_tx && ps.last_tx_s > 0)
                                         ? (now_s - ps.last_tx_s) : -1));
        /* TX loss AFTER retries (windowed IIR): share of resolved frames
         * (ACKed or retry-exhausted) that ultimately failed. The per-attempt
         * RF loss stays derivable via tx_retransmitted/(tx_frames+
         * tx_retransmitted); the RA EWMA (loss_q8) is the MCS-tuning
         * counter, separate by design. */
        cJSON_AddNumberToObject(row, "tx_loss_pct", (double)(has_tx ? ps.loss_pct : 0));

        cJSON_AddItemToArray(arr, row);
    }

    uint8_t wifi_mac[6];
    char s[18];
    mac_generator_get(wifi_mac);
    snprintf(s, sizeof(s), "%02X:%02X:%02X:%02X:%02X:%02X",
                wifi_mac[0], wifi_mac[1], wifi_mac[2],
                wifi_mac[3], wifi_mac[4], wifi_mac[5]);
    cJSON_AddStringToObject(out, "m", s);
    cJSON_AddNumberToObject(out, "tx_mcs", (double)default_tx_mcs);

    return WEB_API_RC_OK;
}

int32_t web_api_rns_mtu_cfg_get( const cJSON *in, cJSON *out ){
    (void)in;
    if (out == NULL) return WEB_API_RC_BAD_REQUEST;
    (void)cJSON_AddNumberToObject(out, "mtu", (double)rns_mtu_limit_get());
    return WEB_API_RC_OK;
}

int32_t web_api_rns_mtu_cfg_post( const cJSON *in, cJSON *out ){
    int v;
    if (json_get_int(in, "mtu", &v)) {
        /* Server-side clamp mirroring the UI: a scripted mtu=0 advertised 0 to
         * the peer and a negative value wrapped to ~65535 (limit disabled). */
        if (v >= 500 && v <= 2048) {
            rns_mtu_limit_set((int16_t)v);
        }else{
            log_warn("rns_mtu post out of range (%d), ignored", v);
        }
    }

    return web_api_rns_mtu_cfg_get(NULL, out);
}

int32_t web_api_ack_cfg_get( const cJSON *in, cJSON *out ){
    halow_ack_config_t cfg;
    (void)in;
    if (out == NULL) return WEB_API_RC_BAD_REQUEST;
    halow_ack_config_get_live(&cfg);
    cJSON_AddNumberToObject(out, "retries",  (double)cfg.max_retries);
    cJSON_AddNumberToObject(out, "timeout_ms", (double)cfg.timeout_ms);
    cJSON_AddNumberToObject(out, "rate_adapt", (double)cfg.rate_adapt);
    cJSON_AddNumberToObject(out, "ra_loss_up",   (double)cfg.ra_loss_up);
    cJSON_AddNumberToObject(out, "ra_loss_down", (double)cfg.ra_loss_down);
    cJSON_AddNumberToObject(out, "window",   (double)cfg.window);
    cJSON_AddNumberToObject(out, "fids",     (double)cfg.ack_fids);
    cJSON_AddNumberToObject(out, "agg",      (double)cfg.agg);
    cJSON_AddNumberToObject(out, "agg_bytes",   (double)cfg.agg_bytes);
    cJSON_AddNumberToObject(out, "agg_hold_ms", (double)cfg.agg_hold_ms);
    cJSON_AddNumberToObject(out, "ack_hold_ms", (double)cfg.ack_hold_ms);
    cJSON_AddNumberToObject(out, "gap_ms",      (double)cfg.data_gap_ms);
    cJSON_AddNumberToObject(out, "bc_repeat", (double)cfg.bc_repeat);
    cJSON_AddNumberToObject(out, "env",       (double)cfg.env);
#ifdef FW_BUILD_BETA
    {
        halow_ack_stats_t st;
        halow_ack_stats_get(&st);
        cJSON_AddNumberToObject(out, "tx_frames",  (double)st.tx_frames);
        cJSON_AddNumberToObject(out, "acked",      (double)st.acked);
        cJSON_AddNumberToObject(out, "retransmitted", (double)st.retransmitted);
        cJSON_AddNumberToObject(out, "dropped",    (double)st.dropped);
        cJSON_AddNumberToObject(out, "acks_sent",  (double)st.acks_sent);
        cJSON_AddNumberToObject(out, "ack_mcs",    (double)st.ack_mcs_last);
        cJSON_AddNumberToObject(out, "acks_tx_fail",(double)st.acks_tx_fail);
        cJSON_AddNumberToObject(out, "acks_rx_dup",(double)st.acks_rx_dup);
        cJSON_AddNumberToObject(out, "acks_rx_frames",(double)st.acks_rx_frames);
        cJSON_AddNumberToObject(out, "drop_deadline",(double)st.drop_deadline);
        cJSON_AddNumberToObject(out, "drop_exhaust",(double)st.drop_exhaust);
        cJSON_AddNumberToObject(out, "drop_throttle",(double)st.drop_throttle);
        cJSON_AddNumberToObject(out, "drop_agg_full",(double)st.drop_agg_full);
        cJSON_AddNumberToObject(out, "drop_plain_vac",(double)st.drop_plain_vac);
        cJSON_AddNumberToObject(out, "drop_plain_slot",(double)st.drop_plain_slot);
        cJSON_AddNumberToObject(out, "env_tx_bundles",(double)st.env_tx_bundles);
        cJSON_AddNumberToObject(out, "env_rx_bundles",(double)st.env_rx_bundles);
        cJSON_AddNumberToObject(out, "env_tx_acks",   (double)st.env_tx_acks);
        cJSON_AddNumberToObject(out, "env_rx_acks",   (double)st.env_rx_acks);
        cJSON_AddNumberToObject(out, "rx_env_unk",    (double)st.rx_env_unk);
        cJSON_AddNumberToObject(out, "ack_rtt_avg_ms",
            st.ack_rtt_hits ? (double)(st.ack_rtt_sum_ms / st.ack_rtt_hits) : 0.0);
        cJSON_AddNumberToObject(out, "ack_rtt_hits", (double)st.ack_rtt_hits);
        cJSON_AddNumberToObject(out, "noack_hits", (double)st.noack_hits);
        cJSON_AddNumberToObject(out, "last_evm",   (double)st.last_evm);
        cJSON_AddNumberToObject(out, "peers",      (double)st.peers);
        cJSON_AddNumberToObject(out, "outstanding",(double)st.outstanding);
        cJSON_AddNumberToObject(out, "ra_ack_calls",   (double)st.ra_ack_calls);
        cJSON_AddNumberToObject(out, "ra_upshifts",    (double)st.ra_upshifts);
        cJSON_AddNumberToObject(out, "ra_downshifts",  (double)st.ra_downshifts);
        cJSON_AddNumberToObject(out, "ra_blk_loss",    (double)st.ra_blocked_loss);
        cJSON_AddNumberToObject(out, "ra_blk_gap",     (double)st.ra_blocked_gap);
        cJSON_AddNumberToObject(out, "ra_blk_max",     (double)st.ra_blocked_max);
        cJSON_AddNumberToObject(out, "bc_repeats",     (double)st.bc_repeats);
    }
#endif
    return WEB_API_RC_OK;
}

int32_t web_api_ack_cfg_post( const cJSON *in, cJSON *out ){
    halow_ack_config_t cfg;
    int v;
    if (in == NULL) return WEB_API_RC_BAD_REQUEST;
    halow_ack_config_get_live(&cfg);
    /* Deliberately narrow surface: only user-meaningful knobs are settable
     * (retries, aggregation on/off, RA). Timing/window/ACK-shape parameters are
     * firmware-tuned internals -- accepting them here once let a debug POST
     * (ra=0/tmo=200/window=4/aggbytes=2000) silently live in configdb and pin
     * MCS to 1 for days. agg_bytes is always max; the per-MCS runtime cap in
     * halow_ack_eff_agg_bytes does the real sizing. */
    if (json_get_int(in, "retries",  &v)) { if (v >= 0 && v <= 8) cfg.max_retries = (uint8_t)v; }
    if (json_get_int(in, "rate_adapt", &v)) { cfg.rate_adapt = (uint8_t)(v ? 1u : 0u); }
    if (json_get_int(in, "ra_loss_up",   &v)) { if (v >= 0 && v <= 100) cfg.ra_loss_up   = (uint8_t)v; }
    if (json_get_int(in, "ra_loss_down", &v)) { if (v >= 0 && v <= 100) cfg.ra_loss_down = (uint8_t)v; }
    if (json_get_int(in, "agg",    &v)) { cfg.agg = (uint8_t)(v ? 1u : 0u); }
    /* window: accepted again (clamped hard) -- the measured ACK RTT under
     * bidir load is ~220 ms, so window 8 caps acceptance at ~36 fps and the
     * THROTTLE losses scale with offered load. 10-12 slots break the
     * self-sustaining backlog; heap allows ~16 max (7.7 KB/slot). */
    if (json_get_int(in, "window", &v)) { if (v >= 4 && v <= 16) cfg.window = (uint8_t)v; }
    if (json_get_int(in, "fids",   &v)) { if (v >= 1 && v <= 32) cfg.ack_fids  = (uint8_t)v; }
    if (json_get_int(in, "bc_repeat", &v)) { if (v >= 1 && v <= HALOW_ACK_BC_REPEAT_MAX) cfg.bc_repeat = (uint8_t)v; }
    if (json_get_int(in, "env",       &v)) { cfg.env = (uint8_t)(v ? 1u : 0u); }   /* 0 = force legacy formats (interop test gate) */
    if (json_get_int(in, "gap_ms",      &v)) { if (v >= 0 && v <= 250) cfg.data_gap_ms = (uint16_t)v; }
    if (json_get_int(in, "agg_hold_ms", &v)) { if (v >= 1 && v <= 100) cfg.agg_hold_ms  = (uint16_t)v; }
    if (json_get_int(in, "ack_hold_ms", &v)) { if (v >= 0 && v <= 100) cfg.ack_hold_ms  = (uint16_t)v; }
    halow_ack_config_apply(&cfg);
    return web_api_ack_cfg_get(NULL, out);
}

int32_t web_api_privacy_cfg_get( const cJSON *in, cJSON *out ){
    mac_generator_config_t cfg;
    (void)in;
    if (out == NULL) return WEB_API_RC_BAD_REQUEST;
    mac_generator_config_load(&cfg);
    cJSON_AddNumberToObject(out, "rotation", (double)cfg.rotation_minutes);
    cJSON_AddBoolToObject(out, "broadcast", cfg.broadcast_mac);
    return WEB_API_RC_OK;
}

int32_t web_api_privacy_cfg_post( const cJSON *in, cJSON *out ){
    mac_generator_config_t cfg;
    (void)out;
    if (in == NULL) return WEB_API_RC_BAD_REQUEST;
    mac_generator_config_load(&cfg);
    const cJSON *j;
    j = cJSON_GetObjectItem(in, "rotation");
    if (j && cJSON_IsNumber(j)) {
        int32_t r = (int32_t)j->valuedouble;
        if (r < 0) r = 0;
        if (r > 10080) r = 10080;   /* cap at a week; negative used to wrap to ~65535 min */
        cfg.rotation_minutes = (uint16_t)r;
    }
    j = cJSON_GetObjectItem(in, "broadcast");
    if (j && cJSON_IsBool(j)) cfg.broadcast_mac = (uint8_t)cJSON_IsTrue(j);
    mac_generator_config_save(&cfg);
    mac_generator_config_apply(&cfg);

    return WEB_API_RC_OK;
}

int32_t web_api_reticulum_links_get( const cJSON *in, cJSON *out ){
    cJSON *arr;
    cJSON *row;
    rns_link_db_link_t link;
    char id_hex[RNS_LINK_ID_LEN * 2 + 1];
    char dest_hex[RNS_TRUNCATED_HASH_LEN * 2 + 1];
    char mac_str[18];
    uint8_t count;
    uint8_t i;
    uint8_t j;

    extern volatile uint32_t g_dbg_rns_rx_calls;
    extern volatile uint32_t g_dbg_rns_rx_parse_fail;
    extern volatile uint32_t g_dbg_rns_rx_valid;
    extern volatile uint32_t g_dbg_rns_rx_reg_ok;
    extern volatile uint32_t g_dbg_rns_rx_reg_fail;

    (void)in;

    if (out == NULL) {
        return WEB_API_RC_BAD_REQUEST;
    }

    arr = cJSON_AddArrayToObject(out, "d");
    if (arr == NULL) {
        return WEB_API_RC_INTERNAL;
    }

    cJSON_AddNumberToObject(out, "rx_calls", (double)g_dbg_rns_rx_calls);
    cJSON_AddNumberToObject(out, "rx_parse_fail", (double)g_dbg_rns_rx_parse_fail);
    cJSON_AddNumberToObject(out, "rx_valid", (double)g_dbg_rns_rx_valid);
    cJSON_AddNumberToObject(out, "rx_reg_ok", (double)g_dbg_rns_rx_reg_ok);
    cJSON_AddNumberToObject(out, "rx_reg_fail", (double)g_dbg_rns_rx_reg_fail);
    { extern volatile uint32_t g_dbg_rns_tx_parse_fail;
      cJSON_AddNumberToObject(out, "tx_parse_fail", (double)g_dbg_rns_tx_parse_fail); }

    /* Dump every known Reticulum link with the learned neighbour MAC, state and
     * per-direction counters — the primary way to verify (over HTTP, without
     * UART) that links are registered and peer MACs are being learned. */
    count = rns_link_db_link_count_get();
    for (i = 0; i < count; i++) {
        if (!rns_link_db_link_snapshot_by_index(i, &link)) {
            continue;
        }

        /* Skip links that never learned a neighbour MAC. These are
         * unanswered outbound LINKREQUESTs (state REQUEST_SENT, never seen
         * on RX): the TX path already falls back to broadcast for them, so
         * they carry no useful peer info and only clutter the table. */
        bool mac_unknown = true;
        for (j = 0; j < 6; j++) {
            if (link.remote_mac[j] != RNS_LINK_MAC_UNKNOWN_BYTE) {
                mac_unknown = false;
                break;
            }
        }
        if (mac_unknown) {
            continue;
        }

        for (j = 0; j < RNS_LINK_ID_LEN; j++) {
            sprintf(id_hex + j * 2, "%02X", link.id[j]);
        }
        id_hex[RNS_LINK_ID_LEN * 2] = '\0';

        for (j = 0; j < RNS_TRUNCATED_HASH_LEN; j++) {
            sprintf(dest_hex + j * 2, "%02X", link.destination[j]);
        }
        dest_hex[RNS_TRUNCATED_HASH_LEN * 2] = '\0';

        snprintf(mac_str, sizeof(mac_str), "%02X:%02X:%02X:%02X:%02X:%02X",
                 link.remote_mac[0], link.remote_mac[1], link.remote_mac[2],
                 link.remote_mac[3], link.remote_mac[4], link.remote_mac[5]);

        int32_t now_s = (int32_t)time(NULL);
        int32_t last_rx_age = (link.lastrx_timestamp_s > 0)
                              ? (now_s - link.lastrx_timestamp_s) : -1;
        int32_t last_tx_age = (link.lasttx_timestamp_s > 0)
                              ? (now_s - link.lasttx_timestamp_s) : -1;

        row = cJSON_CreateArray();
        if (row == NULL) {
            return WEB_API_RC_INTERNAL;
        }

        /* Order MUST match parseReticulumRow() in web_configurator/www/main.js:
         * [id, remoteMac, destination, state, rxBytes, txBytes,
         *  rxPackets, txPackets, lastRx, lastTx, mtu] */
        cJSON_AddItemToArray(row, cJSON_CreateString(id_hex));             /* id           */
        cJSON_AddItemToArray(row, cJSON_CreateString(mac_str));            /* remote_mac   */
        cJSON_AddItemToArray(row, cJSON_CreateString(dest_hex));           /* destination  */
        cJSON_AddItemToArray(row, cJSON_CreateNumber((double)link.state)); /* state        */
        cJSON_AddItemToArray(row, cJSON_CreateNumber((double)link.rx_bytes));
        cJSON_AddItemToArray(row, cJSON_CreateNumber((double)link.tx_bytes));
        cJSON_AddItemToArray(row, cJSON_CreateNumber((double)link.rx_packets));
        cJSON_AddItemToArray(row, cJSON_CreateNumber((double)link.tx_packets));
        cJSON_AddItemToArray(row, cJSON_CreateNumber((double)last_rx_age));
        cJSON_AddItemToArray(row, cJSON_CreateNumber((double)last_tx_age));
        cJSON_AddItemToArray(row, cJSON_CreateNumber((double)link.effective_mtu));

        cJSON_AddItemToArray(arr, row);
    }

    return WEB_API_RC_OK;
}
