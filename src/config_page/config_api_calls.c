
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
#include "net_ip.h"
#include "tcp_server.h"
#include "utils.h"
#include "device.h"
#include "statistics.h"

/* -------------------------------------------------------------------------- */
/* Change version                                                             */
/* -------------------------------------------------------------------------- */

static volatile uint32_t s_change_version = 0;
extern struct netif *netif_default;

void web_api_notify_change( void ){
    s_change_version++;
}

uint32_t web_api_change_version( void ){
    return s_change_version;
}

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

/* -------------------------------------------------------------------------- */
/* /api/heartbeat                                                             */
/* -------------------------------------------------------------------------- */

int32_t web_api_heartbeat_get( const cJSON *in, cJSON *out ){
    (void)in;

    if (out == NULL) {
        return WEB_API_RC_BAD_REQUEST;
    }

    (void)cJSON_AddNumberToObject(out, "version", (double)web_api_change_version());
    return WEB_API_RC_OK;
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

    (void)in;

    if (out == NULL) {
        return WEB_API_RC_BAD_REQUEST;
    }

    halow_config_load(&cfg);

    char bndw[16];
    (void)snprintf(bndw, sizeof(bndw), "%d MHz", (int)cfg.bandwidth);
    (void)cJSON_AddStringToObject(out, "bandwidth",    bndw);
    (void)cJSON_AddNumberToObject(out, "central_freq", ((double)cfg.central_freq) / 10.0);
    (void)cJSON_AddBoolToObject(out,   "super_power",  (cfg.rf_super_power != 0) ? 1 : 0);
    (void)cJSON_AddNumberToObject(out, "power_dbm",    (double)cfg.rf_power);
    char mcs[8];
    (void)snprintf(mcs, sizeof(mcs), "MCS%d", (int)cfg.mcs);
    (void)cJSON_AddStringToObject(out, "mcs_index", mcs);

    return WEB_API_RC_OK;
}

int32_t web_api_halow_cfg_post( const cJSON *in, cJSON *out ){
    halow_config_t cfg;
    bool b;
    int i;
    double d;

    if (in == NULL || !cJSON_IsObject(in) || out == NULL) {
        return api_err(out, WEB_API_RC_BAD_REQUEST, "bad json");
    }

    halow_config_load(&cfg);

    const cJSON *j;

    j = cJSON_GetObjectItemCaseSensitive(in, "bandwidth");
    if (j != NULL && cJSON_IsString(j) && j->valuestring != NULL) {
        const char *s = j->valuestring;          /* "4 MHz" */
        int bw = atoi(s);                        /* 4 */

        if (bw > 0 && bw < 64) {
            cfg.bandwidth = (int8_t)bw;
        }

        os_printf("bndw(json) = %s -> %d\r\n", s, bw);
    }
    
    j = cJSON_GetObjectItemCaseSensitive(in, "mcs_index");
    if (j != NULL && cJSON_IsString(j) && j->valuestring != NULL) {
        const char *s = j->valuestring;
        if (s[0] == 'M' && s[1] == 'C' && s[2] == 'S') {
            cfg.mcs = (int8_t)atoi(&s[3]);
        }
    }

    if (json_get_bool(in, "super_power", &b)) {
        cfg.rf_super_power = b ? 1 : 0;
    }

    if (json_get_int(in, "power_dbm", &i)) {
        if (i > -128 && i < 128) {
            cfg.rf_power = (int8_t)i;
        }
    }

    if (json_get_double(in, "central_freq", &d)) {
        if (d > 0.0) {
            cfg.central_freq = (uint16_t)(d * 10.0 + 0.5);
        }
    }

    halow_config_apply(&cfg);
    halow_config_save(&cfg);

    web_api_notify_change();

    return web_api_halow_cfg_get(NULL, out);
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
        return api_err(out, WEB_API_RC_BAD_REQUEST, "bad json");
    }

    ip[0] = 0;
    gw[0] = 0;
    mask[0] = 0;

    (void)json_get_bool(in, "dhcp", &dhcp);
    (void)json_get_string(in, "ip_address", ip, sizeof(ip));
    (void)json_get_string(in, "gw_address", gw, sizeof(gw));
    (void)json_get_string(in, "netmask", mask, sizeof(mask));

    net_ip_config_set_default(&cfg);
    cfg.mode = dhcp ? NET_IP_MODE_DHCP : NET_IP_MODE_STATIC;

    if (cfg.mode == NET_IP_MODE_STATIC) {
        if (!ip4addr_aton(ip, &cfg.ip)) {
            return api_err(out, WEB_API_RC_BAD_REQUEST, "bad ip_address");
        }
        if (!ip4addr_aton(mask, &cfg.mask)) {
            return api_err(out, WEB_API_RC_BAD_REQUEST, "bad netmask");
        }
        if (!ip4addr_aton(gw, &cfg.gw)) {
            return api_err(out, WEB_API_RC_BAD_REQUEST, "bad gw_address");
        }
    }

    net_ip_config_apply(&cfg);
    net_ip_config_save(&cfg);

    web_api_notify_change();

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
        return api_err(out, WEB_API_RC_BAD_REQUEST, "bad json");
    }

    whitelist[0] = 0;

    (void)json_get_bool(in, "enable", &enable);
    (void)json_get_int(in, "port", &port);
    (void)json_get_string(in, "whitelist", whitelist, sizeof(whitelist));

    tcp_server_config_load(&cfg);

    cfg.enabled = enable ? true : false;

    if (port >= 1 && port <= 65535) {
        cfg.port = (uint16_t)port;
    }

    if (utils_cidr_to_ip(whitelist, &ip) && utils_cidr_to_mask(whitelist, &mask)) {
        cfg.whitelist_ip   = ip;
        cfg.whitelist_mask = mask;
    } else {
        ip4_addr_set_u32(&cfg.whitelist_ip,   PP_HTONL(0u));
        ip4_addr_set_u32(&cfg.whitelist_mask, PP_HTONL(0u));
    }

    tcp_server_config_apply(&cfg);
    tcp_server_config_save(&cfg);

    web_api_notify_change();

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
        return api_err(out, WEB_API_RC_BAD_REQUEST, "bad json");
    }

    halow_lbt_config_load(&cfg);

    if (json_get_bool(in, "en", &b))    { cfg.lbt_enabled  = b ? 1 : 0; }

    if (json_get_int(in, "sw", &v))    { if (v >= 1 && v <= 65535) cfg.noise_short_window_samples = (uint16_t)v; }
    if (json_get_int(in, "lw", &v))    { if (v >= 1 && v <= 65535) cfg.noise_long_window_samples  = (uint16_t)v; }
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

    web_api_notify_change();
    //return web_api_lbt_cfg_get(NULL, out);
    return web_api_halow_cfg_get(NULL, out);
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
    (void)cJSON_AddStringToObject(out, "ver", FW_FULL_VERSION);

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
    statistics_radio_reset();
    web_api_notify_change();
    return web_api_lbt_cfg_get(NULL, out);
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

int32_t web_api_all_get( const cJSON *in, cJSON *out ){
    cJSON *halow = NULL;
    cJSON *net   = NULL;
    cJSON *tcp   = NULL;
    cJSON *lbt   = NULL;
    cJSON *ota   = NULL;

    cJSON *stat  = NULL;
    cJSON *dev   = NULL;
    cJSON *radio = NULL;

    int32_t rc;

    (void)in;

    if (out == NULL) {
        return WEB_API_RC_BAD_REQUEST;
    }

    (void)cJSON_AddNumberToObject(out, "ver", (double)web_api_change_version());

    halow = cJSON_CreateObject();
    net   = cJSON_CreateObject();
    tcp   = cJSON_CreateObject();
    lbt   = cJSON_CreateObject();
    ota   = cJSON_CreateObject();

    stat  = cJSON_CreateObject();
    dev   = cJSON_CreateObject();
    radio = cJSON_CreateObject();

    if (!halow || !net || !tcp || !lbt || !ota || !stat || !dev || !radio) {
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

    rc = web_api_online_ota_get(NULL, ota);
    if (rc != WEB_API_RC_OK) goto fail;

    rc = web_api_dev_stat_get(NULL, dev);
    if (rc != WEB_API_RC_OK) goto fail;

    rc = web_api_radio_stat_get(NULL, radio);
    if (rc != WEB_API_RC_OK) goto fail;

    cJSON_AddItemToObject(stat, "device", dev);    dev = NULL;
    cJSON_AddItemToObject(stat, "radio",  radio);  radio = NULL;

    cJSON_AddItemToObject(out, "halow", halow);   halow = NULL;
    cJSON_AddItemToObject(out, "net",   net);     net   = NULL;
    cJSON_AddItemToObject(out, "tcp",   tcp);     tcp   = NULL;
    cJSON_AddItemToObject(out, "lbt",   lbt);     lbt   = NULL;
    cJSON_AddItemToObject(out, "ota",   ota);     ota   = NULL;

    cJSON_AddItemToObject(out, "stat",  stat);    stat  = NULL;

    return WEB_API_RC_OK;

fail:
    cJSON_Delete(halow);
    cJSON_Delete(net);
    cJSON_Delete(tcp);
    cJSON_Delete(lbt);
    cJSON_Delete(ota);

    cJSON_Delete(stat);
    cJSON_Delete(dev);
    cJSON_Delete(radio);
    return rc;
}

int32_t web_api_reboot_post( const cJSON *in, cJSON *out ){
    device_reboot();
    return 0;
}
