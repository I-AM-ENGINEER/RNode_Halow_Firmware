
#include "basic_include.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "cJSON.h"

#include "config_page/config_api_calls.h"
#include "config_page/config_api_dispatch.h"

#include "halow.h"
#include "net_ip.h"
#include "tcp_server.h"
#include "utils.h"

/* -------------------------------------------------------------------------- */
/* Change version                                                             */
/* -------------------------------------------------------------------------- */

static volatile uint32_t s_change_version = 0;

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

    (void)cJSON_AddNumberToObject(out, "bandwidth",    (double)cfg.bandwidth);
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

    if (json_get_int(in, "bandwidth", &i)) {
        if (i > 0 && i < 64) {
            cfg.bandwidth = (int8_t)i;
        }
    }
    
    const cJSON *j = cJSON_GetObjectItemCaseSensitive(in, "mcs_index");
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

static bool s_lbt_enable = false;
static int  s_lbt_max_airtime_perc = 100;

int32_t web_api_lbt_cfg_get( const cJSON *in, cJSON *out ){
    (void)in;

    if (out == NULL) {
        return WEB_API_RC_BAD_REQUEST;
    }

    (void)cJSON_AddBoolToObject(out, "enable", s_lbt_enable ? 1 : 0);
    (void)cJSON_AddNumberToObject(out, "max_airtime_perc", (double)s_lbt_max_airtime_perc);
    return WEB_API_RC_OK;
}

int32_t web_api_lbt_cfg_post( const cJSON *in, cJSON *out ){
    bool b;
    int i;

    if (in == NULL || !cJSON_IsObject(in) || out == NULL) {
        return api_err(out, WEB_API_RC_BAD_REQUEST, "bad json");
    }

    if (json_get_bool(in, "enable", &b)) {
        s_lbt_enable = b;
    }
    if (json_get_int(in, "max_airtime_perc", &i)) {
        if (i >= 0 && i <= 100) {
            s_lbt_max_airtime_perc = i;
        }
    }

    web_api_notify_change();
    return web_api_lbt_cfg_get(NULL, out);
}

/* -------------------------------------------------------------------------- */
/* /api/dev_stat + /api/radio_stat (placeholders)                             */
/* -------------------------------------------------------------------------- */

int32_t web_api_dev_stat_get( const cJSON *in, cJSON *out ){
    (void)in;

    if (out == NULL) {
        return WEB_API_RC_BAD_REQUEST;
    }

    (void)cJSON_AddStringToObject(out, "todo", "dev_stat not implemented");
    return WEB_API_RC_OK;
}

int32_t web_api_radio_stat_get( const cJSON *in, cJSON *out ){
    (void)in;

    if (out == NULL) {
        return WEB_API_RC_BAD_REQUEST;
    }

    (void)cJSON_AddStringToObject(out, "todo", "radio_stat not implemented");
    return WEB_API_RC_OK;
}
