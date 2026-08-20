#include "sys_config.h"
#include "build_info_gen.h"
#define LOG_LOCAL_LEVEL LOG_LEVEL_CONFIG_API_DISPATCH

#include "basic_include.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "config_page/config_api_dispatch.h"
#include "config_page/config_api_calls.h"
#include "lib/logc/log.h"

typedef int32_t (*web_api_cb_t)( const cJSON *in, cJSON *out );

typedef struct {
    const char  *endpoint;   /* part after "/api/" */
    web_api_cb_t get_cb;
    web_api_cb_t post_cb;
} web_api_route_t;

static bool api_str_eq( const char *a, const char *b ){
    if (a == NULL || b == NULL) {
        return false;
    }
    return (strcmp(a, b) == 0) ? true : false;
}

static const char *api_uri_to_endpoint( const char *uri, char *tmp, size_t tmp_sz ){
    const char *p;
    size_t n;
    size_t i;

    if (uri == NULL || tmp == NULL || tmp_sz < 2) {
        return NULL;
    }

    if (strncmp(uri, "/api/", 5) != 0) {
        return NULL;
    }

    p = uri + 5;

    /* cut query */
    n = strcspn(p, "?#");
    if (n == 0) {
        return NULL;
    }
    if (n >= tmp_sz) {
        n = tmp_sz - 1;
    }

    memcpy(tmp, p, n);
    tmp[n] = 0;

    /* trim trailing slashes */
    for (i = n; i > 0; i--) {
        if (tmp[i - 1] != '/') {
            break;
        }
        tmp[i - 1] = 0;
    }

    if (tmp[0] == 0) {
        return NULL;
    }

    return tmp;
}

/*
 * NOTE about table:
 * We intentionally list legacy endpoints as separate entries (instead of alias field),
 * because it's simpler to read and removes "why NULL alias" questions.
 */
static const web_api_route_t s_api_routes[] = {
    //{ "stat_reset",  web_api_stat_reset,  NULL },
    { "get_stat",           web_api_stat_get,               NULL                        },
    { "get_all",            web_api_all_get,                NULL                        },
    { "get_nearby_modems",  web_api_nearby_modems_get,      NULL                        },
    { "get_reticulum_links",web_api_reticulum_links_get,    NULL                        },
    { "halow_cfg",          web_api_halow_cfg_get,          web_api_halow_cfg_post      },
    { "lbt_cfg",            web_api_lbt_cfg_get,            web_api_lbt_cfg_post        },
    { "cca_cfg",            web_api_cca_cfg_get,            web_api_cca_cfg_post        },
    { "net_cfg",            web_api_net_cfg_get,            web_api_net_cfg_post        },
    { "slip_cfg",           web_api_slip_cfg_get,           web_api_slip_cfg_post       },
    { "log_cfg",            web_api_log_cfg_get,            web_api_log_cfg_post        },
    { "tcp_server_cfg",     web_api_tcp_server_cfg_get,     web_api_tcp_server_cfg_post },
    { "telemetry_cfg",      web_api_telemetry_cfg_get,      web_api_telemetry_cfg_post  },
    { "privacy_cfg",        web_api_privacy_cfg_get,        web_api_privacy_cfg_post    },
    { "ack_cfg",            web_api_ack_cfg_get,            web_api_ack_cfg_post        },
    { "telemetry_send",     NULL,                           web_api_telemetry_send_post },

    { "ota_wipe_lfs",       NULL,                           web_api_ota_wipe_lfs_post   },
    { "ota_file_begin",     NULL,                           web_api_ota_file_begin_post },
    { "ota_file_end",       NULL,                           web_api_ota_file_end_post   },
    { "ota_file_chunk",     NULL,                           web_api_ota_file_chunk_post },
    { "ota_fw_begin",       NULL,                           web_api_ota_fw_begin_post   },
    { "ota_fw_end",         NULL,                           web_api_ota_fw_end_post     },
    { "ota_fw_chunk",       NULL,                           web_api_ota_fw_chunk_post   },
    { "reboot",             NULL,                           web_api_reboot_post         },
    { "reset_stat",         NULL,                           web_api_radio_stat_post     },
#ifdef FW_BUILD_BETA
    { "cpu_dump",           web_api_cpu_dump_get,           NULL                        },
    { "tx_dbg",             web_api_tx_dbg_get,             NULL                        },
    { "rf_dbg",             web_api_rf_dbg_get,             web_api_rf_dbg_post         },
#endif
    { "default_rst",        NULL,                           web_api_default_reset       },
};

static const web_api_route_t *api_find_route( const char *endpoint ){
    size_t i;

    if (endpoint == NULL) {
        return NULL;
    }

    for (i = 0; i < (sizeof(s_api_routes) / sizeof(s_api_routes[0])); i++) {
        if (api_str_eq(endpoint, s_api_routes[i].endpoint)) {
            return &s_api_routes[i];
        }
    }

    return NULL;
}

static void api_set_err( cJSON *out, const char *msg ){
    if (out == NULL || msg == NULL) {
        return;
    }
    /* overwrite is OK */
    (void)cJSON_DeleteItemFromObject(out, "err");
    (void)cJSON_AddStringToObject(out, "err", msg);
}

int32_t web_api_dispatch( const char *method,
                          const char *uri,
                          const cJSON *in_json,
                          cJSON *out_json ){
    char ep[64];
    const char *endpoint;
    const web_api_route_t *r;
    web_api_cb_t cb;
    int32_t rc;

    if (method == NULL || uri == NULL || out_json == NULL) {
        log_warn("dispatch bad args");
        return WEB_API_RC_BAD_REQUEST;
    }
    if (!cJSON_IsObject(out_json)) {
        log_warn("dispatch out_json not object");
        return WEB_API_RC_BAD_REQUEST;
    }

    endpoint = api_uri_to_endpoint(uri, ep, sizeof(ep));
    if (endpoint == NULL) {
        log_warn("dispatch bad uri='%s'", uri);
        api_set_err(out_json, "bad uri");
        return WEB_API_RC_BAD_REQUEST;
    }

    r = api_find_route(endpoint);
    if (r == NULL) {
        log_warn("dispatch api not found method=%s ep=%s", method, endpoint);
        api_set_err(out_json, "api not found");
        return WEB_API_RC_NOT_FOUND;
    }

    cb = NULL;

    if (strcmp(method, "GET") == 0) {
        cb = r->get_cb;
    } else if (strcmp(method, "POST") == 0) {
        cb = r->post_cb;
    } else {
        log_warn("dispatch method not allowed method=%s ep=%s", method, endpoint);
        api_set_err(out_json, "method not allowed");
        return WEB_API_RC_METHOD_NOT_ALLOWED;
    }

    if (cb == NULL) {
        log_warn("dispatch no handler method=%s ep=%s", method, endpoint);
        api_set_err(out_json, "method not allowed");
        return WEB_API_RC_METHOD_NOT_ALLOWED;
    }

    log_trace("dispatch method=%s ep=%s", method, endpoint);
    rc = cb(in_json, out_json);
    if (rc != WEB_API_RC_OK) {
        log_warn("dispatch rc=%ld method=%s ep=%s", (long)rc, method, endpoint);
    }
    return rc;
}
