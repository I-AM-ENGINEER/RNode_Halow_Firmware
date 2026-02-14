
#include "basic_include.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "config_page/config_api_dispatch.h"
#include "config_page/config_api_calls.h"

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
    { "heartbeat",              web_api_heartbeat_get,       NULL },
    { "api_halow_cfg",          web_api_halow_cfg_get,       web_api_halow_cfg_post },
    { "api_net_cfg",            web_api_net_cfg_get,         web_api_net_cfg_post },
    { "api_tcp_server_cfg",     web_api_tcp_server_cfg_get,  web_api_tcp_server_cfg_post },
    { "api_lbt_cfg",            web_api_lbt_cfg_get,         web_api_lbt_cfg_post },
    { "api_dev_stat",           web_api_dev_stat_get,        NULL },
    { "api_radio_stat",         web_api_radio_stat_get,      NULL },
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

    if (method == NULL || uri == NULL || out_json == NULL) {
        return WEB_API_RC_BAD_REQUEST;
    }
    if (!cJSON_IsObject(out_json)) {
        return WEB_API_RC_BAD_REQUEST;
    }

    endpoint = api_uri_to_endpoint(uri, ep, sizeof(ep));
    if (endpoint == NULL) {
        api_set_err(out_json, "bad uri");
        return WEB_API_RC_BAD_REQUEST;
    }

    r = api_find_route(endpoint);
    if (r == NULL) {
        api_set_err(out_json, "api not found");
        return WEB_API_RC_NOT_FOUND;
    }

    cb = NULL;

    if (strcmp(method, "GET") == 0) {
        cb = r->get_cb;
    } else if (strcmp(method, "POST") == 0) {
        cb = r->post_cb;
    } else {
        api_set_err(out_json, "method not allowed");
        return WEB_API_RC_METHOD_NOT_ALLOWED;
    }

    if (cb == NULL) {
        api_set_err(out_json, "method not allowed");
        return WEB_API_RC_METHOD_NOT_ALLOWED;
    }

    return cb(in_json, out_json);
}
