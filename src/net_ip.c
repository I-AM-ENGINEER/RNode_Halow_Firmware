#include "sys_config.h"
#define LOG_LOCAL_LEVEL LOG_LEVEL_NET_IP

#include "net_ip.h"
#include "lwip/netif.h"
#include "lwip/ip_addr.h"
#include "lwip/dhcp.h"
#include "configdb.h"
#include "lwip/tcpip.h"
#include "lib/logc/log.h"

#define NET_IP_CONFIG_PREFIX              CONFIGDB_ADD_MODULE("net_ip")
#define NET_IP_CONFIG_ADD_CONFIG(name)    NET_IP_CONFIG_PREFIX "." name

#define NET_IP_CONFIG_MODE_NAME           NET_IP_CONFIG_ADD_CONFIG("mode")
#define NET_IP_CONFIG_IP_NAME             NET_IP_CONFIG_ADD_CONFIG("ip")
#define NET_IP_CONFIG_MASK_NAME           NET_IP_CONFIG_ADD_CONFIG("mask")
#define NET_IP_CONFIG_GW_NAME             NET_IP_CONFIG_ADD_CONFIG("gw")

static struct netif *g_nif;
extern struct netif *netif_default;

static inline void net_ip_config_log_trace( const char *tag, const net_ip_config_t *cfg ){
    char ipbuf[16];
    char maskbuf[16];
    char gwbuf[16];

    if( cfg == NULL ){
        return;
    }

    ip4addr_ntoa_r((const ip4_addr_t *)&cfg->ip,   ipbuf,   sizeof(ipbuf));
    ip4addr_ntoa_r((const ip4_addr_t *)&cfg->mask, maskbuf, sizeof(maskbuf));
    ip4addr_ntoa_r((const ip4_addr_t *)&cfg->gw,   gwbuf,   sizeof(gwbuf));

    log_trace("%s mode=%d ip=%s mask=%s gw=%s",
              tag ? tag : "CFG",
              cfg->mode,
              ipbuf,
              maskbuf,
              gwbuf);
}

static inline void net_ip_config_log_debug( const char *tag, const net_ip_config_t *cfg ){
    char ipbuf[16];
    char maskbuf[16];
    char gwbuf[16];

    if( cfg == NULL ){
        return;
    }

    ip4addr_ntoa_r((const ip4_addr_t *)&cfg->ip,   ipbuf,   sizeof(ipbuf));
    ip4addr_ntoa_r((const ip4_addr_t *)&cfg->mask, maskbuf, sizeof(maskbuf));
    ip4addr_ntoa_r((const ip4_addr_t *)&cfg->gw,   gwbuf,   sizeof(gwbuf));

    log_debug("%s mode=%d ip=%s mask=%s gw=%s",
              tag ? tag : "CFG",
              cfg->mode,
              ipbuf,
              maskbuf,
              gwbuf);
}

static bool net_ip_config_is_valid( const net_ip_config_t *cfg ){
    if( cfg == NULL ){
        return false;
    }

    if( (cfg->mode != NET_IP_MODE_DHCP) &&
        (cfg->mode != NET_IP_MODE_STATIC) ){
        return false;
    }

    if( cfg->mode == NET_IP_MODE_STATIC ){
        uint32_t m = lwip_ntohl(cfg->mask.addr);
        uint32_t inv;

        if( m == 0 ){
            return false;
        }

        inv = ~m;
        if( (inv & (inv + 1)) != 0 ){
            return false;
        }
    }

    return true;
}

static void net_ip_apply_cb( void *arg ){
    net_ip_config_t *cfg = (net_ip_config_t *)arg;

    if( cfg == NULL ){
        log_warn("apply cb: cfg null");
        return;
    }

    if( g_nif == NULL ){
        log_warn("apply cb: netif null");
        os_free(cfg);
        return;
    }

    log_debug("apply cb: mode=%d", cfg->mode);

    dhcp_stop(g_nif);

    if( cfg->mode == NET_IP_MODE_DHCP ){
        err_t err = dhcp_start(g_nif);
        if( err != ERR_OK ){
            log_error("dhcp_start failed err=%d", (int)err);
        }
    } else {
        netif_set_addr(g_nif, &cfg->ip, &cfg->mask, &cfg->gw);
    }

    os_free(cfg);
}

void net_ip_config_fill_runtime_addrs( net_ip_config_t *cfg ){
    if( cfg == NULL ){
        return;
    }

    if( g_nif == NULL ){
        return;
    }

    cfg->ip.addr   = netif_ip4_addr(g_nif)->addr;
    cfg->mask.addr = netif_ip4_netmask(g_nif)->addr;
    cfg->gw.addr   = netif_ip4_gw(g_nif)->addr;
}

void net_ip_config_set_default( net_ip_config_t *cfg ){
    if( cfg == NULL ){
        return;
    }

    cfg->ip.addr   = NET_IP_CONFIG_IP_DEF;
    cfg->mask.addr = NET_IP_CONFIG_MASK_DEF;
    cfg->gw.addr   = NET_IP_CONFIG_GW_DEF;
    cfg->mode      = NET_IP_CONFIG_MODE_DEF;
}

void net_ip_config_load( net_ip_config_t *cfg ){
    int32_t mode = NET_IP_MODE_DHCP;

    if( cfg == NULL ){
        return;
    }

    configdb_get_i32(NET_IP_CONFIG_MODE_NAME, &mode);
    cfg->mode = (net_ip_mode_t)mode;

    cfg->ip.addr   = NET_IP_CONFIG_IP_DEF;
    cfg->mask.addr = NET_IP_CONFIG_MASK_DEF;
    cfg->gw.addr   = NET_IP_CONFIG_GW_DEF;

    if( cfg->mode == NET_IP_MODE_STATIC ){
        configdb_get_i32(NET_IP_CONFIG_IP_NAME,   (int32_t *)&cfg->ip.addr);
        configdb_get_i32(NET_IP_CONFIG_MASK_NAME, (int32_t *)&cfg->mask.addr);
        configdb_get_i32(NET_IP_CONFIG_GW_NAME,   (int32_t *)&cfg->gw.addr);
    }

    net_ip_config_log_trace("LOAD", cfg);
}

void net_ip_config_save( const net_ip_config_t *cfg ){
    int32_t mode;

    if( cfg == NULL ){
        return;
    }

    if( !net_ip_config_is_valid(cfg) ){
        log_warn("trying save invalid config");
        return;
    }

    net_ip_config_log_debug("SAVE", cfg);

    mode = (int32_t)cfg->mode;
    configdb_set_i32(NET_IP_CONFIG_MODE_NAME, &mode);

    if( cfg->mode == NET_IP_MODE_STATIC ){
        configdb_set_i32(NET_IP_CONFIG_IP_NAME,   (int32_t *)&cfg->ip.addr);
        configdb_set_i32(NET_IP_CONFIG_MASK_NAME, (int32_t *)&cfg->mask.addr);
        configdb_set_i32(NET_IP_CONFIG_GW_NAME,   (int32_t *)&cfg->gw.addr);
    }
}

void net_ip_config_apply( const net_ip_config_t *cfg ){
    net_ip_config_t *cpy;

    if( cfg == NULL ){
        log_warn("apply: cfg null");
        return;
    }

    if( g_nif == NULL ){
        log_warn("apply: netif null");
        return;
    }

    if( !net_ip_config_is_valid(cfg) ){
        log_warn("trying apply invalid config");
        return;
    }

    cpy = (net_ip_config_t *)os_malloc(sizeof(*cpy));
    if( cpy == NULL ){
        log_error("apply: OOM");
        return;
    }

    memcpy(cpy, cfg, sizeof(*cpy));
    net_ip_config_log_debug("APPLY", cfg);

    if( tcpip_try_callback(net_ip_apply_cb, cpy) != ERR_OK ){
        log_error("apply: tcpip_try_callback failed");
        os_free(cpy);
        return;
    }
}

int32_t net_ip_init( void ){
    net_ip_config_t net_ip_config;

    g_nif = netif_default;
    if( g_nif == NULL ){
        log_error("init: netif_default null");
        return -1;
    }

    net_ip_config_load(&net_ip_config);

    if( !net_ip_config_is_valid(&net_ip_config) ){
        log_warn("invalid config in DB -> defaults");
        net_ip_config_set_default(&net_ip_config);
    }

    net_ip_config_save(&net_ip_config);
    net_ip_config_apply(&net_ip_config);

    log_info("net_ip init ok");
    return 0;
}

void net_ip_wait_ready( void ){
    while( 1 ){
        struct netif *n = netif_default;

        if( n != NULL ){
            if( netif_is_up(n) && netif_is_link_up(n) && !ip4_addr_isany_val(*netif_ip4_addr(n)) ){
                log_debug("net ready ip=%s", ip4addr_ntoa(netif_ip4_addr(n)));
                return;
            }
        }

        log_trace("wait ready...");
        os_sleep_ms(100);
    }
}
