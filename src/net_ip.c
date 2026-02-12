#include "net_ip.h"
#include "lwip/netif.h"
#include "lwip/ip_addr.h"
#include "lwip/dhcp.h"
#include "configdb.h"
#include "lwip/tcpip.h"
#include "sys_config.h"

#define NET_IP_DEBUG

#ifdef NET_IP_DEBUG
#define nip_debug(fmt, ...)  os_printf("[NET_IP] " fmt "\r\n", ##__VA_ARGS__)
#else
#define nip_debug(fmt, ...)  do { } while (0)
#endif

#define NET_IP_CONFIG_PREFIX              CONFIGDB_ADD_MODULE("net_ip")
#define NET_IP_CONFIG_ADD_CONFIG(name)    NET_IP_CONFIG_PREFIX "." name

#define NET_IP_CONFIG_MODE_NAME           NET_IP_CONFIG_ADD_CONFIG("mode")
#define NET_IP_CONFIG_IP_NAME             NET_IP_CONFIG_ADD_CONFIG("ip")
#define NET_IP_CONFIG_MASK_NAME           NET_IP_CONFIG_ADD_CONFIG("mask")
#define NET_IP_CONFIG_GW_NAME             NET_IP_CONFIG_ADD_CONFIG("gw")

static struct netif *g_nif;
extern struct netif *netif_default;


#ifdef NET_IP_DEBUG
static inline void net_ip_config_debug_print( const char *tag,
                                              const net_ip_config_t *cfg ){
    char ipbuf[16];
    char maskbuf[16];
    char gwbuf[16];

    if (cfg == NULL) {
        return;
    }

    ip4addr_ntoa_r((const ip4_addr_t *)&cfg->ip,   ipbuf,   sizeof(ipbuf));
    ip4addr_ntoa_r((const ip4_addr_t *)&cfg->mask, maskbuf, sizeof(maskbuf));
    ip4addr_ntoa_r((const ip4_addr_t *)&cfg->gw,   gwbuf,   sizeof(gwbuf));

    nip_debug("%s mode=%d ip=%s mask=%s gw=%s",
              tag ? tag : "CFG",
              cfg->mode,
              ipbuf,
              maskbuf,
              gwbuf);
}
#else
#define net_ip_config_debug_print(tag, cfg) do { } while (0)
#endif

static bool net_ip_config_is_valid(const net_ip_config_t *cfg){
    if (cfg == NULL) {
        return false;
    }
    if ((cfg->mode != NET_IP_MODE_DHCP) &&
        (cfg->mode != NET_IP_MODE_STATIC)) {
        return false;
    }

    if (cfg->mode == NET_IP_MODE_STATIC) {
        uint32_t m = lwip_ntohl(cfg->mask.addr);
        uint32_t inv;

        if (m == 0) {
            return false;
        }
        inv = ~m;
        if ((inv & (inv + 1)) != 0) {
            return false;
        }
    }
    return true;
}


static void net_ip_apply_cb(void *arg){
    net_ip_config_t* cfg = (net_ip_config_t*)arg;

    if (cfg == NULL) {
        return;
    }
    if (g_nif == NULL) {
        os_free(cfg);
        return;
    }
    nip_debug("APPLY: mode=%d", cfg->mode);

    dhcp_stop(g_nif);

    if (cfg->mode == NET_IP_MODE_DHCP) {
        dhcp_start(g_nif);
    } else {
        netif_set_addr(g_nif, &cfg->ip, &cfg->mask, &cfg->gw);
    }

    os_free(cfg);
}

void net_ip_config_fill_runtime_addrs(net_ip_config_t *cfg){
    if (cfg == NULL) {
        return;
    }
    if (g_nif == NULL) {
        return;
    }
    cfg->ip.addr   = netif_ip4_addr(g_nif)->addr;
    cfg->mask.addr = netif_ip4_netmask(g_nif)->addr;
    cfg->gw.addr   = netif_ip4_gw(g_nif)->addr;
}


void net_ip_config_set_default(net_ip_config_t *cfg){
    if(cfg == NULL){
        return;
    }
    
    cfg->ip.addr    = NET_IP_CONFIG_IP_DEF;
    cfg->mask.addr  = NET_IP_CONFIG_MASK_DEF;
    cfg->gw.addr    = NET_IP_CONFIG_GW_DEF;
    cfg->mode       = NET_IP_CONFIG_MODE_DEF;
}

void net_ip_config_load(net_ip_config_t *cfg){
    if (cfg == NULL) {
        return;
    }
    
    int32_t mode = NET_IP_MODE_DHCP;
    configdb_get_i32(NET_IP_CONFIG_MODE_NAME, &mode);
    cfg->mode = (net_ip_mode_t)mode;

    cfg->ip.addr   = NET_IP_CONFIG_IP_DEF;
    cfg->mask.addr = NET_IP_CONFIG_MASK_DEF;
    cfg->gw.addr   = NET_IP_CONFIG_GW_DEF;

    if (cfg->mode == NET_IP_MODE_STATIC) {
        configdb_get_i32(NET_IP_CONFIG_IP_NAME,   (int32_t*)&cfg->ip.addr);
        configdb_get_i32(NET_IP_CONFIG_MASK_NAME, (int32_t*)&cfg->mask.addr);
        configdb_get_i32(NET_IP_CONFIG_GW_NAME,   (int32_t*)&cfg->gw.addr);
    }

    net_ip_config_debug_print("LOAD", cfg);
}

void net_ip_config_save(const net_ip_config_t *cfg){
    if (cfg == NULL) {
        return;
    }
    if(!net_ip_config_is_valid(cfg)){
        nip_debug("Trying save invalid config!");
        return;
    }
    net_ip_config_debug_print("SAVE", cfg);
    
    int32_t mode = (int32_t)cfg->mode;
    configdb_set_i32(NET_IP_CONFIG_MODE_NAME, &mode);
    if(cfg->mode == NET_IP_MODE_STATIC){
        configdb_set_i32(NET_IP_CONFIG_IP_NAME,   (int32_t*)&cfg->ip.addr);
        configdb_set_i32(NET_IP_CONFIG_MASK_NAME, (int32_t*)&cfg->mask.addr);
        configdb_set_i32(NET_IP_CONFIG_GW_NAME,   (int32_t*)&cfg->gw.addr);
    }
}

void net_ip_config_apply( const net_ip_config_t *cfg ){
    net_ip_config_t *cpy;

    if (cfg == NULL) {
        return;
    }
    if (g_nif == NULL) {
        return;
    }
    if (!net_ip_config_is_valid(cfg)) {
        nip_debug("Trying apply invalid config!");
        return;
    }
    
    cpy = (net_ip_config_t *)os_malloc(sizeof(*cpy));
    if (cpy == NULL) {
        nip_debug("apply: OOM");
        return;
    }

    memcpy(cpy, cfg, sizeof(*cpy));
    net_ip_config_debug_print("APPLY", cfg);

    if (tcpip_try_callback(net_ip_apply_cb, cpy) != ERR_OK) {
        nip_debug("apply: tcpip_try_callback failed");
        os_free(cpy);
        return;
    }
}

int32_t net_ip_init(void){
    g_nif = netif_default;
    net_ip_config_t net_ip_config;
    net_ip_config_load(&net_ip_config);
    if (!net_ip_config_is_valid(&net_ip_config)) {
        nip_debug("Invalid config in DB -> defaults");
        net_ip_config_set_default(&net_ip_config);
    }
    net_ip_config_save(&net_ip_config);
    net_ip_config_apply(&net_ip_config);
    return 0;
}
