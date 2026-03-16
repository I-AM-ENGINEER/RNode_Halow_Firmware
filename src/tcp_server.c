#include "tcp_server.h"

#include "lwip/tcp.h"
#include "lwip/tcpip.h"
#include "sys_config.h"
#include "configdb.h"
#include "lwip/ip4_addr.h"
#include "lwip/ip_addr.h"
#include "lwip/netbuf.h"
#include "lwip/api.h"
#include <string.h>

//#define TCP_SERVER_DEBUG

#ifdef TCP_SERVER_DEBUG
#define tcps_debug(fmt, ...)  os_printf("[TCPS] " fmt "\r\n", ##__VA_ARGS__)
#else
#define tcps_debug(fmt, ...)  do { } while (0)
#endif

#ifndef TCP_SERVER_CONFIG_PREFIX
#define TCP_SERVER_CONFIG_PREFIX                    CONFIGDB_ADD_MODULE("tcps")
#define TCP_SERVER_CONFIG_ADD_CONFIG(name)          TCP_SERVER_CONFIG_PREFIX "." name

#define TCP_SERVER_CONFIG_PORT_NAME                 TCP_SERVER_CONFIG_ADD_CONFIG("port")
#define TCP_SERVER_CONFIG_ENABLED_NAME              TCP_SERVER_CONFIG_ADD_CONFIG("enabled")
#define TCP_SERVER_CONFIG_WHITELIST_IP_NAME         TCP_SERVER_CONFIG_ADD_CONFIG("wlst_ip")
#define TCP_SERVER_CONFIG_WHITELIST_MASK_NAME       TCP_SERVER_CONFIG_ADD_CONFIG("wlst_mask")
#endif

static tcp_server_config_t g_cfg;
static tcp_server_rx_cb_t g_rx_cb;

static struct os_task g_tcps_rx_task;
static struct os_mutex g_clinet_mutex;
static struct netconn *g_client_nc;

static bool tcp_server_ip_allowed( const ip4_addr_t *addr ){
    uint32_t ip;
    uint32_t wl_ip;
    uint32_t wl_mask;

    if (addr == NULL) {
        return false;
    }

    wl_mask = ip4_addr_get_u32(&g_cfg.whitelist_mask);
    if (wl_mask == 0) {
        return true;
    }

    ip    = ip4_addr_get_u32(addr);
    wl_ip = ip4_addr_get_u32(&g_cfg.whitelist_ip);

    return ((ip & wl_mask) == (wl_ip & wl_mask));
}

void tcp_server_config_load(tcp_server_config_t *cfg){
    int8_t enabled;
    int16_t port;
    int32_t ip;
    int32_t mask;

    if (cfg == NULL) {
        return;
    }

    cfg->enabled = TCP_SERVER_CONFIG_ENABLED_DEF ? true : false;
    cfg->port = TCP_SERVER_CONFIG_PORT_DEF;
    cfg->whitelist_ip.addr = (uint32_t)TCP_SERVER_CONFIG_WHITELIST_IP_DEF;
    cfg->whitelist_mask.addr = (uint32_t)TCP_SERVER_CONFIG_WHITELIST_MASK_DEF;

    if (configdb_get_i8(TCP_SERVER_CONFIG_ENABLED_NAME, &enabled) == 0) {
        cfg->enabled = enabled ? true : false;
    }
    if (configdb_get_i16(TCP_SERVER_CONFIG_PORT_NAME, &port) == 0) {
        cfg->port = (uint16_t)port;
    }
    if (configdb_get_i32(TCP_SERVER_CONFIG_WHITELIST_IP_NAME, &ip) == 0) {
        cfg->whitelist_ip.addr = (uint32_t)ip;
    }
    if (configdb_get_i32(TCP_SERVER_CONFIG_WHITELIST_MASK_NAME, &mask) == 0) {
        cfg->whitelist_mask.addr = (uint32_t)mask;
    }
}

void tcp_server_config_save(const tcp_server_config_t *cfg){
    int8_t enabled;
    int16_t port;
    int32_t ip;
    int32_t mask;

    if (cfg == NULL) {
        return;
    }

    enabled = cfg->enabled ? 1 : 0;
    port = (int16_t)cfg->port;
    ip = (int32_t)cfg->whitelist_ip.addr;
    mask = (int32_t)cfg->whitelist_mask.addr;

    configdb_set_i8(TCP_SERVER_CONFIG_ENABLED_NAME, &enabled);
    configdb_set_i16(TCP_SERVER_CONFIG_PORT_NAME, &port);
    configdb_set_i32(TCP_SERVER_CONFIG_WHITELIST_IP_NAME, &ip);
    configdb_set_i32(TCP_SERVER_CONFIG_WHITELIST_MASK_NAME, &mask);

    memcpy(&g_cfg, cfg, sizeof(tcp_server_config_t));
}

void tcp_server_config_apply(const tcp_server_config_t *cfg){
    if (cfg == NULL) {
        return;
    }

    memcpy(&g_cfg, cfg, sizeof(tcp_server_config_t));
    if(!cfg->enabled){
        os_mutex_lock(&g_clinet_mutex, 100);
        if(g_client_nc != NULL){
            tcps_debug("APPLY disconnect client nc=%p", g_client_nc);
            netconn_close(g_client_nc);
            netconn_delete(g_client_nc);
            g_client_nc = NULL;
        }
        os_mutex_unlock(&g_clinet_mutex);
    }
}

bool tcp_server_get_client_info( ip4_addr_t *addr, uint16_t *port ){
    if(os_mutex_lock(&g_clinet_mutex, 0) != 0){
        return false;
    }
    if (g_client_nc == NULL) {
        return false;
    }

    if (addr != NULL) {
        *addr = g_client_nc->pcb.tcp->remote_ip;
    }
    if (port != NULL) {
        *port = g_client_nc->pcb.tcp->remote_port;
    }
    os_mutex_unlock(&g_clinet_mutex);
    return true;
}

static void tcp_client_loop( struct netconn *client ){
    err_t err;
    struct netbuf *nb = NULL;

    while (1) {
        err = netconn_recv(client, &nb);
        if (err != ERR_OK || nb == NULL) {
            tcps_debug("recv end err=%d nb=%p", (int)err, nb);
            break;
        }
        
        netbuf_first(nb);
        do{
            uint8_t* data;
            uint16_t data_len;
            
            netbuf_data(nb, (void**)&data, &data_len);
            if(g_rx_cb != NULL){
                g_rx_cb(data, data_len);
            }
        }while (netbuf_next(nb) >= 0);

        netbuf_delete(nb);
        nb = NULL;
    }

    if (nb != NULL) {
        netbuf_delete(nb);
    }
}

static void tcp_server_task( void *arg ){
    struct netconn *listen = NULL;
    err_t err;
    
    (void)arg;

    tcps_debug("server start");

    listen = netconn_new(NETCONN_TCP);
    netconn_bind(listen, IP_ADDR_ANY, g_cfg.port);
    netconn_listen(listen);

    tcps_debug("listening on port %d", g_cfg.port);

    while (1) {
        if(!g_cfg.enabled){
            os_sleep_ms(3000);
            continue;
        }
        struct netconn *client = NULL;
        err = netconn_accept(listen, &client);
        tcps_debug("accept ret err=%d client=%p", (int)err, client);

        if (err != ERR_OK) {
            tcps_debug("accept failed err=%d client=%p", (int)err, client);
            if (client != NULL) {
                netconn_close(client);
                netconn_delete(client);
            }
            continue;
        }

        ip4_addr_t client_ip = client->pcb.tcp->remote_ip;
        if (!tcp_server_ip_allowed(&client_ip)) {
            tcps_debug("client reject ip=%s", ip4addr_ntoa(&client_ip));
            netconn_close(client);
            netconn_delete(client);
            continue;
        }

        tcps_debug("client accepted nc=%p", client);

        os_mutex_lock(&g_clinet_mutex, 100);
        g_client_nc = client;
        os_mutex_unlock(&g_clinet_mutex);

        tcp_client_loop(client);

        tcps_debug("closing client nc=%p", client);
        os_mutex_lock(&g_clinet_mutex, 100);
        g_client_nc = NULL;
        os_mutex_unlock(&g_clinet_mutex);
        netconn_close(client);
        netconn_delete(client);
    }
}

int32_t tcp_server_init(tcp_server_rx_cb_t cb){
    g_rx_cb = cb;
    os_mutex_init(&g_clinet_mutex);
    os_mutex_unlock(&g_clinet_mutex);

    tcp_server_config_load(&g_cfg);
    tcp_server_config_save(&g_cfg);
    
    (void)os_task_init((const uint8 *)"tcps", &g_tcps_rx_task, tcp_server_task, 0);
    (void)os_task_set_stacksize(&g_tcps_rx_task, TCP_SERVER_TASK_STACK);
    (void)os_task_set_priority(&g_tcps_rx_task, TCP_SERVER_TASK_PRIO);
    (void)os_task_run(&g_tcps_rx_task);

    return 0;
}

int32_t tcp_server_send(const uint8_t *data, uint32_t len){
    os_mutex_lock(&g_clinet_mutex, 10);

    if(g_client_nc == NULL){
        os_mutex_unlock(&g_clinet_mutex);
        return 1;
    }

    struct tcp_pcb *pcb = g_client_nc->pcb.tcp;

    if(pcb == NULL){
        os_mutex_unlock(&g_clinet_mutex);
        return 2;
    }

    if(tcp_sndbuf(pcb) < len){
        netconn_close(g_client_nc);
        netconn_delete(g_client_nc);
        os_mutex_unlock(&g_clinet_mutex);
        return 3;
    }

    netconn_write(g_client_nc, data, len, NETCONN_COPY);

    os_mutex_unlock(&g_clinet_mutex);
    return 0;
}
