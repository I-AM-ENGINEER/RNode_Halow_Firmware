#include "tcp_server.h"

#include "sys_config.h"
#include "lwip/tcp.h"
#include "lwip/tcpip.h"
#include "configdb.h"
#include "lwip/ip4_addr.h"
#include "lwip/ip_addr.h"
#include "lwip/netbuf.h"
#include "lwip/api.h"
#include "lib/lwrb/lwrb.h"
#include <string.h>

//#define TCP_SERVER_DEBUG

#define TCP_SERVER_RF_TO_TCP_BUFF_COUNT     8

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

struct rb_tx_package{
    uint8_t* data;
    size_t len;
};

static tcp_server_config_t g_cfg;
static tcp_server_rx_cb_t g_rx_cb;
static lwrb_t g_tx_rb;
static struct rb_tx_package* g_tx_rb_buff[TCP_SERVER_RF_TO_TCP_BUFF_COUNT];
static struct os_mutex g_tx_rb_mutex;

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
}

bool tcp_server_get_client_info(ip4_addr_t *addr, uint16_t *port){
    bool ok = false;

    if (os_mutex_lock(&g_clinet_mutex, 0) != 0){
        return false;
    }

    if (g_client_nc != NULL &&
        g_client_nc->pcb.tcp != NULL) {

        if (addr != NULL) {
            ip4_addr_copy(*addr, g_client_nc->pcb.tcp->remote_ip);
        }

        if (port != NULL) {
            *port = g_client_nc->pcb.tcp->remote_port;
        }

        ok = true;
    }

    os_mutex_unlock(&g_clinet_mutex);
    return ok;
}

static void tcp_client_loop( struct netconn *client ){
    err_t err;
    struct netbuf *nb = NULL;

    while (1) {
        if(!g_cfg.enabled){
            os_sleep_ms(3000);
            break;
        }

        // Send if needed
        os_mutex_lock(&g_tx_rb_mutex, OS_MUTEX_WAIT_FOREVER);
        struct rb_tx_package tx_package;
        if(lwrb_read(&g_tx_rb, &tx_package, sizeof(tx_package)) == sizeof(tx_package)){
            size_t offset = 0;
            uint32_t wb_cnt = 0;

            while (offset < tx_package.len) {
                size_t written = 0;
                err = netconn_write_partly(
                    client,
                    tx_package.data + offset,
                    tx_package.len - offset,
                    NETCONN_COPY,
                    &written
                );

                if (written > 0) {
                    offset += written;
                    wb_cnt = 0;
                }

                if (err == ERR_OK) {
                    continue;
                }

                if (err == ERR_WOULDBLOCK) {
                    if (++wb_cnt > 1000) {
                        tcps_debug("send stuck -> close");
                        break;
                    }
                    os_sleep_ms(1);
                    continue;
                }

                tcps_debug("send failed err=%d offset=%u len=%u",
                        (int)err,
                        (unsigned)offset,
                        (unsigned)tx_package.len);
                break;
            }

            os_free(tx_package.data);

            if (offset < tx_package.len) {
                os_mutex_unlock(&g_tx_rb_mutex);
                break;
            }
        }
        os_mutex_unlock(&g_tx_rb_mutex);
        
        // Receive if needed
        err = netconn_recv(client, &nb);

        if(err == ERR_WOULDBLOCK) {
            os_sleep_ms(1); // Not very efficient, but easy
            continue;
        }

        if(err != ERR_OK || nb == NULL) {
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
    netconn_listen_with_backlog(listen, 0);

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
                tcps_debug("1DELETE nc=%p", client);
                netconn_delete(client);
            }
            continue;
        }

        ip4_addr_t client_ip = client->pcb.tcp->remote_ip;
        if (!tcp_server_ip_allowed(&client_ip)) {
            tcps_debug("client reject ip=%s", ip4addr_ntoa(&client_ip));
            netconn_close(client);
            tcps_debug("2DELETE nc=%p", client);
            netconn_delete(client);
            continue;
        }

        tcps_debug("client accepted nc=%p", client);

        os_mutex_lock(&g_clinet_mutex, OS_MUTEX_WAIT_FOREVER);
        //netconn_set_recvtimeout(client, 5000);
        netconn_set_sendtimeout(client, 1000);
        netconn_set_nonblocking(client, 1);
        tcp_nagle_disable(client->pcb.tcp);
        client->pcb.tcp->so_options |= SOF_KEEPALIVE;
        client->pcb.tcp->keep_idle  = 5000;
        client->pcb.tcp->keep_intvl = 2000;
        client->pcb.tcp->keep_cnt   = 3;
        g_client_nc = client;
        os_mutex_unlock(&g_clinet_mutex);

        tcp_client_loop(client);

        tcps_debug("closing client nc=%p", client);
        os_mutex_lock(&g_clinet_mutex, OS_MUTEX_WAIT_FOREVER);
        g_client_nc = NULL;
        netconn_close(client);
        tcps_debug("3DELETE nc=%p", client);
        netconn_delete(client);
        os_mutex_unlock(&g_clinet_mutex);
    }
}

int32_t tcp_server_init(tcp_server_rx_cb_t cb){
    g_rx_cb = cb;
    lwrb_init(&g_tx_rb, g_tx_rb_buff, sizeof(g_tx_rb_buff));
    os_mutex_init(&g_clinet_mutex);
    os_mutex_init(&g_tx_rb_mutex);

    tcp_server_config_load(&g_cfg);
    tcp_server_config_save(&g_cfg);
    
    (void)os_task_init((const uint8 *)"tcps", &g_tcps_rx_task, tcp_server_task, 0);
    (void)os_task_set_stacksize(&g_tcps_rx_task, TCP_SERVER_TASK_STACK);
    (void)os_task_set_priority(&g_tcps_rx_task, TCP_SERVER_TASK_PRIO);
    (void)os_task_run(&g_tcps_rx_task);

    return 0;
}

int32_t tcp_server_send(const uint8_t *data, uint32_t len){
    int32_t res;
    struct rb_tx_package pkg;

    size_t free = lwrb_get_free(&g_tx_rb);
    if (free < sizeof(pkg)) {
        return -1;
    }

	pkg.data = os_malloc(len);
    if(pkg.data == NULL){
        return -2;
    }
    
    memcpy(pkg.data, data, len);
    pkg.len = len;
    res = os_mutex_lock(&g_tx_rb_mutex, 0);
    if(res != 0){
        os_free(pkg.data);
        return -3;
    }
    
    uint32_t writen = lwrb_write(&g_tx_rb, &pkg, sizeof(pkg));
    if(writen != sizeof(pkg)){
        os_free(pkg.data);
        os_mutex_unlock(&g_tx_rb_mutex);
        return -4;
    }
    os_mutex_unlock(&g_tx_rb_mutex);
    return 0;
}
