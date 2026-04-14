#include "sys_config.h"
#define LOG_LOCAL_LEVEL LOG_LEVEL_TCP_SERVER

#include "tcp_server.h"

#include "lwip/tcp.h"
#include "lwip/tcpip.h"
#include "configdb.h"
#include "lwip/ip4_addr.h"
#include "lwip/ip_addr.h"
#include "lwip/netbuf.h"
#include "lwip/api.h"
#include "lib/lwrb/lwrb.h"
#include "lib/logc/log.h"
#include "net_ip.h"

#include <string.h>

#define TCP_SERVER_RF_TO_TCP_BUFF_COUNT             (8)
#define TCP_SERVER_SEND_STALL_LIMIT_MS              (10000)

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

static inline void tcp_server_cfg_log_trace( const char *tag, const tcp_server_config_t *cfg ){
    char ipbuf[16];
    char maskbuf[16];

    if( cfg == NULL ){
        return;
    }

    ip4addr_ntoa_r(&cfg->whitelist_ip, ipbuf, sizeof(ipbuf));
    ip4addr_ntoa_r(&cfg->whitelist_mask, maskbuf, sizeof(maskbuf));

    log_trace("%s en=%d port=%u wip=%s wmask=%s",
              tag ? tag : "CFG",
              cfg->enabled ? 1 : 0,
              (unsigned)cfg->port,
              ipbuf,
              maskbuf);
}

static inline void tcp_server_cfg_log_debug( const char *tag, const tcp_server_config_t *cfg ){
    char ipbuf[16];
    char maskbuf[16];

    if( cfg == NULL ){
        return;
    }

    ip4addr_ntoa_r(&cfg->whitelist_ip, ipbuf, sizeof(ipbuf));
    ip4addr_ntoa_r(&cfg->whitelist_mask, maskbuf, sizeof(maskbuf));

    log_debug("%s en=%d port=%u wip=%s wmask=%s",
              tag ? tag : "CFG",
              cfg->enabled ? 1 : 0,
              (unsigned)cfg->port,
              ipbuf,
              maskbuf);
}

static bool tcp_server_ip_allowed( const ip4_addr_t *addr ){
    uint32_t ip;
    uint32_t wl_ip;
    uint32_t wl_mask;

    if( addr == NULL ){
        return false;
    }

    wl_mask = ip4_addr_get_u32(&g_cfg.whitelist_mask);
    if( wl_mask == 0 ){
        return true;
    }

    ip    = ip4_addr_get_u32(addr);
    wl_ip = ip4_addr_get_u32(&g_cfg.whitelist_ip);

    return ((ip & wl_mask) == (wl_ip & wl_mask));
}

void tcp_server_config_load( tcp_server_config_t *cfg ){
    int8_t enabled;
    int16_t port;
    int32_t ip;
    int32_t mask;

    if( cfg == NULL ){
        return;
    }

    cfg->enabled = TCP_SERVER_CONFIG_ENABLED_DEF ? true : false;
    cfg->port = TCP_SERVER_CONFIG_PORT_DEF;
    cfg->whitelist_ip.addr = (uint32_t)TCP_SERVER_CONFIG_WHITELIST_IP_DEF;
    cfg->whitelist_mask.addr = (uint32_t)TCP_SERVER_CONFIG_WHITELIST_MASK_DEF;

    if( configdb_get_i8(TCP_SERVER_CONFIG_ENABLED_NAME, &enabled) == 0 ){
        cfg->enabled = enabled ? true : false;
    }
    if( configdb_get_i16(TCP_SERVER_CONFIG_PORT_NAME, &port) == 0 ){
        cfg->port = (uint16_t)port;
    }
    if( configdb_get_i32(TCP_SERVER_CONFIG_WHITELIST_IP_NAME, &ip) == 0 ){
        cfg->whitelist_ip.addr = (uint32_t)ip;
    }
    if( configdb_get_i32(TCP_SERVER_CONFIG_WHITELIST_MASK_NAME, &mask) == 0 ){
        cfg->whitelist_mask.addr = (uint32_t)mask;
    }

    tcp_server_cfg_log_trace("LOAD", cfg);
}

void tcp_server_config_save( const tcp_server_config_t *cfg ){
    int8_t enabled;
    int16_t port;
    int32_t ip;
    int32_t mask;

    if( cfg == NULL ){
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
    tcp_server_cfg_log_debug("SAVE", cfg);
}

void tcp_server_config_apply( const tcp_server_config_t *cfg ){
    if( cfg == NULL ){
        return;
    }

    memcpy(&g_cfg, cfg, sizeof(tcp_server_config_t));
    tcp_server_cfg_log_debug("APPLY", cfg);
}

bool tcp_server_get_client_info( ip4_addr_t *addr, uint16_t *port ){
    bool ok = false;

    if( os_mutex_lock(&g_clinet_mutex, 0) != 0 ){
        return false;
    }

    if( g_client_nc != NULL &&
        g_client_nc->pcb.tcp != NULL ){

        if( addr != NULL ){
            ip4_addr_copy(*addr, g_client_nc->pcb.tcp->remote_ip);
        }

        if( port != NULL ){
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

    while( 1 ){
        if( !g_cfg.enabled ){
            os_sleep_ms(3000);
            break;
        }

        os_mutex_lock(&g_tx_rb_mutex, OS_MUTEX_WAIT_FOREVER);
        struct rb_tx_package tx_package;
        if( lwrb_read(&g_tx_rb, &tx_package, sizeof(tx_package)) == sizeof(tx_package) ){
            size_t offset = 0;
            uint32_t wb_cnt = 0;

            while( offset < tx_package.len ){
                size_t written = 0;
                err = netconn_write_partly(
                    client,
                    tx_package.data + offset,
                    tx_package.len - offset,
                    NETCONN_COPY,
                    &written
                );

                if( written > 0 ){
                    offset += written;
                    wb_cnt = 0;
                }

                if( err == ERR_OK ){
                    continue;
                }

                if( err == ERR_WOULDBLOCK ){
                    if( ++wb_cnt > TCP_SERVER_SEND_STALL_LIMIT_MS ){
                        log_warn("send stuck -> close");
                        break;
                    }
                    os_sleep_ms(1);
                    continue;
                }

                log_warn("send failed err=%d offset=%u len=%u",
                         (int)err,
                         (unsigned)offset,
                         (unsigned)tx_package.len);
                break;
            }

            os_free(tx_package.data);

            if( offset < tx_package.len ){
                os_mutex_unlock(&g_tx_rb_mutex);
                break;
            }
        }
        os_mutex_unlock(&g_tx_rb_mutex);

        err = netconn_recv(client, &nb);

        if( err == ERR_WOULDBLOCK ){
            os_sleep_ms(1);
            continue;
        }

        if( err != ERR_OK || nb == NULL ){
            log_debug("recv end err=%d nb=%p", (int)err, nb);
            break;
        }

        netbuf_first(nb);
        do{
            uint8_t *data;
            uint16_t data_len;

            netbuf_data(nb, (void **)&data, &data_len);
            if( g_rx_cb != NULL ){
                g_rx_cb(data, data_len);
            }
        }while( netbuf_next(nb) >= 0 );

        netbuf_delete(nb);
        nb = NULL;
    }

    if( nb != NULL ){
        netbuf_delete(nb);
    }
}

static void tcp_server_task( void *arg ){
    struct netconn *listen = NULL;
    err_t err;

    (void)arg;

    log_info("server start");

    listen = netconn_new(NETCONN_TCP);
    if( listen == NULL ){
        log_error("netconn_new failed");
        return;
    }

    err = netconn_bind(listen, IP_ADDR_ANY, g_cfg.port);
    if( err != ERR_OK ){
        log_error("bind failed err=%d port=%u", (int)err, (unsigned)g_cfg.port);
        netconn_delete(listen);
        return;
    }

    err = netconn_listen_with_backlog(listen, 0);
    if( err != ERR_OK ){
        log_error("listen failed err=%d port=%u", (int)err, (unsigned)g_cfg.port);
        netconn_delete(listen);
        return;
    }

    log_info("listening on port %u", (unsigned)g_cfg.port);

    while( 1 ){
        if( !g_cfg.enabled ){
            os_sleep_ms(3000);
            continue;
        }

        struct netconn *client = NULL;
        err = netconn_accept(listen, &client);
        log_trace("accept err=%d client=%p", (int)err, client);

        if( err != ERR_OK ){
            log_warn("accept failed err=%d client=%p", (int)err, client);
            if( client != NULL ){
                netconn_close(client);
                netconn_delete(client);
            }
            continue;
        }

        ip4_addr_t client_ip = client->pcb.tcp->remote_ip;
        if( !tcp_server_ip_allowed(&client_ip) ){
            log_warn("client reject ip=%s", ip4addr_ntoa(&client_ip));
            netconn_close(client);
            netconn_delete(client);
            continue;
        }

        log_info("client accepted ip=%s port=%u nc=%p",
                 ip4addr_ntoa(&client_ip),
                 (unsigned)client->pcb.tcp->remote_port,
                 client);

        os_mutex_lock(&g_clinet_mutex, OS_MUTEX_WAIT_FOREVER);
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

        log_info("closing client nc=%p", client);
        os_mutex_lock(&g_clinet_mutex, OS_MUTEX_WAIT_FOREVER);
        g_client_nc = NULL;
        netconn_close(client);
        netconn_delete(client);
        os_mutex_unlock(&g_clinet_mutex);
    }
}

void tcp_server_init( tcp_server_rx_cb_t cb ){
    g_rx_cb = cb;
    lwrb_init(&g_tx_rb, g_tx_rb_buff, sizeof(g_tx_rb_buff));
    os_mutex_init(&g_clinet_mutex);
    os_mutex_init(&g_tx_rb_mutex);

    tcp_server_config_load(&g_cfg);
    tcp_server_config_save(&g_cfg);

    os_task_init((const uint8 *)"tcps", &g_tcps_rx_task, tcp_server_task, 0);
    os_task_set_stacksize(&g_tcps_rx_task, TCP_SERVER_TASK_STACK);
    os_task_set_priority(&g_tcps_rx_task, TCP_SERVER_TASK_PRIO);
    os_task_run(&g_tcps_rx_task);
    log_info("tcp server init ok");
}

int32_t tcp_server_send( const uint8_t *data, uint32_t len ){
    int32_t res;
    struct rb_tx_package pkg;
    size_t free = lwrb_get_free(&g_tx_rb);
    uint32_t writen;

    if( free < sizeof(pkg) ){
        log_trace("send queue full free=%u need=%u",
                  (unsigned)free,
                  (unsigned)sizeof(pkg));
        return -1;
    }

    pkg.data = os_malloc(len);
    if( pkg.data == NULL ){
        log_warn("send malloc failed len=%u", (unsigned)len);
        return -2;
    }

    memcpy(pkg.data, data, len);
    pkg.len = len;

    res = os_mutex_lock(&g_tx_rb_mutex, 0);
    if( res != 0 ){
        os_free(pkg.data);
        return -3;
    }

    writen = lwrb_write(&g_tx_rb, &pkg, sizeof(pkg));
    if( writen != sizeof(pkg) ){
        os_free(pkg.data);
        os_mutex_unlock(&g_tx_rb_mutex);
        log_warn("send rb write failed wr=%u need=%u",
                 (unsigned)writen,
                 (unsigned)sizeof(pkg));
        return -4;
    }

    os_mutex_unlock(&g_tx_rb_mutex);
    return 0;
}
