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
#include "halow_ack.h"
#include "halow.h"                 /* halow_config_t etc. */
extern halow_tx_dbg_t g_tx_dbg;    /* rf_tcp_dropped counter (halow.c) */

#include <string.h>

#define TCP_SERVER_RF_TO_TCP_BUFF_COUNT             (32)
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
static uint8_t g_tx_rb_buff[TCP_SERVER_RF_TO_TCP_BUFF_COUNT * sizeof(struct rb_tx_package)];
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

    /* Snapshot the pcb pointer ONCE: err_tcp (tcpip thread) can NULL it at any
     * instant; re-reading g_client_nc->pcb.tcp between the check and each use
     * could pass the test on one load and fault on the next. A stale non-NULL
     * (freed-between) pointer can still yield a garbage IP read -- harmless
     * here (display only), never a wild write. */
    struct tcp_pcb *pcb = ( g_client_nc != NULL ) ? g_client_nc->pcb.tcp : NULL;
    if( pcb != NULL ){

        if( addr != NULL ){
            ip4_addr_copy(*addr, pcb->remote_ip);
        }

        if( port != NULL ){
            *port = pcb->remote_port;
        }

        ok = true;
    }

    os_mutex_unlock(&g_clinet_mutex);
    return ok;
}

static void tcp_server_tx_queue_clear( void ){
    struct rb_tx_package pkg;

    os_mutex_lock(&g_tx_rb_mutex, OS_MUTEX_WAIT_FOREVER);

    while( lwrb_read(&g_tx_rb, &pkg, sizeof(pkg)) == sizeof(pkg) ){
        if( pkg.data != NULL ){
            os_free(pkg.data);
        }
    }

    lwrb_reset(&g_tx_rb);
    os_mutex_unlock(&g_tx_rb_mutex);

    log_debug("tx queue cleared");
}

/* Feed the netbuf's bytes to the TX decoder starting at (*chunk, *ofs).
 * Returns 0 when the whole netbuf was consumed (caller may free it), or the
 * g_rx_cb status: HALOW_ACK_TX_THROTTLE stops at the exact resume position
 * (cursor updated); other negatives mean the frame owns a retry slot already
 * -- the chunk is fully consumed, caller just paces. */
static int32_t tcp_server_feed_netbuf( struct netbuf *nb, uint16_t *chunk, uint16_t *ofs ){
    netbuf_first(nb);
    uint16_t ci = 0u;
    for( ;; ){
        uint8_t *data;
        uint16_t dlen;
        netbuf_data(nb, (void **)&data, &dlen);
        if( (ci > *chunk || (ci == *chunk && *ofs < dlen)) && g_rx_cb != NULL ){
            uint16_t consumed = 0u;
            int32_t r = g_rx_cb(data + *ofs, (uint16_t)(dlen - *ofs), &consumed);
            if( r == HALOW_ACK_TX_THROTTLE ){
                uint32_t adv = consumed;
                if( adv > (uint32_t)(dlen - *ofs) ) adv = (uint32_t)(dlen - *ofs);
                *ofs = (uint16_t)(*ofs + adv);
                if( *ofs >= dlen ){ *chunk = (uint16_t)(ci + 1u); *ofs = 0u; }
                return r;
            }
            *ofs = 0u;
            *chunk = (uint16_t)(ci + 1u);
        }
        if( netbuf_next(nb) < 0 ) break;
        ci++;
    }
    return 0;
}

static void tcp_client_loop( struct netconn *client ){
    err_t err;
    struct netbuf *nb = NULL;
    /* TX backpressure: when the RF/ACK TX path is saturated, g_rx_cb returns
     * HALOW_ACK_TX_THROTTLE. We then SKIP netconn_recv so lwIP closes the TCP
     * recv window and the blasting TCP sender paces itself -- while STILL
     * draining the RF->TCP ring above every iteration (RX delivery to the app
     * never stalls). This is the only way to absorb a full TCP blast without
     * dropping frames or starving the receive direction. */
    uint32_t tx_throttle_ms = 0u;
#define TCP_SERVER_TX_THROTTLE_MS  5u
    struct netbuf *held_nb = NULL;
    uint16_t held_chunk = 0u, held_ofs = 0u;

    while( 1 ){
        if( !g_cfg.enabled ){
            os_sleep_ms(3000);
            break;
        }

        /* Pop ONE package under the mutex, then write it to the client with
         * the mutex RELEASED. The old code held g_tx_rb_mutex across the whole
         * blocking write-retry loop (up to the 10 s stall limit): any period
         * where the host read side was slow-but-alive made every producer's
         * try-lock fail -> RF->TCP frames were dropped while up to 31 of 32
         * ring slots sat free. */
        struct rb_tx_package tx_package;

        for( uint32_t burst = 0u; burst < 4u; burst++ ){
            bool have_pkg = false;
            os_mutex_lock(&g_tx_rb_mutex, OS_MUTEX_WAIT_FOREVER);
            if( lwrb_read(&g_tx_rb, &tx_package, sizeof(tx_package)) == sizeof(tx_package) ){
                have_pkg = true;
            }
            os_mutex_unlock(&g_tx_rb_mutex);
            if( !have_pkg ) break;
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
                /* Partial/failed host write: the undelivered tail is lost --
                 * count it, or RF->TCP loss stays invisible (invariant 3). */
                g_tx_dbg.rf_tcp_dropped++;
                break;
            }
        }

        /* TX backpressure: while the RF/ACK TX path is saturated, g_rx_cb returns
         * HALOW_ACK_TX_THROTTLE. Parked netbufs wait in a bounded FIFO; we KEEP
         * draining netconn_recv while the FIFO has room so lwIP's recvmbox can
         * never overflow (mbox overflow -> sys_mbox_trypost fails inside the
         * recv event callback -> lwIP aborts the connection with ERR_ABRT --
         * the blast-kill measured as recv err=-15 after ~140 frames). With
         * FIFO 8 + recvmbox 16 netbufs of parking versus a 4*MSS window the
         * reader always stays ahead: full FIFO just means we stop reading, the
         * recv window closes, the blasting sender parks in its own kernel
         * buffers -- lossless pacing instead of an abort. */
        if( tx_throttle_ms > 0u ){
            tx_throttle_ms--;
            os_sleep_ms(1);
            continue;
        }

        g_tx_dbg.tcps_held = (held_nb != NULL) ? 1u : 0u;
        if( held_nb != NULL ){
            uint16_t chunk = held_chunk, ofs = held_ofs;
            int32_t r = tcp_server_feed_netbuf(held_nb, &chunk, &ofs);
            if( r == HALOW_ACK_TX_THROTTLE ){
                held_chunk = chunk; held_ofs = ofs;
                os_sleep_ms(1);
                continue;
            }
            if( r < 0 ) tx_throttle_ms = TCP_SERVER_TX_THROTTLE_MS;
            netbuf_delete(held_nb);
            held_nb = NULL;
            continue;
        }

        if( !halow_ack_tx_ready() ){
            extern int32_t rns_tcp_retry_held(void);
            (void)rns_tcp_retry_held();
            os_sleep_ms(2);
            continue;
        }

        g_tx_dbg.tcps_beat++;
        err = netconn_recv(client, &nb);

        if( err == ERR_WOULDBLOCK ){
            os_sleep_ms(1);
            continue;
        }

        if( err != ERR_OK || nb == NULL ){
            g_tx_dbg.tcps_last_err = (int32_t)err;
            log_warn("recv end err=%d nb=%p", (int)err, nb);
            break;
        }
        g_tx_dbg.tcps_recv_ok++;

        {
            uint16_t chunk = 0u, ofs = 0u;
            int32_t r = tcp_server_feed_netbuf(nb, &chunk, &ofs);
            if( r == HALOW_ACK_TX_THROTTLE ){
                held_nb = nb; held_chunk = chunk; held_ofs = ofs;
                nb = NULL;
                continue;
            }
            if( r < 0 ) tx_throttle_ms = TCP_SERVER_TX_THROTTLE_MS;
        }

        netbuf_delete(nb);
        nb = NULL;
    }

    if( held_nb != NULL ){
        netbuf_delete(held_nb);
    }

    if( nb != NULL ){
        netbuf_delete(nb);
    }
}

/* Runs in the tcpip thread via tcpip_callback(): the only context allowed to
 * touch pcb fields with core locking disabled. If the connection died before
 * the callback ran, err_tcp has already NULLed pcb.tcp -- just skip. */
static void tcp_server_cfg_keepalive( void *arg ){
    struct netconn *nc = (struct netconn *)arg;
    if( nc == NULL || nc->pcb.tcp == NULL ) return;
    tcp_nagle_disable(nc->pcb.tcp);
    nc->pcb.tcp->so_options |= SOF_KEEPALIVE;
    nc->pcb.tcp->keep_idle  = 5000;
    nc->pcb.tcp->keep_intvl = 2000;
    nc->pcb.tcp->keep_cnt   = 3;
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

        /* NEVER touch client->pcb.* directly here: err_tcp() can NULL/free the
         * pcb while the netconn still sits in the accept mbox (lwIP 2.1.2
         * api_msg.c), and a RST can free it between a NULL check and a raw
         * field write -- the store then lands on freed memory or address ~0
         * and faults (the historical exception-loop crash PC was exactly this
         * keepalive block). Netconn-level option setters exist for everything
         * and are serialized in the tcpip thread. */
        struct tcp_pcb *cpcb = client->pcb.tcp;   /* snapshot once */
        if( cpcb == NULL ){
            log_warn("accept: null pcb, drop client");
            netconn_delete(client);
            continue;
        }

        ip4_addr_t client_ip = cpcb->remote_ip;
        if( !tcp_server_ip_allowed(&client_ip) ){
            log_warn("client reject ip=%s", ip4addr_ntoa(&client_ip));
            netconn_close(client);
            netconn_delete(client);
            continue;
        }

        log_info("client accepted ip=%s port=%u nc=%p",
                 ip4addr_ntoa(&client_ip),
                 (unsigned)cpcb->remote_port,
                 client);

        tcp_server_tx_queue_clear();

        {
            extern void rns_tcp_session_reset(void);
            rns_tcp_session_reset();
        }

        /* Keepalive/nagle config must run in the tcpip thread (LWIP core
         * locking is disabled in this build, so only that thread may touch
         * pcb fields): err_tcp can free the pcb at any moment from tcpip
         * context, and a raw write here lands on freed memory or address ~0
         * -- the exact PC of the historical exception-loop crash. */
        tcpip_callback(tcp_server_cfg_keepalive, client);

        os_mutex_lock(&g_clinet_mutex, OS_MUTEX_WAIT_FOREVER);
        netconn_set_sendtimeout(client, 1000);
        netconn_set_nonblocking(client, 1);
        g_client_nc = client;
        os_mutex_unlock(&g_clinet_mutex);

        tcp_client_loop(client);

        log_info("closing client nc=%p", client);
        os_mutex_lock(&g_clinet_mutex, OS_MUTEX_WAIT_FOREVER);
        g_client_nc = NULL;
        os_mutex_unlock(&g_clinet_mutex);
        tcp_server_tx_queue_clear();
        
        netconn_close(client);
        netconn_delete(client);

        /* Bound the accept/close cycle rate: a client that connects and dies
         * instantly (bench: scripted reconnect storms) spins this loop at
         * full speed, and the tight accept->raw-pcb-config->delete churn is
         * exactly the window where lwIP pcb/netconn lifetimes race. */
        os_sleep_ms(50);
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
    uint32_t writen;

    /* Check free space INSIDE the mutex: reading it before locking is a TOCTOU
     * -- the consumer only grows free space today, but any second producer (or
     * a consumer change) could shrink it in between, and lwrb_write would then
     * do a PARTIAL write, leaving a torn rb_tx_package in the ring whose
     * os_free() later detonates on a garbage pointer. */
    res = os_mutex_lock(&g_tx_rb_mutex, 0);
    if( res != 0 ){
        return -3;
    }
    if( lwrb_get_free(&g_tx_rb) < sizeof(pkg) ){
        os_mutex_unlock(&g_tx_rb_mutex);
        log_trace("send queue full");
        return -1;
    }

    pkg.data = os_malloc(len);
    if( pkg.data == NULL ){
        os_mutex_unlock(&g_tx_rb_mutex);
        log_warn("send malloc failed len=%u", (unsigned)len);
        return -2;
    }

    memcpy(pkg.data, data, len);
    pkg.len = len;

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
