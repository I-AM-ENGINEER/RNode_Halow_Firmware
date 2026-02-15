#include "tcp_server.h"

#include "lwip/tcp.h"
#include "lwip/tcpip.h"
#include "sys_config.h"
#include "configdb.h"
#include "lwip/ip4_addr.h"
#include "lwip/ip_addr.h"
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

struct tcp_tx_package {
    struct tcp_pcb* pcb;
    uint16_t len;
    uint8_t data[0];
};

static struct os_semaphore g_rxq_sem;
static struct os_semaphore g_yield_sem;
static struct tcp_pcb* g_listen_pcb;
static struct tcp_pcb* g_client_pcb;
static uint32_t g_client_gen;
static tcp_server_config_t g_cfg;
static tcp_server_rx_cb_t g_rx_cb;
static uint8_t* g_rx_pkg_buf;

/* RX worker: process long g_rx_cb() outside tcpip thread and call tcp_recved() only after processing. */
#ifndef TCP_SERVER_RX_QUEUE_LEN
#define TCP_SERVER_RX_QUEUE_LEN              4
#endif

#ifndef TCP_SERVER_RX_TASK_STACK
#define TCP_SERVER_RX_TASK_STACK             2048
#endif

#ifndef TCP_SERVER_RX_TASK_PRIO
#define TCP_SERVER_RX_TASK_PRIO              20
#endif

#ifndef TCP_SERVER_BARRIER
#define TCP_SERVER_BARRIER()                 __sync_synchronize()
#endif

typedef struct {
    struct tcp_pcb *pcb;
    struct pbuf *p;
    uint32_t gen;
} tcp_server_rx_job_t;

typedef struct {
    struct tcp_pcb *pcb;
    struct pbuf *p;
    uint16_t len;
    uint32_t gen;
} tcp_server_rx_done_t;

static struct os_task g_tcps_rx_task;
static bool g_tcps_rx_task_started;
static volatile uint32_t g_rxq_wr;
static volatile uint32_t g_rxq_rd;
static tcp_server_rx_job_t g_rxq[TCP_SERVER_RX_QUEUE_LEN];

static void tcp_server_rx_task( void *arg );
static int32_t tcp_server_rx_worker_init( void );
static bool tcp_server_rxq_push( struct tcp_pcb *pcb, struct pbuf *p, uint32_t gen );
static bool tcp_server_rxq_pop( tcp_server_rx_job_t *out );
static void tcp_server_rx_done_cb( void *arg );
static void tcp_server_pbuf_free_cb( void *arg );

static err_t tcp_server_accept_callback(void *arg, struct tcp_pcb *newpcb, err_t err);

#ifdef TCP_SERVER_DEBUG
static inline void tcp_server_config_debug_print( const char *tag,
                                                  const tcp_server_config_t *cfg ){
    char ipbuf[16];
    char maskbuf[16];

    if (cfg == NULL) {
        return;
    }

    ip4addr_ntoa_r((const ip4_addr_t *)&cfg->whitelist_ip,   ipbuf,   sizeof(ipbuf));
    ip4addr_ntoa_r((const ip4_addr_t *)&cfg->whitelist_mask, maskbuf, sizeof(maskbuf));

    tcps_debug("%s en=%d port=%u wlst_ip=%s wlst_mask=%s",
               tag ? tag : "CFG",
               cfg->enabled ? 1 : 0,
               (unsigned)cfg->port,
               ipbuf,
               maskbuf);
}
#else
#define tcp_server_config_debug_print(tag, cfg) do { } while (0)
#endif

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

    tcp_server_config_debug_print("LOAD", cfg);
}

void tcp_server_config_save(const tcp_server_config_t *cfg){
    int8_t enabled;
    int16_t port;
    int32_t ip;
    int32_t mask;

    if (cfg == NULL) {
        return;
    }

    tcp_server_config_debug_print("SAVE", cfg);

    enabled = cfg->enabled ? 1 : 0;
    port = (int16_t)cfg->port;
    ip = (int32_t)cfg->whitelist_ip.addr;
    mask = (int32_t)cfg->whitelist_mask.addr;

    configdb_set_i8(TCP_SERVER_CONFIG_ENABLED_NAME, &enabled);
    configdb_set_i16(TCP_SERVER_CONFIG_PORT_NAME, &port);
    configdb_set_i32(TCP_SERVER_CONFIG_WHITELIST_IP_NAME, &ip);
    configdb_set_i32(TCP_SERVER_CONFIG_WHITELIST_MASK_NAME, &mask);
}

static bool tcp_server_rxq_push( struct tcp_pcb *pcb, struct pbuf *p, uint32_t gen ){
    uint32_t wr = (uint32_t)g_rxq_wr;
    uint32_t next = wr + 1U;
    if (next >= TCP_SERVER_RX_QUEUE_LEN) {
        next = 0U;
    }
    if (next == (uint32_t)g_rxq_rd) {
        return false;
    }

    g_rxq[wr].pcb = pcb;
    g_rxq[wr].p = p;
    g_rxq[wr].gen = gen;
    TCP_SERVER_BARRIER();
    g_rxq_wr = next;

    (void)os_sema_up(&g_rxq_sem);
    return true;
}

static bool tcp_server_rxq_pop( tcp_server_rx_job_t *out ){
    uint32_t rd = (uint32_t)g_rxq_rd;
    if (rd == (uint32_t)g_rxq_wr) {
        return false;
    }

    if (out != NULL) {
        *out = g_rxq[rd];
    }

    TCP_SERVER_BARRIER();
    rd++;
    if (rd >= TCP_SERVER_RX_QUEUE_LEN) {
        rd = 0U;
    }
    g_rxq_rd = rd;
    return true;
}

static void tcp_server_pbuf_free_cb( void *arg ){
    struct pbuf *p = (struct pbuf *)arg;
    if (p != NULL) {
        pbuf_free(p);
    }
}

static void tcp_server_rx_done_cb( void *arg ){
    tcp_server_rx_done_t *j = (tcp_server_rx_done_t *)arg;

    if (j == NULL) {
        return;
    }

    if (j->p != NULL) {
        if ((j->gen == g_client_gen) && (j->pcb == g_client_pcb) && (j->pcb != NULL)) {
            tcp_recved(j->pcb, (u16_t)j->len);
        }
        pbuf_free(j->p);
    }

    os_free(j);
}

static void tcp_server_rx_task( void *arg ){
    (void)arg;

    while (1) {
        uint32_t off;
        uint32_t tot;
        tcp_server_rx_job_t job;

        if (!tcp_server_rxq_pop(&job)) {
            (void)os_sema_down(&g_rxq_sem, 1000);
            continue;
        }

        if (job.p == NULL) {
            continue;
        }

        /* connection changed - just drop queued data */
        if (job.gen != g_client_gen) {
            while (tcpip_try_callback(tcp_server_pbuf_free_cb, job.p) != ERR_OK) {
                os_sema_down(&g_yield_sem, 1);
            }
            continue;
        }

        if (g_rx_cb == NULL || g_rx_pkg_buf == NULL) {
            tcp_server_rx_done_t *done = (tcp_server_rx_done_t *)os_malloc(sizeof(*done));
            if (done == NULL) {
                while (tcpip_try_callback(tcp_server_pbuf_free_cb, job.p) != ERR_OK) {
                    os_sema_down(&g_yield_sem, 1);
                }
                continue;
            }
            done->pcb = job.pcb;
            done->p = job.p;
            done->len = (uint16_t)job.p->tot_len;
            done->gen = job.gen;

            while (tcpip_try_callback(tcp_server_rx_done_cb, done) != ERR_OK) {
                os_sema_down(&g_yield_sem, 1);
            }
            continue;
        }

        off = 0U;
        tot = (uint32_t)job.p->tot_len;

        while (off < tot) {
            uint32_t chunk = tot - off;
            if (chunk > HALOW_MTU) {
                chunk = HALOW_MTU;
            }

            pbuf_copy_partial(job.p, g_rx_pkg_buf, (u16_t)chunk, (u16_t)off);
            g_rx_cb(g_rx_pkg_buf, chunk);
            off += chunk;
        }

        {
            tcp_server_rx_done_t *done = (tcp_server_rx_done_t *)os_malloc(sizeof(*done));
            if (done == NULL) {
                /* worst-case: free without updating rcv window */
                while (tcpip_try_callback(tcp_server_pbuf_free_cb, job.p) != ERR_OK) {
                    os_sema_down(&g_yield_sem, 1);
                }
                continue;
            }

            done->pcb = job.pcb;
            done->p = job.p;
            done->len = (uint16_t)job.p->tot_len;
            done->gen = job.gen;

            while (tcpip_try_callback(tcp_server_rx_done_cb, done) != ERR_OK) {
                os_sema_down(&g_yield_sem, 1);
            }
        }
    }
}

static int32_t tcp_server_rx_worker_init( void ){
    int32_t ret;

    if (g_tcps_rx_task_started) {
        return 0;
    }

    g_rxq_wr = 0;
    g_rxq_rd = 0;

    (void)os_sema_init(&g_rxq_sem, 0);
    (void)os_sema_init(&g_yield_sem, 0);

    ret = os_task_init((const uint8 *)"tcps_rx", &g_tcps_rx_task, tcp_server_rx_task, 0);
    tcps_debug("os_task_init(rx) -> %d", (int)ret);
    if (ret != 0) {
        return ret;
    }

    ret = os_task_set_stacksize(&g_tcps_rx_task, TCP_SERVER_RX_TASK_STACK);
    tcps_debug("os_task_set_stacksize(rx) -> %d", (int)ret);

    ret = os_task_set_priority(&g_tcps_rx_task, TCP_SERVER_RX_TASK_PRIO);
    tcps_debug("os_task_set_priority(rx) -> %d", (int)ret);

    ret = os_task_run(&g_tcps_rx_task);
    tcps_debug("os_task_run(rx) -> %d", (int)ret);
    if (ret == 0) {
        g_tcps_rx_task_started = true;
    }
    return ret;
}

static void tcp_server_apply_cb(void *arg){
    tcp_server_config_t *cfg = (tcp_server_config_t *)arg;
    struct tcp_pcb *pcb;
    err_t err;

    if (cfg == NULL) {
        return;
    }

    if (g_listen_pcb != NULL) {
        tcp_accept(g_listen_pcb, NULL);
        tcp_close(g_listen_pcb);
        g_listen_pcb = NULL;
    }

    if (g_client_pcb != NULL) {
        g_client_gen++;
        tcp_arg(g_client_pcb, NULL);
        tcp_recv(g_client_pcb, NULL);
        tcp_err (g_client_pcb, NULL);
        tcp_abort(g_client_pcb);
        g_client_pcb = NULL;
    }

    g_cfg = *cfg;

    if (!g_cfg.enabled) {
        tcp_server_config_debug_print("APPLY(disabled)", &g_cfg);
        goto end;
    }

    pcb = tcp_new();
    if (pcb == NULL) {
        tcps_debug("APPLY tcp_new OOM");
        goto end;
    }

    err = tcp_bind(pcb, IP_ADDR_ANY, (uint16_t)g_cfg.port);
    if (err != ERR_OK) {
        tcps_debug("APPLY bind port=%u err=%d", (unsigned)g_cfg.port, (int)err);
        tcp_close(pcb);
        goto end;
    }
    tcp_arg(pcb, NULL);

    pcb = tcp_listen(pcb);
    if (pcb == NULL) {
        tcps_debug("APPLY listen OOM");
        goto end;
    }

    g_listen_pcb = pcb;

    tcp_nagle_disable(pcb);
    tcp_accept(pcb, tcp_server_accept_callback);
    tcp_server_config_debug_print("APPLY(ok)", &g_cfg);

end:
    os_free(cfg);
}

void tcp_server_config_apply(const tcp_server_config_t *cfg){
    tcp_server_config_t *copy;

    if (cfg == NULL) {
        return;
    }

    copy = (tcp_server_config_t *)os_malloc(sizeof(*copy));
    if (copy == NULL) {
        tcps_debug("APPLY arg OOM");
        return;
    }

    *copy = *cfg;

    if (tcpip_try_callback(tcp_server_apply_cb, copy) != ERR_OK) {
        os_free(copy);
        tcps_debug("APPLY tcpip_try_callback failed");
        return;
    }
}

bool tcp_server_get_client_info( ip4_addr_t *addr, uint16_t *port ){
    if (g_client_pcb == NULL) {
        return false;
    }

    if (addr != NULL) {
        *addr = *ip_2_ip4(&g_client_pcb->remote_ip);
    }
    if (port != NULL) {
        *port = g_client_pcb->remote_port;
    }
    return true;
}

static void tcp_server_send_callback(void *arg){
    struct tcp_tx_package* j = (struct tcp_tx_package*)arg;

    if (j == NULL) {
        return;
    }
    if (j->pcb == NULL) {
        goto end;
    }
    if(j->pcb != g_client_pcb){
        goto end;
    }
    if (tcp_sndbuf(j->pcb) < j->len) {
        goto end;
    }
    if (tcp_sndqueuelen(j->pcb) >= TCP_SND_QUEUELEN) {
        goto end;
    }
    if (tcp_write(j->pcb, j->data, j->len, TCP_WRITE_FLAG_COPY) == ERR_OK) {
        int32_t res = tcp_output(j->pcb);
        if(res != ERR_OK){
            tcps_debug("Output err=%d", res);
        }
    }
end:
    os_free(j);
}

static err_t tcp_server_recv_callback (void *arg,
                                       struct tcp_pcb *tpcb,
                                       struct pbuf *p,
                                       err_t err)
{
    (void)arg;
    (void)err;

    if (p == NULL) {
        tcp_close(tpcb);
        if (g_client_pcb == tpcb) {
            g_client_pcb = NULL;
            g_client_gen++;
        }
        return ERR_OK;
    }

    tcps_debug("RECV cb: tot_len=%u first_len=%u", (unsigned)p->tot_len, (unsigned)p->len);

    if (g_rx_cb == NULL || !g_tcps_rx_task_started) {
        tcp_recved(tpcb, p->tot_len);
        pbuf_free(p);
        return (g_rx_cb == NULL) ? ERR_ARG : ERR_OK;
    }

    if (!tcp_server_rxq_push(tpcb, p, g_client_gen)) {
        /* do not free p: let lwIP keep it and re-call us later */
        tcps_debug("RXQ full");
        return ERR_MEM;
    }

    return ERR_OK;
}

static void tcp_server_err_callback(void *arg, err_t err){
    (void)arg;
    (void)err;

    tcps_debug("ERR cb: err=%d client_pcb was=%p", (int)err, (void *)g_client_pcb);

    g_client_pcb = NULL;
    g_client_gen++;
}

static err_t tcp_server_accept_callback(void *arg, struct tcp_pcb *newpcb, err_t err){
    (void)arg;
    (void)err;

    if (g_cfg.whitelist_mask.addr != 0) {
        const ip4_addr_t *rip = ip_2_ip4(&newpcb->remote_ip);
        if (((rip->addr) & g_cfg.whitelist_mask.addr) != (g_cfg.whitelist_ip.addr & g_cfg.whitelist_mask.addr)) {
            tcp_abort(newpcb);
            return ERR_ABRT;
        }
    }

    if (g_client_pcb) {
        tcp_abort(newpcb);
        return ERR_ABRT;
    }

    g_client_pcb = newpcb;
    g_client_gen++;

    tcp_recv(newpcb, tcp_server_recv_callback);
    tcp_err (newpcb, tcp_server_err_callback);

    return ERR_OK;
}

int32_t tcp_server_init(tcp_server_rx_cb_t cb){
    struct tcp_pcb *pcb;
    err_t err;
    g_rx_cb = cb;

    tcp_server_config_load(&g_cfg);
    tcp_server_config_save(&g_cfg);

    if (g_rx_cb != NULL) {
        if (g_rx_pkg_buf == NULL) {
            g_rx_pkg_buf = os_malloc(HALOW_MTU);
            if (g_rx_pkg_buf == NULL) {
                tcps_debug("Out of memory while RX buff allocate\r\n");
                return -3;
            }
        }
        (void)tcp_server_rx_worker_init();
    }

    if (!g_cfg.enabled) {
        tcps_debug("disabled");
        return 0;
    }

    pcb = tcp_new();
    if (pcb == NULL) {
        tcps_debug("Error creating PCB. Out of Memory\r\n");
        return -1;
    }

    err = tcp_bind(pcb, IP_ADDR_ANY, (uint16_t)g_cfg.port);
    if (err != ERR_OK) {
        tcps_debug("Unable to bind to port %u: err = %d\r\n", (unsigned)g_cfg.port, err);
        return -2;
    }
    tcp_arg(pcb, NULL);

    pcb = tcp_listen(pcb);
    if (pcb == NULL) {
        tcps_debug("Out of memory while tcp_listen\r\n");
        return -3;
    }

    g_listen_pcb = pcb;

    tcp_nagle_disable(pcb);
    tcp_accept(pcb, tcp_server_accept_callback);
    return 0;
}

int32_t tcp_server_send(const uint8_t *data, uint32_t len){
    if (!data) {
        return -1;
    }
    if (len == 0) {
        return 0;
    }
    if (len > TCP_SERVER_MTU) {
        return -2;
    }
    if (!g_client_pcb) {
        return -3;
    }

    struct tcp_tx_package *tx_package = os_malloc(sizeof(struct tcp_tx_package) + len);
    if (tx_package == NULL) {
        return -4;
    }


    tx_package->pcb = g_client_pcb;
    tx_package->len = (uint16_t)len;
    memcpy(tx_package->data, data, len);

    if (tcpip_try_callback(tcp_server_send_callback, tx_package) != ERR_OK) {
        os_free(tx_package);
        return -4;
    }

    return 0;
}
