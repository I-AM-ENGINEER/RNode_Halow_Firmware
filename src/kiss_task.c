/* kiss_task.c */
#include "kiss_task.h"
#include "kiss-tnc.h"

#include <string.h>

#include "lwip/tcp.h"
#include "lwip/tcpip.h"
#include "lwip/netif.h"
#include "lwip/sys.h"

#include "basic_include.h"

#ifdef KISS_DEBUG
#define kiss_dbg(fmt, ...)  hgprintf("[KISS] " fmt "\r\n", ##__VA_ARGS__)
#else
#define kiss_dbg(fmt, ...)  do { } while (0)
#endif

#define KISS_NETIF_NAME        "e0"
#define KISS_TCP_PORT_DEFAULT  8001

#define KISS_TX_BUF_SIZE       1700
#define KISS_RADIO_RX_MAX      1500
#define KISS_OUT_Q_LEN         8

static struct kiss_ctx kiss;

static struct netif   *nif;
static struct tcp_pcb *listen_pcb;
static struct tcp_pcb *client_pcb;

static struct os_work       kiss_wk;
static struct os_workqueue  kiss_wkq;

static struct kiss_task_cfg g_cfg;

struct kiss_out_item {
    uint32_t len;
    uint8_t  data[KISS_RADIO_RX_MAX];
};

static uint8_t g_txbuf[KISS_TX_BUF_SIZE];

static struct kiss_out_item outq[KISS_OUT_Q_LEN];
static uint8_t outq_head;
static uint8_t outq_tail;
static uint8_t outq_cnt;
static uint8_t outq_scheduled;

static void kiss_tcp_close_client (void) {
    if (!client_pcb) {
        return;
    }

    tcp_arg(client_pcb, NULL);
    tcp_recv(client_pcb, NULL);
    tcp_err(client_pcb, NULL);

    if (tcp_close(client_pcb) != ERR_OK) {
        tcp_abort(client_pcb);
    }

    client_pcb = NULL;

    if (g_cfg.on_disconnect) {
        g_cfg.on_disconnect();
    }
}

static void kiss_send_frame (uint8_t port, uint8_t cmd, const uint8_t *data, uint32_t len) {
    if (!client_pcb) {
        return;
    }

    uint8_t buf[KISS_TX_BUF_SIZE];

    uint32_t n = kiss_tnc_encode(
        port,
        cmd,
        data,
        len,
        buf,
        sizeof(buf)
    );

    if (!n) {
        return;
    }

    err_t e = tcp_write(client_pcb, buf, n, TCP_WRITE_FLAG_COPY);
    if (e != ERR_OK) {
        return;
    }

    tcp_output(client_pcb);
}

static void kiss_rx_cb (
    void *user,
    uint8_t port,
    uint8_t cmd,
    const uint8_t *data,
    uint32_t len
){
    (void)user;

#ifdef KISS_DEBUG
    kiss_dbg("rx: port=%u cmd=0x%X len=%lu",
             (unsigned)port,
             (unsigned)cmd,
             (unsigned long)len);
    if (len) {
        dump_hex("rx data", (uint8_t *)data, (uint32)len, 1);
    }
#endif

    if (port == 0xF && cmd == KISS_CMD_RETURN) {
        kiss_tcp_close_client();
        return;
    }

    if (port != g_cfg.kiss_port) {
        return;
    }

    switch (cmd) {
    case KISS_CMD_DATA:
        if (len && g_cfg.radio_tx) {
            g_cfg.radio_tx(data, len);
        }
        break;

    default:
        break;
    }
}

static void kiss_tcpip_send_pending (void *arg) {
    (void)arg;

    for (;;) {
        if (!client_pcb) {
            sys_prot_t p = sys_arch_protect();
            outq_head = 0;
            outq_tail = 0;
            outq_cnt  = 0;
            outq_scheduled = 0;
            sys_arch_unprotect(p);
            return;
        }

        sys_prot_t p = sys_arch_protect();
        uint8_t cnt  = outq_cnt;
        uint8_t idx  = outq_head;
        if (!cnt) {
            outq_scheduled = 0;
            sys_arch_unprotect(p);
            return;
        }
        sys_arch_unprotect(p);

        struct kiss_out_item *it = &outq[idx];

        uint32_t n = kiss_tnc_encode(
            g_cfg.kiss_port,
            KISS_CMD_DATA,
            it->data,
            it->len,
            g_txbuf,
            sizeof(g_txbuf)
        );

        if (!n) {
            p = sys_arch_protect();
            if (outq_cnt) {
                outq_head = (uint8_t)((outq_head + 1u) % KISS_OUT_Q_LEN);
                outq_cnt--;
            }
            sys_arch_unprotect(p);
            continue;
        }

        err_t e = tcp_write(client_pcb, g_txbuf, n, TCP_WRITE_FLAG_COPY);
        if (e == ERR_MEM) {
            tcp_output(client_pcb);
            return;
        }
        if (e != ERR_OK) {
            return;
        }

        tcp_output(client_pcb);

        p = sys_arch_protect();
        if (outq_cnt) {
            outq_head = (uint8_t)((outq_head + 1u) % KISS_OUT_Q_LEN);
            outq_cnt--;
        }
        sys_arch_unprotect(p);
    }
}

int32_t kiss_radio_rx(const uint8_t *data, uint32_t len) {
    if (!data || !len) {
        return -1;
    }

    if (len > KISS_RADIO_RX_MAX) {
        len = KISS_RADIO_RX_MAX;
    }

    sys_prot_t p = sys_arch_protect();

    if (outq_cnt >= KISS_OUT_Q_LEN) {
        sys_arch_unprotect(p);
        return -2;
    }

    struct kiss_out_item *it = &outq[outq_tail];
    memcpy(it->data, data, len);
    it->len = (uint32_t)len;

    outq_tail = (uint8_t)((outq_tail + 1u) % KISS_OUT_Q_LEN);
    outq_cnt++;

    bool need_schedule = (outq_scheduled == 0);
    outq_scheduled = 1;

    sys_arch_unprotect(p);

    if (need_schedule) {
        tcpip_callback(kiss_tcpip_send_pending, NULL);
    }

    return 0;
}

static void kiss_tcp_err (void *arg, err_t err) {
    (void)arg;
    (void)err;

    client_pcb = NULL;

    if (g_cfg.on_disconnect) {
        g_cfg.on_disconnect();
    }
}

static err_t kiss_tcp_recv (void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err) {
    (void)arg;
    (void)err;

    if (!p) {
        kiss_tcp_close_client();
        return ERR_OK;
    }

#ifdef KISS_DEBUG
    kiss_dbg("tcp rx: tot=%u first=%u",
             (unsigned)p->tot_len,
             (unsigned)p->len);
#endif

    for (struct pbuf *q = p; q; q = q->next) {
        const uint8_t *ptr = (const uint8_t *)q->payload;
        uint32_t len = (uint32_t)q->len;

        for (uint32_t i = 0; i < len; i++) {
            kiss_tnc_input_byte(&kiss, ptr[i], kiss_rx_cb, NULL);
        }

#ifdef KISS_DEBUG
        kiss_dbg("tcp rx chunk: len=%u", (unsigned)len);
        dump_hex("tcp chunk", (uint8_t *)ptr, (uint32)len, 1);
#endif
    }

    tcp_recved(pcb, p->tot_len);
    pbuf_free(p);
    return ERR_OK;
}

static err_t kiss_tcp_accept (void *arg, struct tcp_pcb *newpcb, err_t err) {
    (void)arg;
    (void)err;

    if (client_pcb) {
        tcp_abort(newpcb);
        return ERR_ABRT;
    }

    client_pcb = newpcb;

    tcp_arg(newpcb, NULL);
    tcp_recv(newpcb, kiss_tcp_recv);
    tcp_err(newpcb, kiss_tcp_err);

    if (g_cfg.on_connect) {
        g_cfg.on_connect();
    }

    return ERR_OK;
}

static void kiss_tcp_server_init (void) {
    if (listen_pcb) {
        return;
    }

    listen_pcb = tcp_new();
    if (!listen_pcb) {
        return;
    }

    uint16_t port = g_cfg.tcp_port ? g_cfg.tcp_port : KISS_TCP_PORT_DEFAULT;

    if (tcp_bind(listen_pcb, IP_ADDR_ANY, port) != ERR_OK) {
        tcp_abort(listen_pcb);
        listen_pcb = NULL;
        return;
    }

    struct tcp_pcb *l = tcp_listen(listen_pcb);
    if (!l) {
        tcp_abort(listen_pcb);
        listen_pcb = NULL;
        return;
    }

    listen_pcb = l;
    tcp_accept(listen_pcb, kiss_tcp_accept);
}

static int32 kiss_task_loop (struct os_work *work) {
    (void)work;

    if (!nif) {
        nif = netif_find(KISS_NETIF_NAME);
        if (!nif) {
            kiss_dbg("netif '%s' not found, retry",
                     KISS_NETIF_NAME);
            os_run_work_delay(&kiss_wk, 500);
            return 0;
        }
        kiss_dbg("netif '%s' found", KISS_NETIF_NAME);
    }

    if (!listen_pcb) {
        kiss_dbg("tcp server not running, init");
        kiss_tcp_server_init();

#ifdef KISS_DEBUG
        if (listen_pcb) {
            kiss_dbg("tcp server listening");
        } else {
            kiss_dbg("tcp server init failed");
        }
#endif
    }

    os_run_work_delay(&kiss_wk, 1000);
    return 0;
}

void kiss_task_init (const struct kiss_task_cfg *cfg) {
    kiss_dbg("init begin");

    memset(&g_cfg, 0, sizeof(g_cfg));
    if (cfg) {
        g_cfg = *cfg;
        kiss_dbg("cfg: tcp_port=%u kiss_port=%u",
                 (unsigned)g_cfg.tcp_port,
                 (unsigned)g_cfg.kiss_port);
    } else {
        kiss_dbg("cfg: NULL (using defaults)");
    }

    if (g_cfg.kiss_port > 0x0F) {
        kiss_dbg("kiss_port %u invalid, forcing 0",
                 (unsigned)g_cfg.kiss_port);
        g_cfg.kiss_port = 0;
    }

    nif        = NULL;
    listen_pcb = NULL;
    client_pcb = NULL;

    kiss_tnc_init(&kiss, g_cfg.kiss_port);
    kiss_dbg("kiss_tnc_init(port=%u) done",
             (unsigned)g_cfg.kiss_port);

    outq_head      = 0;
    outq_tail      = 0;
    outq_cnt       = 0;
    outq_scheduled = 0;
    kiss_dbg("outq reset");

    os_workqueue_init(&kiss_wkq, "KISS", OS_TASK_PRIORITY_NORMAL, 2048);
    kiss_dbg("workqueue init");

    OS_WORK_INIT(&kiss_wk, kiss_task_loop, 0);
    kiss_dbg("work init");

    os_run_work_delay(&kiss_wk, 1000);

    kiss_dbg("init done");
}
