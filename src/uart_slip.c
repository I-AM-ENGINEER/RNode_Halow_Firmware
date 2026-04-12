#include "sys_config.h"
#define LOG_LOCAL_LEVEL LOG_LEVEL_UART_SLIP

#include "uart_slip.h"

#include "basic_include.h"
#include "lib/logc/log.h"

#include "lwip/arch.h"
#include "lwip/sio.h"
#include "lwip/netif.h"
#include "lwip/ip_addr.h"
#include "lwip/pbuf.h"
#include "lwip/tcpip.h"
#include "netif/slipif.h"
#include "sys_config.h"
#include "configdb.h"

#include "hal/uart.h"

#include <string.h>

extern struct hguart UART_SLIP_DEVICE;

static struct uart_device *g_slip_uart = (struct uart_device *)&UART_SLIP_DEVICE;

static struct netif slip_netif;
static struct os_task slip_task;

#define UART_SLIP_CONFIG_PREFIX               CONFIGDB_ADD_MODULE("slip")
#define UART_SLIP_CONFIG_ADD_CONFIG(name)     UART_SLIP_CONFIG_PREFIX "." name

#define UART_SLIP_CONFIG_ENABLE_NAME          UART_SLIP_CONFIG_ADD_CONFIG("enable")
#define UART_SLIP_CONFIG_BAUD_NAME            UART_SLIP_CONFIG_ADD_CONFIG("baud")
#define UART_SLIP_CONFIG_IP_NAME              UART_SLIP_CONFIG_ADD_CONFIG("ip")
#define UART_SLIP_CONFIG_MASK_NAME            UART_SLIP_CONFIG_ADD_CONFIG("mask")
#define UART_SLIP_CONFIG_GW_NAME              UART_SLIP_CONFIG_ADD_CONFIG("gw")

static uart_slip_config_t g_uart_slip_config;

static uint8_t slip_rb[UART_SLIP_RB_SIZE];
static volatile uint32_t slip_rb_head = 0;
static volatile uint32_t slip_rb_tail = 0;
static volatile uint32_t slip_rb_overflow = 0;

static volatile bool slip_started = false;
static bool slip_task_created = false;
static bool slip_netif_added = false;

static inline void uart_slip_config_log_trace( const char *tag, const uart_slip_config_t *cfg ){
    char ipbuf[16];
    char maskbuf[16];
    char gwbuf[16];

    if( cfg == NULL ){
        return;
    }

    ip4addr_ntoa_r((const ip4_addr_t *)&cfg->ip,   ipbuf,   sizeof(ipbuf));
    ip4addr_ntoa_r((const ip4_addr_t *)&cfg->mask, maskbuf, sizeof(maskbuf));
    ip4addr_ntoa_r((const ip4_addr_t *)&cfg->gw,   gwbuf,   sizeof(gwbuf));

    log_trace("%s en=%d baud=%lu ip=%s mask=%s gw=%s",
              tag ? tag : "CFG",
              cfg->enabled ? 1 : 0,
              (unsigned long)cfg->baud,
              ipbuf,
              maskbuf,
              gwbuf);
}

static inline void uart_slip_config_log_debug( const char *tag, const uart_slip_config_t *cfg ){
    char ipbuf[16];
    char maskbuf[16];
    char gwbuf[16];

    if( cfg == NULL ){
        return;
    }

    ip4addr_ntoa_r((const ip4_addr_t *)&cfg->ip,   ipbuf,   sizeof(ipbuf));
    ip4addr_ntoa_r((const ip4_addr_t *)&cfg->mask, maskbuf, sizeof(maskbuf));
    ip4addr_ntoa_r((const ip4_addr_t *)&cfg->gw,   gwbuf,   sizeof(gwbuf));

    log_debug("%s en=%d baud=%lu ip=%s mask=%s gw=%s",
              tag ? tag : "CFG",
              cfg->enabled ? 1 : 0,
              (unsigned long)cfg->baud,
              ipbuf,
              maskbuf,
              gwbuf);
}

static bool uart_slip_config_is_valid( const uart_slip_config_t *cfg ){
    uint32_t m;
    uint32_t inv;

    if( cfg == NULL ){
        return false;
    }

    if( cfg->baud == 0 ){
        return false;
    }

    m = lwip_ntohl(cfg->mask.addr);
    if( m == 0 ){
        return false;
    }

    inv = ~m;
    if( (inv & (inv + 1)) != 0 ){
        return false;
    }

    return true;
}

void uart_slip_config_set_default( uart_slip_config_t *cfg ){
    if( cfg == NULL ){
        return;
    }

    cfg->enabled   = UART_SLIP_CONFIG_ENABLE_DEF ? true : false;
    cfg->baud      = UART_SLIP_CONFIG_BAUD_DEF;
    cfg->ip.addr   = UART_SLIP_CONFIG_IP_ADDR_DEF;
    cfg->mask.addr = UART_SLIP_CONFIG_IP_MASK_DEF;
    cfg->gw.addr   = UART_SLIP_CONFIG_IP_GW_DEF;
}

void uart_slip_config_load( uart_slip_config_t *cfg ){
    int32_t enable;
    int32_t baud;

    if( cfg == NULL ){
        return;
    }

    uart_slip_config_set_default(cfg);

    enable = cfg->enabled ? 1 : 0;
    baud   = (int32_t)cfg->baud;

    configdb_get_i32(UART_SLIP_CONFIG_ENABLE_NAME, &enable);
    configdb_get_i32(UART_SLIP_CONFIG_BAUD_NAME,   &baud);
    configdb_get_i32(UART_SLIP_CONFIG_IP_NAME,     (int32_t *)&cfg->ip.addr);
    configdb_get_i32(UART_SLIP_CONFIG_MASK_NAME,   (int32_t *)&cfg->mask.addr);
    configdb_get_i32(UART_SLIP_CONFIG_GW_NAME,     (int32_t *)&cfg->gw.addr);

    cfg->enabled = enable ? true : false;
    cfg->baud    = (uint32_t)baud;

    uart_slip_config_log_trace("LOAD", cfg);
}

void uart_slip_config_save( const uart_slip_config_t *cfg ){
    int32_t enable;
    int32_t baud;

    if( cfg == NULL ){
        return;
    }

    if( !uart_slip_config_is_valid(cfg) ){
        log_warn("trying save invalid config");
        return;
    }

    uart_slip_config_log_debug("SAVE", cfg);

    enable = cfg->enabled ? 1 : 0;
    baud   = (int32_t)cfg->baud;

    configdb_set_i32(UART_SLIP_CONFIG_ENABLE_NAME, &enable);
    configdb_set_i32(UART_SLIP_CONFIG_BAUD_NAME,   &baud);
    configdb_set_i32(UART_SLIP_CONFIG_IP_NAME,     (int32_t *)&cfg->ip.addr);
    configdb_set_i32(UART_SLIP_CONFIG_MASK_NAME,   (int32_t *)&cfg->mask.addr);
    configdb_set_i32(UART_SLIP_CONFIG_GW_NAME,     (int32_t *)&cfg->gw.addr);
}

static inline uint32_t slip_rb_next( uint32_t v ){
    v++;
    if( v >= UART_SLIP_RB_SIZE ){
        v = 0;
    }
    return v;
}

static inline void slip_rb_reset( void ){
    slip_rb_head = 0;
    slip_rb_tail = 0;
    slip_rb_overflow = 0;
}

static inline bool slip_rb_is_empty( void ){
    return slip_rb_head == slip_rb_tail;
}

static inline bool slip_rb_put( uint8_t byte ){
    uint32_t head;
    uint32_t next;

    head = slip_rb_head;
    next = slip_rb_next(head);

    if( next == slip_rb_tail ){
        slip_rb_overflow++;
        return false;
    }

    slip_rb[head] = byte;
    slip_rb_head = next;
    return true;
}

static inline bool slip_rb_get( uint8_t *byte ){
    uint32_t tail;

    tail = slip_rb_tail;
    if( tail == slip_rb_head ){
        return false;
    }

    *byte = slip_rb[tail];
    slip_rb_tail = slip_rb_next(tail);
    return true;
}

static int32_t uart_slip_uart_stop( void ){
    (void)uart_release_irq(g_slip_uart, UART_IRQ_FLAG_RX_BYTE);
    return uart_close(g_slip_uart);
}

static int32_t uart_slip_uart_start( uint32_t baud ){
    int32_t rc;

    (void)uart_release_irq(g_slip_uart, UART_IRQ_FLAG_RX_BYTE);
    (void)uart_close(g_slip_uart);

    rc = uart_open(g_slip_uart, baud);
    if( rc != 0 ){
        log_error("slip uart_open failed rc=%ld baud=%lu", (long)rc, (unsigned long)baud);
        return rc;
    }

    return 0;
}

int32_t uart_slip_irq( uint32_t irq, uint32_t irq_data, uint32_t param1, uint32_t param2 ){
    uint8_t byte;

    (void)irq;
    (void)irq_data;
    (void)param2;

    byte = (uint8_t)param1;
    slip_rb_put(byte);

    while( uart_ioctl(g_slip_uart, UART_IOCTL_CMD_DATA_RDY, 0, 0) ){
        byte = uart_getc(g_slip_uart);
        slip_rb_put(byte);
    }

    return 0;
}

void sio_send( u8_t c, sio_fd_t fd ){
    uart_putc((struct uart_device *)fd, c);
}

sio_fd_t sio_open( u8_t devnum ){
    (void)devnum;

    (void)uart_release_irq(g_slip_uart, UART_IRQ_FLAG_RX_BYTE);

    uart_request_irq(
        g_slip_uart,
        uart_slip_irq,
        UART_IRQ_FLAG_RX_BYTE,
        0
    );

    log_debug("sio_open");
    return (sio_fd_t)g_slip_uart;
}

static void uart_slip_task( void *arg ){
    uint8_t byte;
    uint32_t overflow_prev = 0;

    (void)arg;

    while( 1 ){
        if( slip_started ){
            while( slip_started && slip_rb_get(&byte) ){
                slipif_rxbyte_input(&slip_netif, byte);
            }

            if( slip_rb_overflow != overflow_prev ){
                overflow_prev = slip_rb_overflow;
                log_warn("slip rb overflow=%lu", (unsigned long)overflow_prev);
            }

            os_sleep_ms(1);
        } else {
            os_sleep_ms(10);
        }
    }
}

static void uart_slip_config_apply_cb( void *arg ){
    uart_slip_config_t *cfg = (uart_slip_config_t *)arg;
    int32_t rc = 0;

    if( cfg == NULL ){
        log_warn("apply cb: cfg null");
        return;
    }

    if( !slip_netif_added ){
        log_warn("apply cb: slip netif not added");
        os_free(cfg);
        return;
    }

    slip_started = false;
    slip_rb_reset();
    (void)uart_slip_uart_stop();

    memcpy(&g_uart_slip_config, cfg, sizeof(g_uart_slip_config));

    netif_set_addr(&slip_netif,
                   &g_uart_slip_config.ip,
                   &g_uart_slip_config.mask,
                   &g_uart_slip_config.gw);

    if( g_uart_slip_config.enabled ){
        rc = uart_slip_uart_start(g_uart_slip_config.baud);
        if( rc == 0 ){
            netif_set_up(&slip_netif);
            netif_set_link_up(&slip_netif);
            slip_started = true;
        } else {
            netif_set_link_down(&slip_netif);
            netif_set_down(&slip_netif);
        }
    } else {
        netif_set_link_down(&slip_netif);
        netif_set_down(&slip_netif);
    }

    log_debug("apply cb: en=%d baud=%lu",
              g_uart_slip_config.enabled ? 1 : 0,
              (unsigned long)g_uart_slip_config.baud);

    os_free(cfg);
}

void uart_slip_config_apply( const uart_slip_config_t *cfg ){
    uart_slip_config_t *cpy;

    if( cfg == NULL ){
        log_warn("apply: cfg null");
        return;
    }

    if( !uart_slip_config_is_valid(cfg) ){
        log_warn("trying apply invalid config");
        return;
    }

    cpy = (uart_slip_config_t *)os_malloc(sizeof(*cpy));
    if( cpy == NULL ){
        log_error("apply: OOM");
        return;
    }

    memcpy(cpy, cfg, sizeof(*cpy));
    uart_slip_config_log_debug("APPLY", cfg);

    if( tcpip_try_callback(uart_slip_config_apply_cb, cpy) != ERR_OK ){
        log_error("apply: tcpip_try_callback failed");
        os_free(cpy);
        return;
    }
}

void uart_slip_deinit( void ){
    (void)uart_slip_uart_stop();
    slip_started = false;
    os_sleep_ms(2);

    if( slip_netif_added ){
        netif_set_link_down(&slip_netif);
        netif_set_down(&slip_netif);
        netif_remove(&slip_netif);
        slip_netif_added = false;
    }

    memset(&slip_netif, 0, sizeof(slip_netif));
    slip_rb_reset();

    log_info("slip deinit done");
}


static void uart_slip_init_common( const uart_slip_config_t *cfg ){
    ip4_addr_t ipaddr, netmask, gw;
    int32_t rc = 0;

    if( cfg == NULL ){
        log_warn("slip init common: cfg null");
        return;
    }

    if( slip_started || slip_netif_added ){
        uart_slip_deinit();
    }

    memcpy(&g_uart_slip_config, cfg, sizeof(g_uart_slip_config));
    slip_rb_reset();

    if( g_uart_slip_config.enabled ){
        rc = uart_slip_uart_start(g_uart_slip_config.baud);
        if( rc != 0 ){
            return;
        }
    }

    ipaddr.addr  = g_uart_slip_config.ip.addr;
    netmask.addr = g_uart_slip_config.mask.addr;
    gw.addr      = g_uart_slip_config.gw.addr;

    memset(&slip_netif, 0, sizeof(slip_netif));

#if NO_SYS
    if( netif_add(&slip_netif, &ipaddr, &netmask, &gw, NULL, slipif_init, ip_input) == NULL ){
        log_error("slip netif_add failed");
        (void)uart_slip_uart_stop();
        return;
    }
#else
    if( netif_add(&slip_netif, &ipaddr, &netmask, &gw, NULL, slipif_init, tcpip_input) == NULL ){
        log_error("slip netif_add failed");
        (void)uart_slip_uart_stop();
        return;
    }
#endif

    slip_netif_added = true;

    if( g_uart_slip_config.enabled ){
        netif_set_up(&slip_netif);
        netif_set_link_up(&slip_netif);
        slip_started = true;
    } else {
        netif_set_link_down(&slip_netif);
        netif_set_down(&slip_netif);
        slip_started = false;
    }

    if( !slip_task_created ){
        os_task_init((const uint8 *)"slip", &slip_task, uart_slip_task, 0);
        os_task_set_stacksize(&slip_task, UART_SLIP_TASK_STACK);
        os_task_set_priority(&slip_task, UART_SLIP_TASK_PRIO);
        os_task_run(&slip_task);
        slip_task_created = true;
    }
}

void uart_slip_early_init( void ){
    uart_slip_config_t cfg;

    uart_slip_config_set_default(&cfg);

    if( !uart_slip_config_is_valid(&cfg) ){
        log_error("slip early init: default config invalid");
        return;
    }

    uart_slip_config_log_debug("EARLY", &cfg);
    uart_slip_init_common(&cfg);

    log_info("slip early init done en=%d baud=%lu",
             cfg.enabled ? 1 : 0,
             (unsigned long)cfg.baud);
}

void uart_slip_init( void ){
    uart_slip_config_load(&g_uart_slip_config);

    if( !uart_slip_config_is_valid(&g_uart_slip_config) ){
        log_warn("invalid config in DB -> defaults");
        uart_slip_config_set_default(&g_uart_slip_config);
    }

    uart_slip_config_save(&g_uart_slip_config);
    uart_slip_init_common(&g_uart_slip_config);

    log_info("slip init done en=%d baud=%lu",
             g_uart_slip_config.enabled ? 1 : 0,
             (unsigned long)g_uart_slip_config.baud);
}
