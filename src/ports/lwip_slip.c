#define LOG_LOCAL_LEVEL LOG_TRACE

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

#include "hal/uart.h"

#include <string.h>

extern struct hguart SLIP_CONFIG_UART_DEVICE;

static struct uart_device *g_slip_uart = (struct uart_device *)&SLIP_CONFIG_UART_DEVICE;

static struct netif slip_netif;
static struct os_task slip_task;

#ifndef UART_SLIP_RB_SIZE
#define UART_SLIP_RB_SIZE 2048
#endif

static uint8_t slip_rb[UART_SLIP_RB_SIZE];
static volatile uint32_t slip_rb_head = 0;
static volatile uint32_t slip_rb_tail = 0;
static volatile uint32_t slip_rb_overflow = 0;

static inline uint32_t slip_rb_next( uint32_t v ){
    v++;
    if( v >= UART_SLIP_RB_SIZE ){
        v = 0;
    }
    return v;
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

    uart_release_irq(g_slip_uart, UART_IRQ_FLAG_RX_BYTE);

    uart_request_irq(
        g_slip_uart,
        uart_slip_irq,
        UART_IRQ_FLAG_RX_BYTE,
        0
    );

    return (sio_fd_t)g_slip_uart;
}

static void uart_slip_task( void *arg ){
    uint8_t byte;

    (void)arg;

    while( 1 ){
        while( slip_rb_get(&byte) ){
            slipif_rxbyte_input(&slip_netif, byte);
        }

        os_sleep_ms(1);
    }
}

void uart_slip_init( void ){
    ip4_addr_t ipaddr, netmask, gw;

    slip_rb_head = 0;
    slip_rb_tail = 0;
    slip_rb_overflow = 0;

    IP4_ADDR(&ipaddr,  192,168,7,2);
    IP4_ADDR(&netmask, 255,255,255,255);
    IP4_ADDR(&gw,      192,168,7,1);

#if NO_SYS
    if( netif_add(&slip_netif, &ipaddr, &netmask, &gw, NULL, slipif_init, ip_input) == NULL ){
        log_error("slip netif_add failed");
        return;
    }
#else
    if( netif_add(&slip_netif, &ipaddr, &netmask, &gw, NULL, slipif_init, tcpip_input) == NULL ){
        log_error("slip netif_add failed");
        return;
    }
#endif

    netif_set_up(&slip_netif);
    netif_set_link_up(&slip_netif);

    os_task_init((const uint8 *)"slip", &slip_task, uart_slip_task, 0);
    os_task_set_stacksize(&slip_task, UART_SLIP_TASK_STACK);
    os_task_set_priority(&slip_task, UART_SLIP_TASK_PRIO);
    os_task_run(&slip_task);

    log_debug("slip init done");
}
