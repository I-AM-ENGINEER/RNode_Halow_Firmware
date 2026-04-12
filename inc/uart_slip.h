#ifndef __UART_SLIP_H__
#define __UART_SLIP_H__

#include "lwip/ip4_addr.h"

typedef struct {
    bool enabled;
    uint32_t baud;
    ip4_addr_t ip;
    ip4_addr_t mask;
    ip4_addr_t gw;
} uart_slip_config_t;

void uart_slip_config_set_default( uart_slip_config_t *cfg );
void uart_slip_config_load( uart_slip_config_t *cfg );
void uart_slip_config_save( const uart_slip_config_t *cfg );
void uart_slip_config_apply( const uart_slip_config_t *cfg );
void uart_slip_init( void );
void uart_slip_early_init( void );

#endif // __UART_SLIP_H__
