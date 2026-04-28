#ifndef __NETLOG__H__
#define __NETLOG__H__

#include <stdint.h>
#include <stdbool.h>

#include "lwip/ip_addr.h"

typedef struct {
    bool enable;
    ip4_addr_t ip;
    uint16_t port;
} net_log_config_t;

void net_log_init_early( void );
void net_log_init( void );
void net_log_task_init( void );
void net_log_config_load( net_log_config_t *cfg );
void net_log_config_save( const net_log_config_t *cfg );
void net_log_config_apply( const net_log_config_t *cfg );
void net_log_config_set_default( net_log_config_t *cfg );

bool net_log_send( const void *data, uint16_t len );

#endif // __NETLOG__H__
