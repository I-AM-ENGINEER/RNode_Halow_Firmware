#ifndef __HALOW_PKG_HANDLER__
#define __HALOW_PKG_HANDLER__

#include <stdint.h>
#include "halow_ack.h"

void halow_pkg_handler_rf_to_tcp( uint8_t* pkg, uint16_t len,
                                  const uint8_t *src_mac, const uint8_t *dst_mac,
                                  int8_t evm );
/* Returns 0 on success, HALOW_ACK_TX_THROTTLE (-7) when the TX path is saturated
 * (backpressure signal for the TCP recv loop), <0 on hard error. */
int32_t halow_pkg_handler_tcp_to_rf( uint8_t* pkg, uint16_t len );
void halow_pkg_handler_init( void );
int16_t rns_mtu_limit_get( void );
void rns_mtu_limit_set( int16_t mtu );

#endif // __HALOW_PKG_HANDLER__
