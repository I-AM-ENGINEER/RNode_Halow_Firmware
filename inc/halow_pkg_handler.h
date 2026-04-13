#ifndef __HALOW_PKG_HANDLER__
#define __HALOW_PKG_HANDLER__

#include <stdint.h>

void halow_pkg_handler_rf_to_tcp( uint8_t* pkg, uint16_t len );
void halow_pkg_handler_tcp_to_rf( uint8_t* pkg, uint16_t len );
void halow_pkg_handler_init( void );

#endif // __HALOW_PKG_HANDLER__
