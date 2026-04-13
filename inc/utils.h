#ifndef __UTILS_H_
#define __UTILS_H_

#include <stdint.h>
#include <stdbool.h>
#include "lwip/ip4_addr.h"

extern const uint8_t mac_broadcast[6];

void utils_ip_mask_to_cidr( char *dst, size_t dst_sz, const ip4_addr_t *ip, const ip4_addr_t *mask );
bool utils_cidr_to_mask( const char *s, ip4_addr_t *mask );
bool utils_cidr_to_ip( const char *s, ip4_addr_t *ip );

int64_t get_time_ms(void);
int64_t get_time_us(void);
void get_mac(uint8_t mac[6]);

void bin16_to_hex32( const uint8_t *in, char *out );
int hex32_to_bin16( const char *in, uint8_t *out );

#endif // __UTILS_H_
