#ifndef __UTILS_H_
#define __UTILS_H_

#include <stdint.h>
#include <stdbool.h>
#include "lwip/ip4_addr.h"

void utils_ip_mask_to_cidr( char *dst, size_t dst_sz, const ip4_addr_t *ip, const ip4_addr_t *mask );
bool utils_cidr_to_mask( const char *s, ip4_addr_t *mask );
bool utils_cidr_to_ip( const char *s, ip4_addr_t *ip );

int64_t get_time_ms(void);
int64_t get_time_us(void);
void get_mac(uint8_t mac[6]);

#endif // __UTILS_H_
