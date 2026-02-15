#include "utils.h"
#include "basic_include.h"
#include "osal/time.h"
#include "lib/posix/pthread.h"
#include "lwip/ip4_addr.h"
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

static uint32_t utils_mask_to_prefix( const ip4_addr_t *mask ){
    uint32_t m = lwip_ntohl(ip4_addr_get_u32(mask));
    uint32_t p = 0;

    while ((p < 32u) && ((m & 0x80000000u) != 0u)) {
        p++;
        m <<= 1u;
    }
    return p;
}

void utils_ip_mask_to_cidr( char *dst, size_t dst_sz, const ip4_addr_t *ip, const ip4_addr_t *mask ){
    char ip_str[16];
    uint32_t prefix;

    if (!dst || dst_sz == 0 || !ip || !mask) {
        return;
    }

    ip4addr_ntoa_r(ip, ip_str, sizeof(ip_str));
    prefix = utils_mask_to_prefix(mask);
    snprintf(dst, dst_sz, "%s/%u", ip_str, (unsigned)prefix);
}

bool utils_cidr_to_mask( const char *s, ip4_addr_t *mask ){
    const char *slash;
    uint32_t prefix = 32;
    uint32_t m;

    if (s == NULL){
        return false;
    }
    if (mask == NULL){
        return false;
    }

    slash = strchr(s, '/');
    if (slash != NULL) {
        unsigned long p = strtoul(slash + 1, NULL, 10);
        if (p > 32ul) {
            return false;
        }
        prefix = (uint32_t)p;
    }

    m = (prefix == 0u) ? 0u :
        (prefix == 32u) ? 0xFFFFFFFFu :
        (0xFFFFFFFFu << (32u - prefix));

    ip4_addr_set_u32(mask, PP_HTONL(m));

    return true;
}

bool utils_cidr_to_ip( const char *s, ip4_addr_t *ip ){
    const char *slash;
    char buf[16];
    size_t n;

    if (s == NULL){
        return false;
    }
    if (ip == NULL){
        return false;
    }

    slash = strchr(s, '/');
    if (slash == NULL) {
        return ip4addr_aton(s, ip) ? true : false;
    }

    n = (size_t)(slash - s);
    if ((n == 0) || (n >= sizeof(buf))) {
        return false;
    }

    memcpy(buf, s, n);
    buf[n] = '\0';

    return ip4addr_aton(buf, ip) ? true : false;
}

int64_t get_time_ms(void){
    return (os_jiffies() * NANOSECONDS_PER_TICK) / 1000000ULL;
}

int64_t get_time_us( void ){
    int64_t j1;
    int64_t j2;
    uint32_t val;
    uint32_t load;
    uint32_t sub;

    load = (uint32_t)(CORET->LOAD & CORET_LOAD_RELOAD_Msk);

    do {
        j1  = os_jiffies();
        val = (uint32_t)(CORET->VAL & CORET_VAL_CURRENT_Msk);
        j2  = os_jiffies();
    } while (j1 != j2);

    sub = (load + 1U) - val;
    
    return (j1 * (MICROSECONDS_PER_SECOND / OS_HZ)) +
           (int64_t)(sub / 192U);
}