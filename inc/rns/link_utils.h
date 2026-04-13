#ifndef __RNS_LINK_UTILS_H__
#define __RNS_LINK_UTILS_H__

#include "rns/link_parser.h"

#include <stdbool.h>
#include <stdint.h>

rns_ret_t rns_link_utils_clamp_mtu(
    uint8_t *packet,
    uint16_t packet_len,
    const rns_link_packet_info_t *pkt,
    uint32_t mtu_limit,
    uint32_t *original_mtu
);

#endif // __RNS_LINK_UTILS_H__
