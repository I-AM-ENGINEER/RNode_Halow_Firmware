#include "rns/link_utils.h"

#include <stddef.h>

static size_t link_payload_offset(
    uint16_t packet_len,
    const rns_link_packet_info_t *pkt
){
    return (size_t)packet_len - (size_t)pkt->payload_len;
}

static uint32_t link_request_get_mtu(
    const uint8_t *packet,
    uint16_t packet_len,
    const rns_link_packet_info_t *pkt
){
    const size_t off = link_payload_offset(packet_len, pkt) + 64U;
    const uint32_t signalling =
        ((uint32_t)packet[off + 0] << 16U) |
        ((uint32_t)packet[off + 1] << 8U)  |
        ((uint32_t)packet[off + 2] << 0U);

    return signalling & 0x1FFFFFU;
}

static uint8_t link_request_get_mode(
    const uint8_t *packet,
    uint16_t packet_len,
    const rns_link_packet_info_t *pkt
){
    const size_t off = link_payload_offset(packet_len, pkt) + 64U;
    return (uint8_t)((packet[off + 0] >> 5U) & 0x07U);
}

static void link_request_set_signalling(
    uint8_t *packet,
    uint16_t packet_len,
    const rns_link_packet_info_t *pkt,
    uint8_t mode,
    uint32_t mtu
){
    const size_t off = link_payload_offset(packet_len, pkt) + 64U;
    const uint32_t signalling =
        (mtu & 0x1FFFFFU) |
        (((uint32_t)(mode & 0x07U)) << 21U);

    packet[off + 0] = (uint8_t)((signalling >> 16U) & 0xFFU);
    packet[off + 1] = (uint8_t)((signalling >> 8U) & 0xFFU);
    packet[off + 2] = (uint8_t)((signalling >> 0U) & 0xFFU);
}

rns_ret_t rns_link_utils_clamp_mtu(
    uint8_t *packet,
    uint16_t packet_len,
    const rns_link_packet_info_t *pkt,
    uint32_t mtu_limit,
    uint32_t *original_mtu
){
    uint32_t mtu;
    uint8_t mode;

    if( original_mtu != NULL ){
        *original_mtu = 0U;
    }

    if( packet == NULL || pkt == NULL ){
        return RNS_RET_NULLPTR;
    }

    if( pkt->packet_type != RNS_PACKET_TYPE_LINKREQUEST ){
        return RNS_RET_INVALID_PACKET_TYPE;
    }

    if( pkt->payload_len < 67U ){
        return RNS_RET_PACKET_TOO_SHORT;
    }

    mtu = link_request_get_mtu(packet, packet_len, pkt);

    if( original_mtu != NULL ){
        *original_mtu = mtu;
    }

    if( mtu <= mtu_limit ){
        return RNS_RET_NOT_MODIFIED;
    }

    mode = link_request_get_mode(packet, packet_len, pkt);
    link_request_set_signalling(packet, packet_len, pkt, mode, mtu_limit);

    return RNS_RET_OK;
}

rns_ret_t rns_link_utils_get_mtu(
    const uint8_t *packet,
    uint16_t packet_len,
    const rns_link_packet_info_t *pkt,
    uint32_t *mtu
){
    if( mtu != NULL ){
        *mtu = 0U;
    }

    if( packet == NULL || pkt == NULL || mtu == NULL ){
        return RNS_RET_NULLPTR;
    }

    if( pkt->packet_type != RNS_PACKET_TYPE_LINKREQUEST ){
        return RNS_RET_INVALID_PACKET_TYPE;
    }

    if( pkt->payload_len < 67U ){
        return RNS_RET_PACKET_TOO_SHORT;
    }

    *mtu = link_request_get_mtu(packet, packet_len, pkt);

    return RNS_RET_OK;
}
