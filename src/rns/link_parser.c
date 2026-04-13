#include "rns/link_parser.h"

#include <string.h>

#include "lib/crypto/sha256.h"

#define RNS_HEADER_TYPE1_SIZE  (2U + RNS_TRUNCATED_HASH_LEN + 1U)
#define RNS_HEADER_TYPE2_SIZE  (2U + RNS_TRUNCATED_HASH_LEN + RNS_TRUNCATED_HASH_LEN + 1U)

static int32_t rns_link_parser_calc_link_id(
    const uint8_t *packet,
    size_t packet_len,
    uint8_t out_link_id[RNS_LINK_ID_LEN]
){
    SHA256_CTX ctx;
    uint8_t digest[SHA256_BLOCK_SIZE];
    uint8_t first;
    uint8_t flags;
    rns_header_type_t header_type;
    rns_packet_type_t packet_type;
    size_t hash_body_offset;
    size_t hash_body_len;
    size_t payload_offset;
    size_t payload_len;

    if( packet == NULL || out_link_id == NULL ){
        return RNS_RET_NULLPTR;
    }

    if( packet_len < RNS_HEADER_TYPE1_SIZE ){
        return RNS_RET_PACKET_TOO_SHORT;
    }

    flags = packet[0];
    header_type = (rns_header_type_t)((flags >> 6U) & 0x01U);
    packet_type = (rns_packet_type_t)(flags & 0x03U);

    if( header_type == RNS_HEADER_TYPE_1 ){
        payload_offset = RNS_HEADER_TYPE1_SIZE;
        hash_body_offset = 2U;
    }else if( header_type == RNS_HEADER_TYPE_2 ){
        if( packet_len < RNS_HEADER_TYPE2_SIZE ){
            return RNS_RET_INVALID_HEADER2_SIZE;
        }

        payload_offset = RNS_HEADER_TYPE2_SIZE;
        hash_body_offset = 2U + RNS_TRUNCATED_HASH_LEN;
    }else{
        return RNS_RET_INVALID_HEADER_TYPE;
    }

    payload_len = packet_len - payload_offset;
    hash_body_len = packet_len - hash_body_offset;

    if( packet_type == RNS_PACKET_TYPE_LINKREQUEST && payload_len > RNS_LINKREQUEST_CORE_LEN ){
        hash_body_len -= payload_len - RNS_LINKREQUEST_CORE_LEN;
    }

    first = (uint8_t)(flags & 0x0FU);

    sha256_init(&ctx);
    sha256_update(&ctx, &first, 1U);
    sha256_update(&ctx, &packet[hash_body_offset], hash_body_len);
    sha256_final(&ctx, digest);

    memcpy(out_link_id, digest, RNS_LINK_ID_LEN);

    return RNS_RET_OK;
}

int32_t rns_link_parser_parse( const uint8_t *packet, size_t packet_len, rns_link_packet_info_t *out ){
    uint8_t flags;
    rns_header_type_t header_type;
    size_t payload_offset;
    int rc;

    if( packet == NULL || out == NULL ){
        return RNS_RET_NULLPTR;
    }

    if( packet_len < RNS_HEADER_TYPE1_SIZE ){
        return RNS_RET_PACKET_TOO_SHORT;
    }

    memset(out, 0, sizeof(*out));

    flags = packet[0];

    out->hops = packet[1];
    out->destination_type = (rns_destination_type_t)((flags >> 2U) & 0x03U);
    out->packet_type = (rns_packet_type_t)(flags & 0x03U);

    header_type = (rns_header_type_t)((flags >> 6U) & 0x01U);

    if( header_type == RNS_HEADER_TYPE_1 ){
        payload_offset = RNS_HEADER_TYPE1_SIZE;
        memcpy(out->destination, &packet[2], RNS_TRUNCATED_HASH_LEN);
        out->context = (rns_context_t)packet[2U + RNS_TRUNCATED_HASH_LEN];
    }else if( header_type == RNS_HEADER_TYPE_2 ){
        if( packet_len < RNS_HEADER_TYPE2_SIZE ){
            return RNS_RET_INVALID_HEADER2_SIZE;
        }

        payload_offset = RNS_HEADER_TYPE2_SIZE;
        memcpy(out->destination, &packet[2U + RNS_TRUNCATED_HASH_LEN], RNS_TRUNCATED_HASH_LEN);
        out->context = (rns_context_t)packet[2U + RNS_TRUNCATED_HASH_LEN + RNS_TRUNCATED_HASH_LEN];
    }else{
        return RNS_RET_INVALID_HEADER_TYPE;
    }

    out->payload_len = (uint16_t)(packet_len - payload_offset);

    if( out->destination_type == RNS_DESTINATION_TYPE_LINK ){
        memcpy(out->link_id, out->destination, RNS_LINK_ID_LEN);
        return RNS_RET_OK;
    }

    if( out->packet_type == RNS_PACKET_TYPE_LINKREQUEST ){
        rc = rns_link_parser_calc_link_id(packet, packet_len, out->link_id);
        if( rc != RNS_RET_OK ){
            return rc;
        }
    }

    out->valid =
        (out->destination_type == RNS_DESTINATION_TYPE_LINK) ||
        (out->packet_type == RNS_PACKET_TYPE_LINKREQUEST);

    return RNS_RET_OK;
}
