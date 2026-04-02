#include "rns/link_parser.h"

#include <string.h>

#include "lib/crypto/sha256.h"

#define LOG_LOCAL_LEVEL LOG_WARN
#include "lib/logc/log.h"

#define RNS_LINK_PARSER_HEADER1_SIZE  (2U + RNS_TRUNCATED_HASH_LEN + 1U)
#define RNS_LINK_PARSER_HEADER2_SIZE  (2U + RNS_TRUNCATED_HASH_LEN + RNS_TRUNCATED_HASH_LEN + 1U)

static bool rns_link_parser_calc_link_id( const uint8_t *packet, size_t packet_len, uint8_t out_link_id[RNS_LINK_ID_LEN] ){
    SHA256_CTX ctx;
    uint8_t digest[SHA256_BLOCK_SIZE];
    uint8_t first;
    rns_header_type_t header_type;
    rns_packet_type_t packet_type;
    size_t hash_body_offset;
    size_t hash_body_len;
    size_t payload_offset;
    size_t payload_len;

    if( packet == NULL || out_link_id == NULL ){
        return false;
    }

    if( packet_len < RNS_LINK_PARSER_HEADER1_SIZE ){
        return false;
    }

    header_type = (rns_header_type_t)((packet[0] >> 6U) & 0x01U);
    packet_type = (rns_packet_type_t)(packet[0] & 0x03U);

    if( header_type == RNS_LINK_PARSER_HEADER_1 ){
        payload_offset = RNS_LINK_PARSER_HEADER1_SIZE;
        hash_body_offset = 2U;
    }else if( header_type == RNS_LINK_PARSER_HEADER_2 ){
        if( packet_len < RNS_LINK_PARSER_HEADER2_SIZE ){
            return false;
        }

        payload_offset = RNS_LINK_PARSER_HEADER2_SIZE;
        hash_body_offset = 2U + RNS_TRUNCATED_HASH_LEN;
    }else{
        return false;
    }

    payload_len = packet_len - payload_offset;
    hash_body_len = packet_len - hash_body_offset;

    if( packet_type == RNS_LINK_PARSER_PACKET_LINKREQUEST && payload_len > RNS_LINKREQUEST_CORE_LEN ){
        const size_t diff = payload_len - RNS_LINKREQUEST_CORE_LEN;

        if( hash_body_len < diff ){
            return false;
        }

        hash_body_len -= diff;
    }

    sha256_init(&ctx);

    first = (uint8_t)(packet[0] & 0x0FU);
    sha256_update(&ctx, &first, 1U);
    sha256_update(&ctx, &packet[hash_body_offset], hash_body_len);
    sha256_final(&ctx, digest);

    memcpy(out_link_id, digest, RNS_LINK_ID_LEN);
    return true;
}

bool rns_link_parser_parse( const uint8_t *packet, size_t packet_len, rns_link_parser_packet_t *out ){
    if( packet == NULL || out == NULL ){
        return false;
    }

    memset(out, 0, sizeof(*out));

    if( packet_len < RNS_LINK_PARSER_HEADER1_SIZE ){
        log_trace("link_parser: packet too short: %u", (unsigned)packet_len);
        return false;
    }

    out->flags = packet[0];
    out->hops = packet[1];

    out->header_type = (rns_header_type_t)((out->flags >> 6U) & 0x01U);
    out->context_flag = ((out->flags >> 5U) & 0x01U) != 0U;
    out->transport_type = ((out->flags >> 4U) & 0x01U) != 0U;
    out->destination_type = (rns_destination_type_t)((out->flags >> 2U) & 0x03U);
    out->packet_type = (rns_packet_type_t)(out->flags & 0x03U);

    if( out->header_type == RNS_LINK_PARSER_HEADER_1 ){
        out->header_size = RNS_LINK_PARSER_HEADER1_SIZE;
        out->payload_offset = RNS_LINK_PARSER_HEADER1_SIZE;
        out->payload_len = packet_len - out->payload_offset;

        memcpy(out->destination, &packet[2], RNS_TRUNCATED_HASH_LEN);
        out->context = (rns_context_t)packet[2U + RNS_TRUNCATED_HASH_LEN];
    }else if( out->header_type == RNS_LINK_PARSER_HEADER_2 ){
        if( packet_len < RNS_LINK_PARSER_HEADER2_SIZE ){
            log_warn("link_parser: invalid HEADER_2 size");
            return false;
        }

        out->header_size = RNS_LINK_PARSER_HEADER2_SIZE;
        out->payload_offset = RNS_LINK_PARSER_HEADER2_SIZE;
        out->payload_len = packet_len - out->payload_offset;

        out->has_transport_id = true;
        memcpy(out->transport_id, &packet[2], RNS_TRUNCATED_HASH_LEN);
        memcpy(out->destination, &packet[2U + RNS_TRUNCATED_HASH_LEN], RNS_TRUNCATED_HASH_LEN);
        out->context = (rns_context_t)packet[2U + RNS_TRUNCATED_HASH_LEN + RNS_TRUNCATED_HASH_LEN];
    }else{
        log_warn("link_parser: unknown header_type=%u", (unsigned)out->header_type);
        return false;
    }

    if( out->destination_type == RNS_LINK_PARSER_DESTINATION_LINK ){
        out->destination_is_link_id = true;
        out->has_link_id = true;
        out->link_id_computed = false;
        memcpy(out->link_id, out->destination, RNS_LINK_ID_LEN);
    }else if( out->packet_type == RNS_LINK_PARSER_PACKET_LINKREQUEST ){
        if( rns_link_parser_calc_link_id(packet, packet_len, out->link_id) ){
            out->has_link_id = true;
            out->link_id_computed = true;
        }else{
            log_warn("link_parser: failed to calculate link_id for LINKREQUEST");
        }
    }

    out->valid = true;

    if( out->packet_type == RNS_LINK_PARSER_PACKET_LINKREQUEST ||
		out->destination_type == RNS_LINK_PARSER_DESTINATION_LINK ){
		log_trace(
			"link_parser: packet_type=0x%02X destination_type=0x%02X context=0x%02X has_link_id=%u",
			(unsigned)out->packet_type,
			(unsigned)out->destination_type,
			(unsigned)out->context,
			(unsigned)(out->has_link_id ? 1U : 0U)
		);
	}

    return true;
}
