#ifndef __RNS_LINK_PARSER_H__
#define __RNS_LINK_PARSER_H__

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "rns/defines.h"

typedef struct {
    bool valid;

    uint8_t flags;
    uint8_t hops;

    rns_header_type_t header_type;
    bool context_flag;
    bool transport_type;
    rns_destination_type_t destination_type;
    rns_packet_type_t packet_type;
    rns_context_t context;

    size_t header_size;
    size_t payload_offset;
    size_t payload_len;

    bool has_transport_id;
    uint8_t transport_id[RNS_TRUNCATED_HASH_LEN];

    uint8_t destination[RNS_TRUNCATED_HASH_LEN];
    bool destination_is_link_id;

    bool has_link_id;
    bool link_id_computed;
    uint8_t link_id[RNS_LINK_ID_LEN];
} rns_link_parser_packet_t;

bool rns_link_parser_parse( const uint8_t *packet, size_t packet_len, rns_link_parser_packet_t *out );

#endif // __RNS_LINK_PARSER_H__
