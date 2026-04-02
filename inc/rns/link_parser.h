#ifndef LINK_PARSER_H
#define LINK_PARSER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define LINK_PARSER_TRUNCATED_HASH_LEN    (16U)
#define LINK_PARSER_LINK_ID_LEN           LINK_PARSER_TRUNCATED_HASH_LEN
#define LINK_PARSER_LINKREQUEST_CORE_LEN  (64U)

typedef enum {
    LINK_PARSER_PACKET_DATA        = 0x00U,
    LINK_PARSER_PACKET_ANNOUNCE    = 0x01U,
    LINK_PARSER_PACKET_LINKREQUEST = 0x02U,
    LINK_PARSER_PACKET_PROOF       = 0x03U
} link_parser_packet_type_t;

typedef enum {
    LINK_PARSER_HEADER_1 = 0x00U,
    LINK_PARSER_HEADER_2 = 0x01U
} link_parser_header_type_t;

typedef enum {
    LINK_PARSER_DESTINATION_SINGLE = 0x00U,
    LINK_PARSER_DESTINATION_GROUP  = 0x01U,
    LINK_PARSER_DESTINATION_PLAIN  = 0x02U,
    LINK_PARSER_DESTINATION_LINK   = 0x03U
} link_parser_destination_type_t;

typedef enum {
    LINK_PARSER_CONTEXT_NONE         = 0x00U,
    LINK_PARSER_CONTEXT_KEEPALIVE    = 0xFAU,
    LINK_PARSER_CONTEXT_LINKIDENTIFY = 0xFBU,
    LINK_PARSER_CONTEXT_LINKCLOSE    = 0xFCU,
    LINK_PARSER_CONTEXT_LINKPROOF    = 0xFDU,
    LINK_PARSER_CONTEXT_LRRTT        = 0xFEU,
    LINK_PARSER_CONTEXT_LRPROOF      = 0xFFU
} link_parser_context_t;

typedef struct {
    bool valid;

    uint8_t flags;
    uint8_t hops;

    link_parser_header_type_t header_type;
    bool context_flag;
    bool transport_type;
    link_parser_destination_type_t destination_type;
    link_parser_packet_type_t packet_type;
    link_parser_context_t context;

    size_t header_size;
    size_t payload_offset;
    size_t payload_len;

    bool has_transport_id;
    uint8_t transport_id[LINK_PARSER_TRUNCATED_HASH_LEN];

    uint8_t destination[LINK_PARSER_TRUNCATED_HASH_LEN];
    bool destination_is_link_id;

    bool has_link_id;
    bool link_id_computed;
    uint8_t link_id[LINK_PARSER_LINK_ID_LEN];
} link_parser_packet_t;

bool link_parser_parse( const uint8_t *packet, size_t packet_len, link_parser_packet_t *out );
bool link_parser_get_link_id( const uint8_t *packet, size_t packet_len, uint8_t out_link_id[LINK_PARSER_LINK_ID_LEN] );

#endif