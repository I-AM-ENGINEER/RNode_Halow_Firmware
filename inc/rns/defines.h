#ifndef __RNS_DEFINES_H__
#define __RNS_DEFINES_H__

#include "sys_config.h"
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#define RNS_TRUNCATED_HASH_LEN          (16)
#define RNS_LINK_ID_LEN                 RNS_TRUNCATED_HASH_LEN
#define RNS_LINKREQUEST_CORE_LEN        (64)

// Window for search rns package, should be slightly (1-2%) larger that max MTU
#ifndef RNS_STREAM_MAX_FRAME_SIZE
#define RNS_STREAM_MAX_FRAME_SIZE       (1500)
#endif

// Max plain package length
#ifndef RNS_MAX_MTU
#define RNS_MAX_MTU                     (1460)
#endif

// Time for clear links without activity
#ifndef RNS_LINK_TIMEOUT_S
#define RNS_LINK_TIMEOUT_S              (900)
#endif

// Max link count is 255 because uint8_t is used for hash table indices.
#ifndef RNS_DB_MAX_LINK_COUNT
#define RNS_DB_MAX_LINK_COUNT           (255)
#endif

#ifndef RNS_DB_HASH_SIZE
#define RNS_DB_HASH_SIZE                ((RNS_DB_MAX_LINK_COUNT) * 2)
#endif

#ifndef RNS_LINK_PARSER_LOG_LEVEL
#define RNS_LINK_PARSER_LOG_LEVEL       LOG_TRACE
#endif

#ifndef RNS_STREAM_PARSER_LOG_LEVEL
#define RNS_STREAM_PARSER_LOG_LEVEL     LOG_WARN
#endif

#if RNS_DB_MAX_LINK_COUNT > 255
#error "Max link count cant be more that 255"
#endif

typedef enum {
    RNS_PACKET_DIRECTION_RX,
    RNS_PACKET_DIRECTION_TX,
} rns_packet_direction_t;

typedef enum {
    RNS_LINK_STATE_CLOSED,
    RNS_LINK_STATE_REQUEST_SENT,
    RNS_LINK_STATE_PROOF_RECEIVED,
    RNS_LINK_STATE_OPEN,
} rns_link_db_state_t;

typedef enum {
    RNS_RET_OK = 0,
    RNS_RET_NULLPTR,
    RNS_RET_PACKET_TOO_SHORT,
    RNS_RET_INVALID_HEADER_TYPE,
    RNS_RET_INVALID_HEADER2_SIZE,
    RNS_RET_INVALID_HASH_BODY,
    RNS_RET_NO_LINK_ID,
    RNS_RET_NO_SLOT,
    RNS_RET_NO_MEMORY
} rns_ret_t;

typedef enum {
    RNS_PACKET_TYPE_DATA        = 0x00U,
    RNS_PACKET_TYPE_ANNOUNCE    = 0x01U,
    RNS_PACKET_TYPE_LINKREQUEST = 0x02U,
    RNS_PACKET_TYPE_PROOF       = 0x03U
} rns_packet_type_t;

typedef enum {
    RNS_HEADER_TYPE_1           = 0x00U,
    RNS_HEADER_TYPE_2           = 0x01U
} rns_header_type_t;

typedef enum {
    RNS_DESTINATION_TYPE_SINGLE = 0x00U,
    RNS_DESTINATION_TYPE_GROUP  = 0x01U,
    RNS_DESTINATION_TYPE_PLAIN  = 0x02U,
    RNS_DESTINATION_TYPE_LINK   = 0x03U
} rns_destination_type_t;

typedef enum {
    RNS_CONTEXT_NONE            = 0x00U,
    RNS_CONTEXT_KEEPALIVE       = 0xFAU,
    RNS_CONTEXT_LINKIDENTIFY    = 0xFBU,
    RNS_CONTEXT_LINKCLOSE       = 0xFCU,
    RNS_CONTEXT_LINKPROOF       = 0xFDU,
    RNS_CONTEXT_LRRTT           = 0xFEU,
    RNS_CONTEXT_LRPROOF         = 0xFFU
} rns_context_t;

typedef struct {
    uint8_t hops;
    rns_destination_type_t destination_type;
    rns_packet_type_t packet_type;
    rns_context_t context;
    uint16_t payload_len;
    uint8_t destination[RNS_TRUNCATED_HASH_LEN];
    uint8_t link_id[RNS_LINK_ID_LEN];
} rns_link_packet_info_t;

#endif // __RNS_DEFINES_H__
