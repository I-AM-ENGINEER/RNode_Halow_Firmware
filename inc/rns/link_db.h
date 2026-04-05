#ifndef __RNS_LINK_DB_H__
#define __RNS_LINK_DB_H__

#include "rns/defines.h"

#define RNS_DB_INDEX_NONE    (0xFFu)

typedef struct {
    uint8_t id[RNS_LINK_ID_LEN];
    uint8_t destination[RNS_TRUNCATED_HASH_LEN];
    int32_t firstseen_timestamp_s;
    int32_t lastrx_timestamp_s;
    int32_t lasttx_timestamp_s;
    int32_t rx_bytes;
    int32_t tx_bytes;
    int32_t rx_packets;
    int32_t tx_packets;
    uint8_t hops;
    rns_link_db_state_t state;
    uint8_t hash_next;
    void *user;
} rns_link_db_link_t;

typedef struct {
    rns_link_db_link_t* links[RNS_DB_MAX_LINK_COUNT];
    uint8_t buckets[RNS_DB_HASH_SIZE];
    uint8_t links_count;
} rns_link_db_t;

int32_t rns_link_db_package_register( const rns_link_packet_info_t* pkg, rns_packet_direction_t direction );
rns_link_db_link_t* rns_link_db_link_get( const uint8_t id[RNS_LINK_ID_LEN] );
rns_link_db_link_t* rns_link_db_link_get_by_index( uint32_t index );
uint8_t rns_link_db_link_count_get( void );
void rns_link_db_link_remove( rns_link_db_link_t *link );
void* rns_link_db_link_user_get( const rns_link_db_link_t *link );
void rns_link_db_link_user_set( rns_link_db_link_t *link, void *user );

#endif // __LINK_DB_H__
