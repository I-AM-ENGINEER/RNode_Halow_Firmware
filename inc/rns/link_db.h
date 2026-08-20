#ifndef __RNS_LINK_DB_H__
#define __RNS_LINK_DB_H__

#include "rns/defines.h"

#define RNS_DB_INDEX_NONE    (0xFFu)
#define RNS_LINK_MAC_UNKNOWN_BYTE    (0xFFu)

typedef struct {
    uint8_t id[RNS_LINK_ID_LEN];
    uint8_t destination[RNS_TRUNCATED_HASH_LEN];
    int32_t firstseen_timestamp_s;
    int32_t lastrx_timestamp_s;
    int32_t lasttx_timestamp_s;
    uint32_t rx_bytes;
    uint32_t tx_bytes;
    uint32_t rx_packets;
    uint32_t tx_packets;
    uint8_t hops;
    rns_link_db_state_t state;
    uint8_t remote_mac[6];
    uint32_t effective_mtu;
    uint8_t hash_next;
} rns_link_db_link_t;

typedef struct {
    rns_link_db_link_t* links[RNS_DB_MAX_LINK_COUNT];
    uint8_t buckets[RNS_DB_HASH_SIZE];
    uint8_t links_count;
} rns_link_db_t;

void rns_link_db_init( void );

/* Atomic packet registration: looks up/creates the link, updates counters,
 * state machine, and optionally the peer MAC and effective MTU — all under a
 * single lock. No raw link pointers escape the DB, so callers are race-free.
 *
 * remote_mac != NULL  -> store the peer MAC (logged only when it changes)
 * unicast_to_me       -> an already-learned MAC is only overwritten by frames
 *                        that were ADDRESSED TO US (dst == our MAC). A
 *                        broadcast-destined replay can no longer hijack a
 *                        link's TX destination to an attacker MAC; the
 *                        unknown->known transition stays free (bootstrap).
 * update_mtu == true  -> store effective_mtu (logged only when it changes) */
int32_t rns_link_db_package_register( const rns_link_packet_info_t* pkg,
                                      rns_packet_direction_t direction,
                                      const uint8_t *remote_mac,
                                      uint32_t effective_mtu,
                                      bool update_mtu,
                                      bool unicast_to_me );

uint8_t rns_link_db_link_count_get( void );

void rns_link_db_sweep_expired( void );

bool rns_link_db_link_snapshot_by_index( uint32_t index, rns_link_db_link_t *out );

bool rns_link_db_link_snapshot_by_id( const uint8_t link_id[RNS_LINK_ID_LEN], rns_link_db_link_t *out );

#endif // __LINK_DB_H__
