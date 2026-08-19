#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "sys_config.h"
#define LOG_LOCAL_LEVEL LOG_LEVEL_RNS_LINK_DB
#include "basic_include.h"
#include "lib/logc/log.h"
#include "rns/link_db.h"

static rns_link_db_t g_link_db = {
    .buckets = {
        [0 ...(RNS_DB_HASH_SIZE - 1)] = RNS_DB_INDEX_NONE
    }
};

static struct os_mutex g_link_db_mutex;

static void rns_link_db_lock( void ){
    (void)os_mutex_lock(&g_link_db_mutex, -1);
}

static void rns_link_db_unlock( void ){
    os_mutex_unlock(&g_link_db_mutex);
}

static int32_t rns_link_db_timestamp_s( void ){
    return (int32_t)time(NULL);
}

static uint16_t rns_link_db_hash_id( const uint8_t id[RNS_LINK_ID_LEN] ){
    uint32_t hash = 2166136261u;
    uint32_t i;

    for( i = 0; i < RNS_LINK_ID_LEN; ++i ){
        hash ^= id[i];
        hash *= 16777619u;
    }

    return (uint16_t)(hash % RNS_DB_HASH_SIZE);
}

static int32_t rns_link_db_find_index_by_id( const uint8_t id[RNS_LINK_ID_LEN] ){
    uint16_t bucket_idx;
    uint8_t index;

    bucket_idx = rns_link_db_hash_id(id);
    index = g_link_db.buckets[bucket_idx];

    while( index != RNS_DB_INDEX_NONE ){
        if( g_link_db.links[index] == NULL ){
            return -1;
        }

        if( memcmp(g_link_db.links[index]->id, id, RNS_LINK_ID_LEN) == 0 ){
            return (int32_t)index;
        }

        index = g_link_db.links[index]->hash_next;
    }

    return -1;
}

static int32_t rns_link_db_find_free_slot( void ){
    uint32_t i;

    if( g_link_db.links_count >= RNS_DB_MAX_LINK_COUNT ){
        return -1;
    }

    for( i = 0; i < RNS_DB_MAX_LINK_COUNT; ++i ){
        if( g_link_db.links[i] == NULL ){
            return (int32_t)i;
        }
    }

    return -1;
}

static void rns_link_db_remove_index( uint8_t index ){
    rns_link_db_link_t *link;
    uint16_t bucket_idx;
    uint8_t cur;

    link = g_link_db.links[index];

    if( link == NULL ){
        return;
    }

    bucket_idx = rns_link_db_hash_id(link->id);
    cur = g_link_db.buckets[bucket_idx];

    if( cur == index ){
        g_link_db.buckets[bucket_idx] = link->hash_next;
    }else{
        while( cur != RNS_DB_INDEX_NONE ){
            if( g_link_db.links[cur] == NULL ){
                break;
            }

            if( g_link_db.links[cur]->hash_next == index ){
                g_link_db.links[cur]->hash_next = link->hash_next;
                break;
            }

            cur = g_link_db.links[cur]->hash_next;
        }
    }

    free(link);
    g_link_db.links[index] = NULL;

    if( g_link_db.links_count > 0 ){
        g_link_db.links_count--;
    }
}

static const char *rns_link_state_name( rns_link_db_state_t s ){
    switch( s ){
        case RNS_LINK_STATE_CLOSED:         return "closed";
        case RNS_LINK_STATE_REQUEST_SENT:   return "req_sent";
        case RNS_LINK_STATE_PROOF_RECEIVED: return "proof";
        case RNS_LINK_STATE_OPEN:           return "open";
        default:                            return "?";
    }
}

static bool rns_link_mac_is_unknown( const uint8_t mac[6] ){
    int i;

    for( i = 0; i < 6; i++ ){
        if( mac[i] != RNS_LINK_MAC_UNKNOWN_BYTE ){
            return false;
        }
    }

    return true;
}

int32_t rns_link_db_package_register( const rns_link_packet_info_t *pkg,
                                      rns_packet_direction_t direction,
                                      const uint8_t *remote_mac,
                                      uint32_t effective_mtu,
                                      bool update_mtu,
                                      bool unicast_to_me ){
    rns_link_db_link_t *link;
    int32_t index;
    int32_t slot;
    int32_t now_s;
    uint16_t bucket_idx;
    bool is_new = false;
    bool mac_changed = false;
    bool mtu_changed = false;
    rns_link_db_state_t prev_state;
    const char *dir = (direction == RNS_PACKET_DIRECTION_RX) ? "rx" : "tx";

    if( pkg == NULL ){
        return RNS_RET_NULLPTR;
    }

    rns_link_db_lock();
    now_s = rns_link_db_timestamp_s();
    index = rns_link_db_find_index_by_id(pkg->link_id);

    if( pkg->context == RNS_CONTEXT_LINKCLOSE ){
        if( index >= 0 ){
            log_info("[%s] link close id=%02X%02X%02X%02X",
                     dir,
                     pkg->link_id[0], pkg->link_id[1],
                     pkg->link_id[2], pkg->link_id[3]);
            rns_link_db_remove_index((uint8_t)index);
        }

        rns_link_db_unlock();
        return RNS_RET_OK;
    }

    if( index >= 0 ){
        link = g_link_db.links[index];

        if( link == NULL ){
            rns_link_db_unlock();
            return RNS_RET_NO_SLOT;
        }
    }else{
        slot = rns_link_db_find_free_slot();
        if( slot < 0 ){
            rns_link_db_unlock();
            return RNS_RET_NO_SLOT;
        }

        link = malloc(sizeof(rns_link_db_link_t));
        if( link == NULL ){
            rns_link_db_unlock();
            return RNS_RET_NO_MEMORY;
        }

        memset(link, 0, sizeof(*link));
        memcpy(link->id, pkg->link_id, RNS_LINK_ID_LEN);
        memcpy(link->destination, pkg->destination, RNS_TRUNCATED_HASH_LEN);

        link->firstseen_timestamp_s = now_s;
        link->lastrx_timestamp_s = (direction == RNS_PACKET_DIRECTION_RX) ? now_s : 0;
        link->lasttx_timestamp_s = (direction == RNS_PACKET_DIRECTION_TX) ? now_s : 0;
        link->hops = pkg->hops;
        link->state = RNS_LINK_STATE_CLOSED;
        memset(link->remote_mac, RNS_LINK_MAC_UNKNOWN_BYTE, sizeof(link->remote_mac));
        link->effective_mtu = 0;

        bucket_idx = rns_link_db_hash_id(link->id);
        link->hash_next = g_link_db.buckets[bucket_idx];
        g_link_db.links[slot] = link;
        g_link_db.buckets[bucket_idx] = (uint8_t)slot;
        g_link_db.links_count++;
        is_new = true;
    }

    link->hops = pkg->hops;

    if( direction == RNS_PACKET_DIRECTION_RX ){
        link->lastrx_timestamp_s = now_s;
        link->rx_packets++;
        link->rx_bytes += pkg->payload_len;
    }else{
        link->lasttx_timestamp_s = now_s;
        link->tx_packets++;
        link->tx_bytes += pkg->payload_len;
    }

    if( remote_mac != NULL &&
        ( unicast_to_me || rns_link_mac_is_unknown(link->remote_mac) ) ){
        mac_changed = rns_link_mac_is_unknown(link->remote_mac) ||
                      (memcmp(link->remote_mac, remote_mac, 6) != 0);
        memcpy(link->remote_mac, remote_mac, sizeof(link->remote_mac));
        /* Note: with the addr1=broadcast framing convention (see halow_send_frame),
         * RX delivery does NOT require the peer to be in the LMAC STA table —
         * broadcast-addressed frames are delivered to the host unconditionally,
         * and the per-destination filter happens in halow_rx_handler on addr3.
         * remote_mac is stored here purely so the TX path can address the peer.
         * An already-learned MAC is only re-written for frames ADDRESSED TO US:
         * a captured frame replayed with a broadcast addr3 (which the RX filter
         * accepts) must not be able to silently move our TX destination to an
         * attacker's MAC. */
    }

    if( update_mtu && link->effective_mtu != effective_mtu ){
        link->effective_mtu = effective_mtu;
        mtu_changed = true;
    }

    prev_state = link->state;

    if( link->state != RNS_LINK_STATE_OPEN ){
        if( pkg->packet_type == RNS_PACKET_TYPE_LINKREQUEST ){
            if( direction == RNS_PACKET_DIRECTION_TX && link->state == RNS_LINK_STATE_CLOSED ){
                link->state = RNS_LINK_STATE_REQUEST_SENT;
            }
        }else if(
            pkg->packet_type == RNS_PACKET_TYPE_PROOF ||
            pkg->context == RNS_CONTEXT_LINKPROOF ||
            pkg->context == RNS_CONTEXT_LRPROOF
        ){
            link->state = RNS_LINK_STATE_PROOF_RECEIVED;
        }else if( pkg->destination_type == RNS_DESTINATION_TYPE_LINK ){
            link->state = RNS_LINK_STATE_OPEN;
        }
    }

    if( is_new ){
        log_info("[%s] link new id=%02X%02X%02X%02X state=%s hops=%u pt=%u ctx=%02X dt=%u len=%u",
                 dir,
                 link->id[0], link->id[1], link->id[2], link->id[3],
                 rns_link_state_name(link->state),
                 (unsigned)link->hops,
                 (unsigned)pkg->packet_type,
                 (unsigned)pkg->context,
                 (unsigned)pkg->destination_type,
                 (unsigned)pkg->payload_len);
    }

    if( link->state != prev_state ){
        log_info("[%s] link state id=%02X%02X%02X%02X %s->%s pt=%u ctx=%02X dt=%u",
                 dir,
                 link->id[0], link->id[1], link->id[2], link->id[3],
                 rns_link_state_name(prev_state),
                 rns_link_state_name(link->state),
                 (unsigned)pkg->packet_type,
                 (unsigned)pkg->context,
                 (unsigned)pkg->destination_type);
    }

    if( mac_changed ){
        log_info("[%s] link mac id=%02X%02X%02X%02X mac=%02X:%02X:%02X:%02X:%02X:%02X",
                 dir,
                 link->id[0], link->id[1], link->id[2], link->id[3],
                 link->remote_mac[0], link->remote_mac[1], link->remote_mac[2],
                 link->remote_mac[3], link->remote_mac[4], link->remote_mac[5]);
    }

    if( mtu_changed ){
        log_info("[%s] link mtu id=%02X%02X%02X%02X mtu=%u",
                 dir,
                 link->id[0], link->id[1], link->id[2], link->id[3],
                 (unsigned)link->effective_mtu);
    }

    rns_link_db_unlock();
    return RNS_RET_OK;
}

uint8_t rns_link_db_link_count_get( void ){
    uint8_t c;

    rns_link_db_lock();
    c = g_link_db.links_count;
    rns_link_db_unlock();
    return c;
}

void rns_link_db_sweep_expired( void ){
    int32_t now_s;
    uint32_t i;
    int32_t last_activity_s;
    uint32_t removed = 0;

    now_s = rns_link_db_timestamp_s();

    rns_link_db_lock();
    for( i = 0; i < RNS_DB_MAX_LINK_COUNT; i++ ){
        rns_link_db_link_t *link = g_link_db.links[i];
        if( link == NULL ){
            continue;
        }

        last_activity_s = 0;
        if( link->lastrx_timestamp_s > last_activity_s ){
            last_activity_s = link->lastrx_timestamp_s;
        }
        if( link->lasttx_timestamp_s > last_activity_s ){
            last_activity_s = link->lasttx_timestamp_s;
        }

        if( last_activity_s > 0 && (now_s - last_activity_s) > RNS_LINK_TIMEOUT_S ){
            rns_link_db_remove_index((uint8_t)i);
            removed++;
        }
    }
    rns_link_db_unlock();

    if( removed > 0 ){
        log_info("link db swept %u expired link(s)", (unsigned)removed);
    }
}

bool rns_link_db_link_snapshot_by_index( uint32_t index, rns_link_db_link_t *out ){
    uint32_t i;
    uint32_t pos = 0;
    bool found = false;

    if( out == NULL ){
        return false;
    }

    rns_link_db_lock();
    for( i = 0; i < RNS_DB_MAX_LINK_COUNT; i++ ){
        rns_link_db_link_t *link = g_link_db.links[i];
        if( link == NULL ){
            continue;
        }

        if( pos == index ){
            *out = *link;
            found = true;
            break;
        }

        pos++;
    }
    rns_link_db_unlock();

    return found;
}

bool rns_link_db_link_snapshot_by_id( const uint8_t link_id[RNS_LINK_ID_LEN], rns_link_db_link_t *out ){
    int32_t index;
    bool found = false;

    if( out == NULL || link_id == NULL ){
        return false;
    }

    rns_link_db_lock();
    index = rns_link_db_find_index_by_id(link_id);
    if( index >= 0 && g_link_db.links[index] != NULL ){
        *out = *g_link_db.links[index];
        found = true;
    }
    rns_link_db_unlock();

    return found;
}

static struct os_task g_link_db_sweep_task;

static void link_db_sweep_task( void *arg ){
    (void)arg;

    while( 1 ){
        rns_link_db_sweep_expired();
        os_sleep(LINK_DB_SWEEP_PERIOD_S);
    }
}

void rns_link_db_init( void ){
    int32_t res;

    res = os_mutex_init(&g_link_db_mutex);
    if( res != 0 ){
        log_error("link db os_mutex_init failed rc=%ld", (long)res);
        return;
    }
    os_mutex_unlock(&g_link_db_mutex);

    os_task_init((const uint8 *)"lnksweep", &g_link_db_sweep_task, link_db_sweep_task, 0);
    os_task_set_stacksize(&g_link_db_sweep_task, LINK_DB_SWEEP_TASK_STACK);
    os_task_set_priority(&g_link_db_sweep_task, LINK_DB_SWEEP_TASK_PRIO);
    os_task_run(&g_link_db_sweep_task);

    log_info("link db init ok");
}
