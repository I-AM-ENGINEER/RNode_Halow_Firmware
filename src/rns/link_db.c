#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "rns/link_db.h"

static link_db_t g_link_db = {
    .buckets = {
        [0 ...(RNS_DB_HASH_SIZE - 1)] = RNS_DB_INDEX_NONE
    }
};

int32_t link_db_timestamp_s( void ){
    return (int32_t)time(NULL);
}

static uint16_t link_db_hash_id( const uint8_t id[RNS_LINK_ID_LEN] ){
    uint32_t hash = 2166136261u;
    uint32_t i;

    for( i = 0; i < RNS_LINK_ID_LEN; ++i ){
        hash ^= id[i];
        hash *= 16777619u;
    }

    return (uint16_t)(hash % RNS_DB_HASH_SIZE);
}

static int32_t link_db_find_index_by_id( const uint8_t id[RNS_LINK_ID_LEN] ){
    uint16_t bucket_idx;
    uint8_t index;

    bucket_idx = link_db_hash_id(id);
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

static int32_t link_db_find_free_slot( void ){
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

static void link_db_remove_index( uint8_t index ){
    link_db_link_t *link;
    uint16_t bucket_idx;
    uint8_t cur;

    link = g_link_db.links[index];

    if( link == NULL ){
        return;
    }

    bucket_idx = link_db_hash_id(link->id);
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

int32_t link_db_register_pkg( const rns_link_packet_info_t *pkg, rns_packet_direction_t direction ){
    link_db_link_t *link;
    int32_t index;
    int32_t slot;
    int32_t now_s;
    uint16_t bucket_idx;

    if( pkg == NULL ){
        return RNS_RET_NULLPTR;
    }

    now_s = link_db_timestamp_s();
    index = link_db_find_index_by_id(pkg->link_id);

    if( pkg->context == RNS_CONTEXT_LINKCLOSE ){
        if( index >= 0 ){
            link_db_remove_index((uint8_t)index);
        }

        return RNS_RET_OK;
    }

    if( index >= 0 ){
        link = g_link_db.links[index];

        if( link == NULL ){
            return RNS_RET_NO_SLOT;
        }
    }else{
        slot = link_db_find_free_slot();
        if( slot < 0 ){
            return RNS_RET_NO_SLOT;
        }

        link = malloc(sizeof(link_db_link_t));
        if( link == NULL ){
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

        bucket_idx = link_db_hash_id(link->id);
        link->hash_next = g_link_db.buckets[bucket_idx];
        g_link_db.links[slot] = link;
        g_link_db.buckets[bucket_idx] = (uint8_t)slot;
        g_link_db.links_count++;
    }

    link->hops = pkg->hops;
    memcpy(link->destination, pkg->destination, RNS_TRUNCATED_HASH_LEN);

    if( direction == RNS_PACKET_DIRECTION_RX ){
        link->lastrx_timestamp_s = now_s;
        link->rx_packets++;
        link->rx_bytes += pkg->payload_len;
    }else{
        link->lasttx_timestamp_s = now_s;
        link->tx_packets++;
        link->tx_bytes += pkg->payload_len;
    }

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

    return RNS_RET_OK;
}

const link_db_link_t* link_db_get_link( const uint8_t id[RNS_LINK_ID_LEN] ){
    int32_t index;

    if( id == NULL ){
        return NULL;
    }

    index = link_db_find_index_by_id(id);
    if( index < 0 ){
        return NULL;
    }

    return g_link_db.links[index];
}

uint8_t link_db_get_links_count( void ){
    return g_link_db.links_count;
}

link_db_link_t* link_db_get_link_by_index( uint32_t index ){
    uint32_t i;
    uint32_t pos = 0;

    for( i = 0; i < RNS_DB_MAX_LINK_COUNT; i++ ){
        if( g_link_db.links[i] == NULL ){
            continue;
        }

        if( pos == index ){
            return g_link_db.links[i];
        }

        pos++;
    }

    return NULL;
}
