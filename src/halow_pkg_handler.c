#include "sys_config.h"
#define LOG_LOCAL_LEVEL LOG_LEVEL_HALOW_PKG_HANDLER
#include "basic_include.h"
#include "lib/logc/log.h"
#include "halow_pkg_handler.h"
#include "halow_ack.h"
#include "rns/link_db.h"
#include "rns/link_parser.h"
#include "rns/link_utils.h"
#include "rns/stream_parser.h"
#include "utils.h"
#include "halow.h"
#include "configdb.h"
#include "tcp_server.h"

#define RNS_MTU_LIMIT_KEY   CONFIGDB_ADD_MODULE("rns") ".mtu"
#define RNS_MTU_LIMIT_DEF   (500U)

volatile uint32_t g_dbg_rns_rx_calls;
volatile uint32_t g_dbg_rns_rx_parse_fail;
volatile uint32_t g_dbg_rns_rx_valid;
volatile uint32_t g_dbg_rns_rx_reg_ok;
volatile uint32_t g_dbg_rns_rx_reg_fail;

#define HALOW_ACK_CFG_PREFIX   CONFIGDB_ADD_MODULE("hack")
#define HALOW_ACK_CFG(k)       HALOW_ACK_CFG_PREFIX "." k

#define HALOW_ACK_MAX_PEERS    4u
#define HALOW_ACK_SLOTS        HALOW_ACK_MAX_PEERS
#define HALOW_ACK_FRAME_MAX    2000u
#define HALOW_ACK_DEDUP_WIN    4u
#define HALOW_ACK_TICK_MS      10u

#define HALOW_ACK_RA_MAX_MCS     7u
#define HALOW_ACK_RA_EWMA_WEIGHT 8u
#define HALOW_ACK_RA_Q8(pct)     ((uint16_t)((uint32_t)(pct) * 256u / 100u))

typedef struct {
    uint8_t  in_use;
    uint8_t  retries_used;
    uint64_t tx_jiff;
    uint16_t frame_len;
    uint8_t  dest_mac[6];
    uint8_t  frame[HALOW_ACK_FRAME_MAX];
} halow_ack_slot_t;

typedef struct {
    uint8_t  in_use;
    uint8_t  mac[6];
    uint8_t  cur_retries;
    uint8_t  tx_mcs;            /* 0xFF = global default */
    int8_t   evm_ewma;
    uint16_t loss_ewma_q8;      /* /256 == 0..1 */
    uint32_t tx;
    uint32_t acked;
    uint32_t dropped;
    uint64_t last_ack_jiff;
    uint64_t cooldown_until;
    uint64_t last_seen;
    uint32_t dedup[HALOW_ACK_DEDUP_WIN];
    uint8_t  dedup_idx;
} halow_ack_peer_t;

static halow_ack_config_t g_ack_cfg;
static halow_ack_slot_t   g_ack_slots[HALOW_ACK_SLOTS];
static halow_ack_peer_t   g_ack_peers[HALOW_ACK_MAX_PEERS];
static halow_ack_stats_t  g_ack_stats;
static struct os_work     g_ack_tick_wk;
static struct os_mutex    g_ack_mutex;

static void halow_ack_lock(void)   { (void)os_mutex_lock(&g_ack_mutex, -1); }
static void halow_ack_unlock(void) { os_mutex_unlock(&g_ack_mutex); }

static uint8_t halow_ack_default_mcs( void ){
    halow_config_t hcfg;
    halow_config_load(&hcfg);
    return hcfg.mcs;
}

static void halow_ack_log_mcs( const char *verb, halow_ack_peer_t *p ){
    uint32_t pct_x100 = (uint32_t)p->loss_ewma_q8 * 100u * 100u / 256u;
    (void)pct_x100;
    log_info("ack: peer %02x:%02x:%02x:%02x:%02x:%02x MCS %s -> %u (loss=%u.%02u%%)",
             p->mac[0],p->mac[1],p->mac[2],p->mac[3],p->mac[4],p->mac[5],
             verb, (unsigned)p->tx_mcs,
             (unsigned)(pct_x100 / 100u), (unsigned)(pct_x100 % 100u));
}

static void halow_ack_ra_on_ack( halow_ack_peer_t *p ){
    p->last_ack_jiff = os_jiffies();
    p->loss_ewma_q8 = (uint16_t)(((uint32_t)p->loss_ewma_q8 * (HALOW_ACK_RA_EWMA_WEIGHT - 1u)) >> 3);
    if( !g_ack_cfg.rate_adapt ) return;
    if( p->tx_mcs == HALOW_MCS_DEFAULT ) return;
    if( os_jiffies() < p->cooldown_until ) return;
    if( p->loss_ewma_q8 <= HALOW_ACK_RA_Q8(g_ack_cfg.ra_loss_up) &&
        p->tx_mcs < HALOW_ACK_RA_MAX_MCS ){
        p->tx_mcs++;
        halow_ack_log_mcs("up", p);
    }
}

static void halow_ack_ra_on_drop( halow_ack_peer_t *p ){
    p->loss_ewma_q8 = (uint16_t)((((uint32_t)p->loss_ewma_q8 * (HALOW_ACK_RA_EWMA_WEIGHT - 1u)) >> 3)
                                 + (256u / HALOW_ACK_RA_EWMA_WEIGHT));
    if( !g_ack_cfg.rate_adapt ) return;
    if( p->tx_mcs == HALOW_MCS_DEFAULT ) return;
    if( p->loss_ewma_q8 >= HALOW_ACK_RA_Q8(g_ack_cfg.ra_loss_down) && p->tx_mcs > 0u ){
        p->tx_mcs--;
        halow_ack_log_mcs("down", p);
    }
}

static void halow_ack_ra_check_stale( halow_ack_peer_t *p, uint8_t dflt_mcs ){
    if( !g_ack_cfg.rate_adapt ) return;
    if( p->tx_mcs == HALOW_MCS_DEFAULT ) return;
    if( p->last_ack_jiff == 0u ) return;
    if( (os_jiffies() - p->last_ack_jiff) <= os_msecs_to_jiffies(HALOW_ACK_RA_STALE_MS) ) return;
    p->tx_mcs         = dflt_mcs;
    p->loss_ewma_q8   = 0;
    p->cooldown_until = os_jiffies() + os_msecs_to_jiffies(HALOW_ACK_RA_COOLDOWN_MS);
    log_info("ack: peer %02x:%02x:%02x:%02x:%02x:%02x MCS stale -> default %u",
             p->mac[0],p->mac[1],p->mac[2],p->mac[3],p->mac[4],p->mac[5],
             (unsigned)dflt_mcs);
}

static uint32_t halow_ack_fnv1a( const uint8_t *p, uint16_t len ){
    uint32_t h = 2166136261u;
    while( len-- ){
        h ^= (uint32_t)(*p++);
        h *= 16777619u;
    }
    return h;
}

bool halow_ack_is_ack_frame( const uint8_t *data, uint16_t len ){
    return (data != NULL &&
            len >= HALOW_ACK_ACK_LEN &&
            data[0] == HALOW_ACK_MAGIC0 &&
            data[1] == HALOW_ACK_MAGIC1);
}

void halow_ack_config_set_default( halow_ack_config_t *cfg ){
    if( cfg == NULL ) return;
    cfg->max_retries   = HALOW_ACK_DEFAULT_MAX_RETRIES;
    cfg->timeout_ms    = HALOW_ACK_DEFAULT_TIMEOUT_MS;
    cfg->rate_adapt    = HALOW_ACK_DEFAULT_RATE_ADAPT;
    cfg->ra_loss_up    = HALOW_ACK_DEFAULT_RA_LOSS_UP;
    cfg->ra_loss_down  = HALOW_ACK_DEFAULT_RA_LOSS_DOWN;
}

static void halow_ack_config_clamp( halow_ack_config_t *cfg ){
    if( cfg->max_retries > 8u )    cfg->max_retries = 8u;
    if( cfg->timeout_ms < 5u )     cfg->timeout_ms = 5u;
    if( cfg->ra_loss_up   > 100u ) cfg->ra_loss_up   = HALOW_ACK_DEFAULT_RA_LOSS_UP;
    if( cfg->ra_loss_down > 100u ) cfg->ra_loss_down = HALOW_ACK_DEFAULT_RA_LOSS_DOWN;
    if( cfg->ra_loss_up >= cfg->ra_loss_down ){
        cfg->ra_loss_up   = HALOW_ACK_DEFAULT_RA_LOSS_UP;
        cfg->ra_loss_down = HALOW_ACK_DEFAULT_RA_LOSS_DOWN;
    }
    if( cfg->max_retries == 0u )   cfg->rate_adapt = 0u;
}

void halow_ack_config_load( halow_ack_config_t *cfg ){
    if( cfg == NULL ) return;
    halow_ack_config_set_default(cfg);
    configdb_get_i8 (HALOW_ACK_CFG("retry"),  (int8_t *)&cfg->max_retries);
    configdb_get_i16(HALOW_ACK_CFG("tmo"),    (int16_t *)&cfg->timeout_ms);
    configdb_get_i8 (HALOW_ACK_CFG("ra"),     (int8_t *)&cfg->rate_adapt);
    configdb_get_i8 (HALOW_ACK_CFG("rlup"),   (int8_t *)&cfg->ra_loss_up);
    configdb_get_i8 (HALOW_ACK_CFG("rldn"),   (int8_t *)&cfg->ra_loss_down);
    halow_ack_config_clamp(cfg);
}

void halow_ack_config_save( const halow_ack_config_t *cfg ){
    if( cfg == NULL ) return;
    configdb_set_i8 (HALOW_ACK_CFG("retry"),  (int8_t *)&cfg->max_retries);
    configdb_set_i16(HALOW_ACK_CFG("tmo"),    (int16_t *)&cfg->timeout_ms);
    configdb_set_i8 (HALOW_ACK_CFG("ra"),     (int8_t *)&cfg->rate_adapt);
    configdb_set_i8 (HALOW_ACK_CFG("rlup"),   (int8_t *)&cfg->ra_loss_up);
    configdb_set_i8 (HALOW_ACK_CFG("rldn"),   (int8_t *)&cfg->ra_loss_down);
}

void halow_ack_config_get_live( halow_ack_config_t *cfg ){
    if( cfg == NULL ) return;
    halow_ack_lock();
    *cfg = g_ack_cfg;
    halow_ack_unlock();
}

void halow_ack_config_apply( const halow_ack_config_t *cfg ){
    if( cfg == NULL ) return;
    halow_ack_config_t c = *cfg;
    halow_ack_config_clamp(&c);

    uint8_t dflt = halow_ack_default_mcs();
    uint64_t cooldown_until = os_jiffies() + os_msecs_to_jiffies(HALOW_ACK_RA_COOLDOWN_MS);

    halow_ack_lock();
    g_ack_cfg = c;
    for( uint32_t i = 0; i < HALOW_ACK_MAX_PEERS; i++ ){
        halow_ack_peer_t *p = &g_ack_peers[i];
        if( !p->in_use ) continue;
        if( p->cur_retries > c.max_retries ) p->cur_retries = c.max_retries;
        if( !c.rate_adapt ){
            p->tx_mcs = HALOW_MCS_DEFAULT;
            p->loss_ewma_q8 = 0;
        }else if( p->tx_mcs == HALOW_MCS_DEFAULT ){
            p->tx_mcs = dflt;
            p->loss_ewma_q8 = 0;
            p->cooldown_until = cooldown_until;
        }
    }
    halow_ack_unlock();
    halow_ack_config_save(&c);
    log_info("ack: apply retries=%u tmo=%ums ra=%u up=%u%% down=%u%%",
             (unsigned)c.max_retries, (unsigned)c.timeout_ms, (unsigned)c.rate_adapt,
             (unsigned)c.ra_loss_up, (unsigned)c.ra_loss_down);
}

static halow_ack_peer_t *halow_ack_peer_find( const uint8_t mac[6] ){
    for( uint32_t i = 0; i < HALOW_ACK_MAX_PEERS; i++ )
        if( g_ack_peers[i].in_use && memcmp(g_ack_peers[i].mac, mac, 6) == 0 )
            return &g_ack_peers[i];
    return NULL;
}

static halow_ack_slot_t *halow_ack_slot_for_peer( const uint8_t mac[6] ){
    for( uint32_t i = 0; i < HALOW_ACK_SLOTS; i++ )
        if( g_ack_slots[i].in_use && memcmp(g_ack_slots[i].dest_mac, mac, 6) == 0 )
            return &g_ack_slots[i];
    return NULL;
}

static halow_ack_peer_t *halow_ack_peer_get( const uint8_t mac[6] ){
    uint8_t init_mcs = g_ack_cfg.rate_adapt ? halow_ack_default_mcs() : HALOW_MCS_DEFAULT;
    halow_ack_peer_t *p = halow_ack_peer_find(mac);
    if( p != NULL ){
        if( g_ack_cfg.rate_adapt &&
            p->tx_mcs != HALOW_MCS_DEFAULT &&
            p->last_ack_jiff != 0u &&
            (os_jiffies() - p->last_ack_jiff) > os_msecs_to_jiffies(HALOW_ACK_RA_STALE_MS) ){
            p->tx_mcs         = init_mcs;
            p->loss_ewma_q8   = 0;
            p->cooldown_until = os_jiffies() + os_msecs_to_jiffies(HALOW_ACK_RA_COOLDOWN_MS);
            log_info("ack: peer %02x:%02x:%02x:%02x:%02x:%02x re-heard after stale -> MCS %u",
                     p->mac[0],p->mac[1],p->mac[2],p->mac[3],p->mac[4],p->mac[5],
                     (unsigned)init_mcs);
        }
        p->last_seen = os_jiffies();
        return p;
    }
    halow_ack_peer_t *victim = NULL;
    uint64_t oldest = (uint64_t)-1;
    for( uint32_t i = 0; i < HALOW_ACK_MAX_PEERS; i++ ){
        halow_ack_peer_t *c = &g_ack_peers[i];
        if( !c->in_use ){ victim = c; break; }
        if( halow_ack_slot_for_peer(c->mac) != NULL ) continue;
        if( c->last_seen < oldest ){ oldest = c->last_seen; victim = c; }
    }
    if( victim == NULL ) return NULL;

    memset(victim, 0, sizeof(*victim));
    victim->in_use      = 1;
    memcpy(victim->mac, mac, 6);
    victim->cur_retries = g_ack_cfg.max_retries;
    victim->tx_mcs      = init_mcs;
    if( g_ack_cfg.rate_adapt )
        victim->cooldown_until = os_jiffies() + os_msecs_to_jiffies(HALOW_ACK_RA_COOLDOWN_MS);
    victim->last_seen   = os_jiffies();
    return victim;
}

static bool halow_ack_peer_dedup_seen( halow_ack_peer_t *p, uint32_t hash ){
    for( uint32_t i = 0; i < HALOW_ACK_DEDUP_WIN; i++ )
        if( p->dedup[i] == hash ) return true;
    return false;
}

static void halow_ack_peer_dedup_remember( halow_ack_peer_t *p, uint32_t hash ){
    p->dedup[p->dedup_idx] = hash;
    p->dedup_idx = (uint8_t)((p->dedup_idx + 1u) % HALOW_ACK_DEDUP_WIN);
}

static halow_ack_slot_t *halow_ack_slot_alloc( void ){
    for( uint32_t i = 0; i < HALOW_ACK_SLOTS; i++ )
        if( !g_ack_slots[i].in_use ) return &g_ack_slots[i];
    return NULL;
}

static void halow_ack_send_ack( int8_t evm, const uint8_t dest_mac[6] ){
    uint8_t a[HALOW_ACK_ACK_LEN] = { HALOW_ACK_MAGIC0, HALOW_ACK_MAGIC1, (uint8_t)evm };
    g_ack_stats.acks_sent++;
    (void)halow_tx(a, HALOW_ACK_ACK_LEN, dest_mac, HALOW_ACK_ACK_MCS);
}

int32_t halow_ack_tx( const uint8_t *payload, uint16_t len, const uint8_t dest_mac[6] ){
    if( payload == NULL || dest_mac == NULL ) return -1;
    g_ack_stats.tx_frames++;

    if( g_ack_cfg.max_retries == 0u ||
        memcmp(dest_mac, mac_broadcast, 6) == 0 ||
        (uint32_t)len > HALOW_ACK_FRAME_MAX ){
        return halow_tx(payload, len, dest_mac, HALOW_MCS_DEFAULT);
    }

    halow_ack_lock();
    halow_ack_peer_t *p = halow_ack_peer_get(dest_mac);
    if( p == NULL ){
        halow_ack_unlock();
        return halow_tx(payload, len, dest_mac, HALOW_MCS_DEFAULT);
    }
    uint8_t pmcs = p->tx_mcs;
    if( p->cur_retries == 0u || halow_ack_slot_for_peer(dest_mac) != NULL ){
        halow_ack_unlock();
        return halow_tx(payload, len, dest_mac, pmcs);
    }
    halow_ack_slot_t *s = halow_ack_slot_alloc();
    if( s == NULL ){
        halow_ack_unlock();
        return halow_tx(payload, len, dest_mac, pmcs);
    }

    s->in_use       = 1;
    s->retries_used = 0;
    s->tx_jiff      = os_jiffies();
    s->frame_len    = len;
    memcpy(s->dest_mac, dest_mac, 6);
    memcpy(s->frame, payload, len);
    p->tx++;
    halow_ack_unlock();

    return halow_tx(payload, len, dest_mac, pmcs);
}

bool halow_ack_on_rx( const uint8_t *payload, uint16_t len, const uint8_t src_mac[6],
                      int8_t evm,
                      const uint8_t **out_payload, uint16_t *out_len ){
    if( payload == NULL || out_payload == NULL || out_len == NULL ){
        if( out_payload ) *out_payload = payload;
        if( out_len )     *out_len     = len;
        return true;
    }

    if( halow_ack_is_ack_frame(payload, len) ){
        int8_t ack_evm = (int8_t)payload[2];
        g_ack_stats.last_evm = ack_evm;

        halow_ack_lock();
        halow_ack_peer_t *p = halow_ack_peer_find(src_mac);
        if( p != NULL ){
            p->cur_retries = g_ack_cfg.max_retries;
            p->evm_ewma = (int8_t)(((int16_t)p->evm_ewma * 7 + (int16_t)ack_evm) / 8);
            halow_ack_ra_on_ack(p);
        }
        halow_ack_slot_t *s = halow_ack_slot_for_peer(src_mac);
        if( s != NULL ){
            s->in_use = 0;
            g_ack_stats.acked++;
            if( p != NULL ) p->acked++;
        }else{
            g_ack_stats.acks_rx_dup++;
        }
        halow_ack_unlock();
        return false;
    }

    uint32_t hash = halow_ack_fnv1a(payload, len);
    halow_ack_lock();
    halow_ack_peer_t *p = halow_ack_peer_get(src_mac);
    bool deliver = true;
    if( p != NULL ){
        deliver = !halow_ack_peer_dedup_seen(p, hash);
        if( deliver ) halow_ack_peer_dedup_remember(p, hash);
    }
    halow_ack_unlock();

    halow_ack_send_ack(evm, src_mac);

    if( deliver ){
        *out_payload = payload;
        *out_len     = len;
        return true;
    }
    return false;
}

void halow_ack_tick( void ){
    if( g_ack_cfg.max_retries == 0u ) return;
    uint64_t now = os_jiffies();
    uint64_t timeout_j = os_msecs_to_jiffies(g_ack_cfg.timeout_ms);
    if( timeout_j == 0u ) timeout_j = 1u;

    halow_ack_lock();
    uint8_t dflt_mcs = halow_ack_default_mcs();
    for( uint32_t i = 0; i < HALOW_ACK_SLOTS; i++ ){
        halow_ack_slot_t *s = &g_ack_slots[i];
        if( !s->in_use ) continue;
        if( (now - s->tx_jiff) < timeout_j ) continue;

        halow_ack_peer_t *p = halow_ack_peer_find(s->dest_mac);
        if( p == NULL || p->cur_retries == 0u ){
            s->in_use = 0;
            continue;
        }
        if( s->retries_used < p->cur_retries ){
            s->retries_used++;
            s->tx_jiff = now;
            g_ack_stats.retransmitted++;
            uint8_t pmcs = p->tx_mcs;
            halow_ack_unlock();
            (void)halow_tx(s->frame, s->frame_len, s->dest_mac, pmcs);
            halow_ack_lock();
        }else{
            s->in_use = 0;
            g_ack_stats.dropped++;
            p->dropped++;
            halow_ack_ra_on_drop(p);
            if( p->cur_retries > 0u ){
                p->cur_retries--;
                if( p->cur_retries == 0u ){
                    g_ack_stats.noack_hits++;
                    log_warn("ack: peer %02x:%02x:%02x:%02x:%02x:%02x slid to NOACK",
                             p->mac[0],p->mac[1],p->mac[2],p->mac[3],p->mac[4],p->mac[5]);
                }
            }
        }
    }
    for( uint32_t i = 0; i < HALOW_ACK_MAX_PEERS; i++ ){
        if( g_ack_peers[i].in_use ) halow_ack_ra_check_stale(&g_ack_peers[i], dflt_mcs);
    }
    halow_ack_unlock();
}

static int32_t halow_ack_tick_work( struct os_work *work ){
    (void)work;
    halow_ack_tick();
    os_run_work_delay(&g_ack_tick_wk, HALOW_ACK_TICK_MS);
    return 0;
}

void halow_ack_init( void ){
    halow_ack_config_load(&g_ack_cfg);
    memset(g_ack_slots, 0, sizeof(g_ack_slots));
    memset(g_ack_peers, 0, sizeof(g_ack_peers));
    memset(&g_ack_stats, 0, sizeof(g_ack_stats));

    (void)os_mutex_init(&g_ack_mutex);
    os_mutex_unlock(&g_ack_mutex);

    OS_WORK_INIT(&g_ack_tick_wk, halow_ack_tick_work, 0);
    os_run_work_delay(&g_ack_tick_wk, HALOW_ACK_TICK_MS);

    log_info("ack: init retries=%u tmo=%ums",
             (unsigned)g_ack_cfg.max_retries, (unsigned)g_ack_cfg.timeout_ms);
}

void halow_ack_stats_get( halow_ack_stats_t *out ){
    if( out == NULL ) return;
    halow_ack_lock();
    *out = g_ack_stats;
    uint32_t n = 0, peers = 0;
    for( uint32_t i = 0; i < HALOW_ACK_SLOTS; i++ )     if( g_ack_slots[i].in_use ) n++;
    for( uint32_t i = 0; i < HALOW_ACK_MAX_PEERS; i++ )  if( g_ack_peers[i].in_use ) peers++;
    out->outstanding = (uint8_t)n;
    out->peers       = (uint8_t)peers;
    halow_ack_unlock();
}

bool halow_ack_peer_stats_by_mac( const uint8_t mac[6], halow_ack_peer_stats_t *out ){
    if( out == NULL ) return false;
    memset(out, 0, sizeof(*out));
    out->tx_mcs = HALOW_MCS_DEFAULT;
    if( mac == NULL ) return false;
    halow_ack_lock();
    halow_ack_peer_t *p = halow_ack_peer_find(mac);
    bool found = (p != NULL);
    if( p != NULL ){
        out->tx_mcs      = p->tx_mcs;
        out->cur_retries = p->cur_retries;
        out->tx_frames   = p->tx;
        out->acked       = p->acked;
        out->dropped     = p->dropped;
        out->evm         = p->evm_ewma;
        out->loss_pct    = (uint8_t)((uint32_t)p->loss_ewma_q8 * 100u / 256u);
    }
    halow_ack_unlock();
    return found;
}

static bool halow_peer_mac_known( const uint8_t mac[6] ){
    for( uint32_t i = 0; i < 6; i++ )
        if( mac[i] != RNS_LINK_MAC_UNKNOWN_BYTE ) return true;
    return false;
}

void halow_pkg_handler_rf_to_tcp( uint8_t* pkg, uint16_t len, const uint8_t *src_mac, int8_t evm ){
    int32_t res;
    rns_link_packet_info_t packet_info;
    uint8_t *allocated_rx = NULL;
    uint32_t allocated_len = 0u;
    const uint8_t *inner;
    uint16_t inner_len;

    if( !halow_ack_on_rx(pkg, len, src_mac, evm, &inner, &inner_len) ) return;
    pkg = (uint8_t *)inner;
    len = inner_len;

    g_dbg_rns_rx_calls++;
    res = rns_link_parser_parse(pkg, len, &packet_info);
    if( res != RNS_RET_OK ){
        g_dbg_rns_rx_parse_fail++;
        log_warn("rx rns package parse error=%d len=%u", (int)res, (unsigned int)len);
        return;
    }

    if( packet_info.valid ){
        int32_t rr;
        uint32_t rx_mtu = 0;
        bool have_mtu = (packet_info.packet_type == RNS_PACKET_TYPE_LINKREQUEST &&
                         rns_link_utils_get_mtu(pkg, len, &packet_info, &rx_mtu) == RNS_RET_OK);

        g_dbg_rns_rx_valid++;
        rr = rns_link_db_package_register(&packet_info, RNS_PACKET_DIRECTION_RX,
                                          src_mac, rx_mtu, have_mtu);
        if( rr == RNS_RET_OK ){
            g_dbg_rns_rx_reg_ok++;
        }else{
            g_dbg_rns_rx_reg_fail++;
        }
    }

    res = rns_stream_encode_alloc(pkg, len, &allocated_rx, &allocated_len);
    if( res != 0 || allocated_rx == NULL || allocated_len == 0u ){
        log_warn(
            "rx rns tcp encoding fail res=%d in_len=%u out=%p out_len=%u",
            (int)res,
            (unsigned int)len,
            allocated_rx,
            (unsigned int)allocated_len
        );
        return;
    }

    log_trace(
        "rf->tcp encoded in_len=%u out_len=%u",
        (unsigned int)len,
        (unsigned int)allocated_len,
        allocated_rx
    );

    res = tcp_server_send(allocated_rx, allocated_len);
    if( res != 0 ){
        log_warn("rf->tcp ring full res=%d, drop len=%u", (int)res, (unsigned int)allocated_len);
    }
    free(allocated_rx);
}

void halow_pkg_handler_tcp_to_rf( uint8_t* pkg, uint16_t len ){
    int32_t res;
    rns_link_packet_info_t packet_info;

    res = rns_link_parser_parse(pkg, len, &packet_info);
    if(res != RNS_RET_OK){
        log_warn("tx rns package parse error=%d", res);
        return;
    }

    log_trace("receive pkg type=%d", (int)packet_info.packet_type);

    if( packet_info.valid && packet_info.packet_type == RNS_PACKET_TYPE_LINKREQUEST ){
        uint32_t original_mtu = 0;
        uint32_t hw_mtu;
        uint32_t mtu_limit;
        uint32_t stored_mtu;
        halow_config_t cfg;
        int16_t rns_mtu_limit;

        halow_config_load(&cfg);
        hw_mtu = halow_get_mtu(cfg.mcs);
        rns_mtu_limit = rns_mtu_limit_get();

        if ((uint32_t)rns_mtu_limit < hw_mtu) {
            mtu_limit = (uint32_t)rns_mtu_limit;
        } else {
            mtu_limit = hw_mtu;
        }

        rns_link_utils_clamp_mtu(pkg, len, &packet_info, mtu_limit, &original_mtu);
        log_info("cap link MTU from %db to %db", (int)original_mtu, (int)mtu_limit);

        stored_mtu = (original_mtu <= mtu_limit) ? original_mtu : mtu_limit;

        rns_link_db_package_register(&packet_info, RNS_PACKET_DIRECTION_TX,
                                     NULL, stored_mtu, true);
    }else if( packet_info.valid ){
        rns_link_db_package_register(&packet_info, RNS_PACKET_DIRECTION_TX,
                                     NULL, 0, false);
    }

    rns_link_db_link_t link;
    const uint8_t *dest;
    dest = (packet_info.valid &&
            rns_link_db_link_snapshot_by_id(packet_info.link_id, &link) &&
            halow_peer_mac_known(link.remote_mac))
           ? link.remote_mac : mac_broadcast;

    (void)halow_ack_tx(pkg, len, dest);
}

void halow_pkg_handler_init( void ){
    rns_link_db_init();
    halow_ack_init();
}

int16_t rns_mtu_limit_get( void ){
    int16_t val = RNS_MTU_LIMIT_DEF;
    configdb_get_i16(RNS_MTU_LIMIT_KEY, &val);
    return val;
}

void rns_mtu_limit_set( int16_t mtu ){
    configdb_set_i16(RNS_MTU_LIMIT_KEY, &mtu);
}
