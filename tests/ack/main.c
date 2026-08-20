#include "sys_config.h"
#define LOG_LOCAL_LEVEL LOG_LEVEL_HALOW_PKG_HANDLER
#include "basic_include.h"
#include "lib/logc/log.h"
#include "halow.h"
#include "utils.h"
#include "halow_ack.h"
#include "harness.h"

#include <stdio.h>
#include <string.h>

static int g_pass, g_fail;

#define CHECK(cond) do{ \
    if( cond ){ g_pass++; } \
    else{ g_fail++; printf("    FAIL %s:%d: %s\n", __func__, __LINE__, #cond); } \
}while(0)

static const uint8_t MAC_ME[6]  = {0x00,0x00,0x00,0x00,0x00,0x01};
static const uint8_t PEER_A[6]  = {0x11,0x11,0x11,0x11,0x11,0x11};
static const uint8_t PEER_B[6]  = {0x22,0x22,0x22,0x22,0x22,0x22};
static const uint8_t PEER_C[6]  = {0x33,0x33,0x33,0x33,0x33,0x33};
static const uint8_t PEER_D[6]  = {0x44,0x44,0x44,0x44,0x44,0x44};
static const uint8_t PEER_E[6]  = {0x55,0x55,0x55,0x55,0x55,0x55};
static const uint8_t PEER_R[6]  = {0x66,0x66,0x66,0x66,0x66,0x66};
static const uint8_t PEER_LO[6] = {0x77,0x77,0x77,0x77,0x77,0x77};
static const uint8_t PEER_HI[6] = {0x88,0x88,0x88,0x88,0x88,0x88};

#define EVM_M10 ((int8_t)(-10))
#define EVM_M25 ((int8_t)(-25))
#define EVM_M30 ((int8_t)(-30))

static uint32_t fnv1a( const uint8_t *p, uint16_t len ){
    uint32_t h = 2166136261u;
    while( len-- ){
        h ^= (uint32_t)(*p++);
        h *= 16777619u;
    }
    return h;
}

static void cfg_base( halow_ack_config_t *c ){
    halow_ack_config_set_default(c);
    c->timeout_ms   = 50;
    c->max_retries  = 2;
    c->agg_hold_ms  = 2;
    c->ack_hold_ms  = 0;
    c->rate_adapt   = 0;
    c->window       = 8;
    c->data_gap_ms  = 0;
    c->bc_repeat    = 1;
}

static void node_start( const halow_ack_config_t *cfg ){
    test_time_reset();
    configdb_reset();
    test_tx_reset();
    test_vacancy_set(100000);
    halow_ack_init();
    if( cfg != NULL ) halow_ack_config_apply(cfg);
}

static void run_ticks( int n, uint32_t step_ms ){
    for( int i = 0; i < n; i++ ){
        test_advance_ms(step_ms);
        halow_ack_tick();
    }
}

static bool rx_frame( const uint8_t *src, const uint8_t *payload, uint16_t len, int8_t evm ){
    const uint8_t *out = NULL;
    uint16_t out_len = 0;
    bool delivered = halow_ack_on_rx(payload, len, src, MAC_ME, evm, &out, &out_len);
    CHECK( delivered == (out == payload && out_len == len) );
    return delivered;
}

static void rx_ack_frame( const uint8_t *src, const uint8_t *ack, uint16_t len ){
    const uint8_t *out = NULL;
    uint16_t out_len = 0;
    (void)halow_ack_on_rx(ack, len, src, MAC_ME, 0, &out, &out_len);
}

static uint16_t build_legacy_ack( uint8_t *buf, int8_t evm, uint16_t fid ){
    buf[0] = 0xA5; buf[1] = 0x5A; buf[2] = (uint8_t)evm;
    buf[3] = (uint8_t)(fid & 0xFF); buf[4] = (uint8_t)(fid >> 8);
    return 5;
}

static uint16_t build_env_ack( uint8_t *buf, int8_t evm, uint16_t base ){
    buf[0] = 0xA5; buf[1] = 0x5A; buf[2] = 0x11;
    buf[3] = (uint8_t)evm;
    buf[4] = (uint8_t)(base & 0xFF); buf[5] = (uint8_t)(base >> 8);
    memset(&buf[6], 0, 8);
    return 14;
}

static void env_ack_bit( uint8_t *buf, uint8_t bit ){
    buf[6 + bit / 8] |= (uint8_t)(1u << (bit % 8));
}

static int count_ack_frames( void ){
    int n = 0;
    for( int i = 0; i < test_tx_count(); i++ ){
        const test_tx_cap_t *t = test_tx_at(i);
        if( t->len >= 3 && t->buf[0] == 0xA5 && t->buf[1] == 0x5A &&
            t->buf[2] != 0x10 ) n++;
    }
    return n;
}

static int count_env_ack_frames( void ){
    int n = 0;
    for( int i = 0; i < test_tx_count(); i++ ){
        const test_tx_cap_t *t = test_tx_at(i);
        if( t->len == 14 && t->buf[0] == 0xA5 && t->buf[1] == 0x5A && t->buf[2] == 0x11 ) n++;
    }
    return n;
}

static void fill_payload( uint8_t *p, uint16_t len, uint8_t seed ){
    for( uint16_t i = 0; i < len; i++ ) p[i] = (uint8_t)(seed + i);
}

static void peer_mac( uint8_t *m, uint8_t id ){
    memset(m, id, 6);
}

typedef struct {
    uint16_t fid[32];
    uint8_t  mac[32][6];
    int      n;
} fid_ring_t;

static void fr_clear( fid_ring_t *r ){
    memset(r, 0, sizeof(*r));
}

static void fr_push( fid_ring_t *r, const uint8_t *mac, uint16_t fid ){
    memcpy(r->mac[r->n], mac, 6);
    r->fid[r->n] = fid;
    r->n = (r->n + 1) % 32;
}

static void fr_ack_all( const fid_ring_t *r ){
    uint8_t ack[5];
    for( int k = 0; k < 32; k++ ){
        if( r->fid[k] != 0u )
            rx_ack_frame(r->mac[k], ack, build_legacy_ack(ack, EVM_M10, r->fid[k]));
    }
}

static void ack_fid( const uint8_t *mac, uint16_t fid ){
    uint8_t ack[5];
    rx_ack_frame(mac, ack, build_legacy_ack(ack, EVM_M10, fid));
}

static uint16_t fid_of( const uint8_t *p, uint16_t len ){
    return (uint16_t)(fnv1a(p, len) & 0xFFFFu);
}

static void env_peer_ready( const uint8_t *mac ){
    uint8_t data[16];
    uint8_t env[12] = {0xA5, 0x5A, 0x10, 0x05, 0x00, 0x01, 0x04, 0x00, 'A', 'B', 'C', 'D'};
    fill_payload(data, sizeof(data), 1);
    CHECK( rx_frame(mac, data, sizeof(data), 0) );
    CHECK( rx_frame(mac, env, sizeof(env), 0) );
}

/* ============================== tests ============================== */

static void t_init_defaults( void ){
    halow_ack_config_t live;
    halow_ack_stats_t st;
    int16_t v = 0;

    node_start(NULL);

    halow_ack_stats_get(&st);
    CHECK( st.outstanding == 0 );
    CHECK( st.peers == 0 );
    CHECK( st.tx_frames == 0 && st.acked == 0 && st.dropped == 0 );

    halow_ack_config_get_live(&live);
    CHECK( live.max_retries == 3 );
    CHECK( live.timeout_ms == 100 );
    CHECK( live.window == 10 );
    CHECK( live.ack_fids == 16 );
    CHECK( live.agg == 1 );
    CHECK( live.env == 1 );
    CHECK( live.agg_bytes == 2048 );

    CHECK( test_kv_get("cfg.hack.ver", &v) == 0 && v == 3 );
    CHECK( test_kv_get("cfg.hack.retry", &v) == 0 && v == 3 );
    CHECK( test_task_inits() == 1 );
}

static void t_config_clamp( void ){
    halow_ack_config_t cfg, live;

    node_start(NULL);
    cfg_base(&cfg);
    cfg.timeout_ms  = 9999;
    cfg.max_retries = 99;
    cfg.window      = 99;
    cfg.ack_fids    = 99;
    cfg.agg_hold_ms = 999;
    cfg.ack_hold_ms = 999;
    cfg.bc_repeat   = 9;
    cfg.data_gap_ms = 999;
    cfg.ra_loss_up   = 50;
    cfg.ra_loss_down = 20;
    halow_ack_config_apply(&cfg);

    halow_ack_config_get_live(&live);
    CHECK( live.timeout_ms == 300 );
    CHECK( live.max_retries == 8 );
    CHECK( live.window == 16 );
    CHECK( live.ack_fids == 16 );
    CHECK( live.agg_hold_ms == 100 );
    CHECK( live.ack_hold_ms == 100 );
    CHECK( live.bc_repeat == 3 );
    CHECK( live.data_gap_ms == 250 );
    CHECK( live.ra_loss_up == 5 && live.ra_loss_down == 30 );
}

static void t_broadcast_noack( void ){
    halow_ack_config_t cfg;
    halow_ack_stats_t st;
    uint8_t pkt[100];
    int32_t r;

    cfg_base(&cfg);
    cfg.max_retries = 0;
    cfg.bc_repeat = 2;
    node_start(&cfg);

    fill_payload(pkt, sizeof(pkt), 1);
    r = halow_ack_tx(pkt, sizeof(pkt), mac_broadcast);
    CHECK( r == 0 );
    CHECK( test_tx_count() == 2 );
    CHECK( test_tx_at(0) != NULL && test_tx_at(0)->len == 100 );
    CHECK( test_tx_at(0) != NULL && memcmp(test_tx_at(0)->mac, mac_broadcast, 6) == 0 );
    CHECK( test_tx_at(0) != NULL && test_tx_at(0)->mcs == HALOW_MCS_DEFAULT );

    halow_ack_stats_get(&st);
    CHECK( st.tx_frames == 2 );
    CHECK( st.bc_repeats == 1 );
}

static void t_bundle_flush_fid_ack( void ){
    halow_ack_config_t cfg;
    halow_ack_stats_t st;
    halow_ack_peer_stats_t ps;
    uint8_t frame[300];
    uint8_t ack[5];
    uint16_t fid;
    int32_t r;

    cfg_base(&cfg);
    node_start(&cfg);

    fill_payload(frame, sizeof(frame), 7);
    r = halow_ack_tx(frame, sizeof(frame), PEER_A);
    CHECK( r == 0 );
    CHECK( test_tx_count() == 0 );

    halow_ack_stats_get(&st);
    CHECK( st.tx_frames == 1 );

    run_ticks(3, 5);
    CHECK( test_tx_count() == 1 );
    CHECK( test_tx_at(0)->len == 300 );
    CHECK( memcmp(test_tx_at(0)->buf, frame, 300) == 0 );
    CHECK( memcmp(test_tx_at(0)->mac, PEER_A, 6) == 0 );

    halow_ack_stats_get(&st);
    CHECK( st.outstanding == 1 );

    fid = (uint16_t)(fnv1a(test_tx_at(0)->buf, test_tx_at(0)->len) & 0xFFFF);
    rx_ack_frame(PEER_A, ack, build_legacy_ack(ack, EVM_M10, fid));

    halow_ack_stats_get(&st);
    CHECK( st.acked == 1 );
    CHECK( st.acks_rx_frames == 1 );
    CHECK( st.acks_rx_dup == 0 );
    CHECK( st.outstanding == 0 );

    CHECK( halow_ack_peer_stats_by_mac(PEER_A, &ps) );
    CHECK( ps.acked == 1 );
    CHECK( ps.tx_frames == 1 );
    CHECK( ps.dropped == 0 );
    CHECK( ps.compat == 1 );
}

static void t_retry_exhaust( void ){
    halow_ack_config_t cfg;
    halow_ack_stats_t st;
    halow_ack_peer_stats_t ps;
    uint8_t frame[200];

    cfg_base(&cfg);
    node_start(&cfg);

    fill_payload(frame, sizeof(frame), 3);
    CHECK( halow_ack_tx(frame, sizeof(frame), PEER_A) == 0 );
    run_ticks(3, 5);
    CHECK( test_tx_count() == 1 );

    run_ticks(40, 10);

    halow_ack_stats_get(&st);
    CHECK( test_tx_count() == 3 );
    CHECK( st.retransmitted == 2 );
    CHECK( st.dropped == 1 );
    CHECK( st.drop_exhaust == 1 );
    CHECK( st.outstanding == 0 );

    CHECK( halow_ack_peer_stats_by_mac(PEER_A, &ps) );
    CHECK( ps.dropped == 1 );
}

static void t_slot_lifetime_deadline( void ){
    halow_ack_config_t cfg;
    halow_ack_stats_t st;
    uint8_t frame[200];

    cfg_base(&cfg);
    cfg.max_retries = 8;
    cfg.timeout_ms = 5;
    node_start(&cfg);

    fill_payload(frame, sizeof(frame), 4);
    CHECK( halow_ack_tx(frame, sizeof(frame), PEER_A) == 0 );
    run_ticks(1, 5);
    CHECK( test_tx_count() == 1 );
    run_ticks(1, 5);
    CHECK( test_tx_count() == 2 );

    test_vacancy_set(100);
    run_ticks(80, 5);
    test_vacancy_set(100000);
    run_ticks(4, 5);

    halow_ack_stats_get(&st);
    CHECK( st.dropped == 1 );
    CHECK( st.drop_deadline == 1 );
    CHECK( st.drop_exhaust == 0 );
    CHECK( test_tx_count() == 2 );
    CHECK( st.outstanding == 0 );
}

static void t_rx_dedup( void ){
    halow_ack_config_t cfg;
    halow_ack_stats_t st;
    uint8_t frame[64];

    cfg_base(&cfg);
    node_start(&cfg);

    fill_payload(frame, sizeof(frame), 9);
    CHECK( rx_frame(PEER_B, frame, sizeof(frame), 0) );
    CHECK( !rx_frame(PEER_B, frame, sizeof(frame), 0) );

    frame[0] ^= 1;
    CHECK( rx_frame(PEER_B, frame, sizeof(frame), 0) );

    halow_ack_stats_get(&st);
    CHECK( st.acks_sent == 3 );
    CHECK( st.noack_hits == 0 );
}

static void t_cumulative_ack_coalesce( void ){
    halow_ack_config_t cfg;
    uint8_t f[32];

    cfg_base(&cfg);
    cfg.ack_hold_ms = 20;
    cfg.ack_fids = 4;
    node_start(&cfg);

    for( uint8_t i = 0; i < 3; i++ ){
        fill_payload(f, sizeof(f), i);
        CHECK( rx_frame(PEER_C, f, sizeof(f), EVM_M10) );
    }
    CHECK( count_ack_frames() == 0 );

    run_ticks(1, 30);
    CHECK( count_ack_frames() == 1 );
    {
        const test_tx_cap_t *a = test_tx_at(0);
        CHECK( a != NULL && a->len == 3 + 2 * 4 );
        CHECK( a->buf[0] == 0xA5 && a->buf[1] == 0x5A && a->buf[2] >= 0x80 );
        CHECK( a->buf[3] != 0 || a->buf[4] != 0 );
    }

    for( uint8_t i = 3; i < 7; i++ ){
        fill_payload(f, sizeof(f), i);
        CHECK( rx_frame(PEER_C, f, sizeof(f), EVM_M10) );
    }
    CHECK( count_ack_frames() == 2 );
}

static void t_env_compat_upgrade( void ){
    halow_ack_config_t cfg;
    halow_ack_stats_t st;
    halow_ack_peer_stats_t ps;
    uint8_t data[16];
    uint8_t env[12] = {0xA5, 0x5A, 0x10, 0x05, 0x00, 0x01, 0x04, 0x00, 'A', 'B', 'C', 'D'};

    cfg_base(&cfg);
    node_start(&cfg);

    fill_payload(data, sizeof(data), 1);
    CHECK( rx_frame(PEER_D, data, sizeof(data), 0) );
    CHECK( halow_ack_peer_stats_by_mac(PEER_D, &ps) && ps.compat == 1 );

    CHECK( rx_frame(PEER_D, env, sizeof(env), 0) );
    CHECK( halow_ack_peer_stats_by_mac(PEER_D, &ps) && ps.compat == 2 );

    halow_ack_stats_get(&st);
    CHECK( st.env_rx_bundles == 1 );
}

static void t_env_blockack_roundtrip( void ){
    halow_ack_config_t cfg;
    halow_ack_stats_t st;
    uint8_t frame[300];
    uint8_t ack[14];

    cfg_base(&cfg);
    node_start(&cfg);
    env_peer_ready(PEER_D);

    fill_payload(frame, sizeof(frame), 11);
    CHECK( halow_ack_tx(frame, sizeof(frame), PEER_D) == 0 );
    run_ticks(3, 5);

    CHECK( test_tx_count() >= 1 );
    {
        const test_tx_cap_t *b = test_tx_at(test_tx_count() - 1);
        CHECK( b->buf[0] == 0xA5 && b->buf[1] == 0x5A && b->buf[2] == 0x10 );
        CHECK( b->buf[3] == 0x00 && b->buf[4] == 0x00 );
        CHECK( b->buf[5] == 0x01 );
        CHECK( b->len == 6 + 2 + 300 );
    }
    halow_ack_stats_get(&st);
    CHECK( st.outstanding == 1 );
    CHECK( st.env_tx_bundles == 1 );

    (void)build_env_ack(ack, EVM_M10, (uint16_t)(0 - 63));
    env_ack_bit(ack, 63);
    rx_ack_frame(PEER_D, ack, 14);

    halow_ack_stats_get(&st);
    CHECK( st.acked == 1 );
    CHECK( st.env_rx_acks == 1 );
    CHECK( st.outstanding == 0 );
}
static void t_env_probe_8th_ack( void ){
    halow_ack_config_t cfg;
    halow_ack_stats_t st;
    uint8_t f[24];

    cfg_base(&cfg);
    node_start(&cfg);

    for( uint8_t i = 0; i < 8; i++ ){
        fill_payload(f, sizeof(f), i);
        CHECK( rx_frame(PEER_E, f, sizeof(f), EVM_M10) );
    }
    CHECK( count_ack_frames() == 8 );
    CHECK( count_env_ack_frames() == 1 );

    halow_ack_stats_get(&st);
    CHECK( st.acks_sent == 8 );
    CHECK( st.env_tx_acks == 1 );
}

static void t_env_unknown_malformed( void ){
    halow_ack_stats_t st;
    uint8_t ext[6] = {0xA5, 0x5A, 0x1F, 0x00, 0x01, 0x02};

    node_start(NULL);

    CHECK( !rx_frame(PEER_B, ext, sizeof(ext), 0) );
    halow_ack_env_malformed();
    halow_ack_stats_get(&st);
    CHECK( st.rx_env_unk == 2 );
}

static void t_l0_downgrade_magic_recovery( void ){
    halow_ack_config_t cfg;
    halow_ack_stats_t st;
    halow_ack_peer_stats_t ps;
    uint8_t frame[100];
    uint8_t magic[8] = {0xA5, 0xAD, 0x02, 0x00, 0x04, 0x10, 0x20, 0x30};

    cfg_base(&cfg);
    cfg.max_retries = 1;
    cfg.timeout_ms = 5;
    node_start(&cfg);

    for( uint8_t cycle = 0; cycle < 12; cycle++ ){
        fill_payload(frame, sizeof(frame), cycle);
        CHECK( halow_ack_tx(frame, sizeof(frame), PEER_A) == 0 );
        run_ticks(8, 5);
    }
    CHECK( halow_ack_peer_stats_by_mac(PEER_A, &ps) );
    CHECK( ps.compat == 0 );
    CHECK( ps.l0_falls == 1 );

    halow_ack_stats_get(&st);
    CHECK( st.drop_exhaust == 12 );
    CHECK( st.dropped == 12 );

    CHECK( rx_frame(PEER_A, magic, sizeof(magic), 0) );
    CHECK( halow_ack_peer_stats_by_mac(PEER_A, &ps) && ps.compat == 1 );
}

static void t_throttle_pend_park_drain( void ){
    halow_ack_config_t cfg;
    halow_ack_stats_t st;
    uint8_t f[700];

    cfg_base(&cfg);
    node_start(&cfg);
    test_vacancy_set(100);

    fill_payload(f, sizeof(f), 1);
    CHECK( halow_ack_tx(f, sizeof(f), PEER_A) == 0 );
    fill_payload(f, sizeof(f), 2);
    CHECK( halow_ack_tx(f, sizeof(f), PEER_A) == 0 );
    for( int i = 0; i < 15; i++ ){
        fill_payload(f, sizeof(f), (uint8_t)(i + 3));
        CHECK( halow_ack_tx(f, sizeof(f), PEER_A) == 0 );
    }
    fill_payload(f, sizeof(f), 0x55);
    CHECK( halow_ack_tx(f, sizeof(f), PEER_A) == HALOW_ACK_TX_THROTTLE );
    CHECK( test_tx_count() == 0 );

    test_vacancy_set(100000);
    for( int k = 0; k < 200; k++ ){
        run_ticks(2, 5);
        halow_ack_stats_get(&st);
        if( st.outstanding == 0 && test_tx_count() == 16 ) break;
        for( int i = 0; i < test_tx_count(); i++ ){
            ack_fid(PEER_A, (uint16_t)(fnv1a(test_tx_at(i)->buf, test_tx_at(i)->len) & 0xFFFFu));
        }
    }
    CHECK( test_tx_count() == 16 );
    {
        int bundles = 0;
        for( int i = 0; i < 16; i++ ){
            if( test_tx_at(i)->buf[0] == 0xA5 && test_tx_at(i)->buf[1] == 0xAD ) bundles++;
        }
        CHECK( bundles == 1 );
    }

    halow_ack_stats_get(&st);
    CHECK( st.dropped == 0 );
    CHECK( st.drop_throttle == 0 );
    CHECK( st.outstanding == 0 );
    CHECK( st.acked == 16 );
}

static void t_window_gate( void ){
    halow_ack_config_t cfg;
    halow_ack_stats_t st;
    uint8_t f[100];

    cfg_base(&cfg);
    cfg.window = 2;
    node_start(&cfg);

    fill_payload(f, sizeof(f), 1);
    CHECK( halow_ack_tx(f, sizeof(f), PEER_A) == 0 );
    run_ticks(2, 5);
    CHECK( test_tx_count() == 1 );

    fill_payload(f, sizeof(f), 2);
    CHECK( halow_ack_tx(f, sizeof(f), PEER_A) == 0 );
    run_ticks(2, 5);
    CHECK( test_tx_count() == 2 );

    halow_ack_stats_get(&st);
    CHECK( st.outstanding == 2 );
    CHECK( !halow_ack_tx_ready() );

    fill_payload(f, sizeof(f), 3);
    CHECK( halow_ack_tx(f, sizeof(f), PEER_A) == 0 );
    run_ticks(3, 5);
    CHECK( test_tx_count() == 2 );

    cfg.window = 6;
    halow_ack_config_apply(&cfg);
    run_ticks(3, 5);
    CHECK( test_tx_count() == 3 );
    CHECK( halow_ack_tx_ready() );
}

static void t_tx_ready_gating( void ){
    halow_ack_config_t cfg;
    uint8_t f[100];

    cfg_base(&cfg);
    cfg.window = 4;
    node_start(&cfg);

    CHECK( halow_ack_tx_ready() );
    test_vacancy_set(100);
    CHECK( !halow_ack_tx_ready() );
    test_vacancy_set(100000);
    CHECK( halow_ack_tx_ready() );

    for( uint8_t i = 0; i < 3; i++ ){
        fill_payload(f, sizeof(f), i);
        CHECK( halow_ack_tx(f, sizeof(f), PEER_A) == 0 );
        run_ticks(2, 5);
    }
    CHECK( !halow_ack_tx_ready() );
}

static void t_ra_upshift( void ){
    halow_ack_config_t cfg;
    halow_ack_stats_t st;
    halow_ack_peer_stats_t ps;
    uint8_t data[16];
    uint8_t ack[5];

    cfg_base(&cfg);
    cfg.rate_adapt = 1;
    node_start(&cfg);

    fill_payload(data, sizeof(data), 1);
    CHECK( rx_frame(PEER_R, data, sizeof(data), 0) );
    CHECK( halow_ack_peer_stats_by_mac(PEER_R, &ps) && ps.tx_mcs == 4 );

    rx_ack_frame(PEER_R, ack, build_legacy_ack(ack, EVM_M10, 0));
    CHECK( halow_ack_peer_stats_by_mac(PEER_R, &ps) && ps.tx_mcs == 5 );

    rx_ack_frame(PEER_R, ack, build_legacy_ack(ack, EVM_M10, 0));
    CHECK( halow_ack_peer_stats_by_mac(PEER_R, &ps) && ps.tx_mcs == 5 );

    for( int i = 0; i < 3; i++ ){
        test_advance_ms(300);
        rx_ack_frame(PEER_R, ack, build_legacy_ack(ack, EVM_M10, 0));
    }
    CHECK( halow_ack_peer_stats_by_mac(PEER_R, &ps) && ps.tx_mcs == 7 );

    test_advance_ms(300);
    rx_ack_frame(PEER_R, ack, build_legacy_ack(ack, EVM_M10, 0));
    CHECK( halow_ack_peer_stats_by_mac(PEER_R, &ps) && ps.tx_mcs == 7 );

    halow_ack_stats_get(&st);
    CHECK( st.ra_upshifts == 3 );
    CHECK( st.ra_blocked_gap >= 1 );
    CHECK( st.ra_blocked_max >= 1 );
    CHECK( st.ra_ack_calls == 6 );
}

static void t_is_internal_frame( void ){
    uint8_t lack[5] = {0xA5, 0x5A, 0xF6, 0x12, 0x34};
    uint8_t eack[14] = {0xA5, 0x5A, 0x11, 0xF6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    uint8_t ebun[12] = {0xA5, 0x5A, 0x10, 0, 1, 1, 4, 0, 'A', 'B', 'C', 'D'};
    uint8_t data[8] = {1, 2, 3, 4, 5, 6, 7, 8};

    node_start(NULL);
    CHECK( halow_ack_is_internal_frame(lack, sizeof(lack)) );
    CHECK( halow_ack_is_internal_frame(eack, sizeof(eack)) );
    CHECK( !halow_ack_is_internal_frame(ebun, sizeof(ebun)) );
    CHECK( !halow_ack_is_internal_frame(data, sizeof(data)) );
}

static void t_agg_size_per_mcs( void ){
    halow_ack_config_t cfg;
    halow_ack_peer_stats_t ps;
    uint8_t data[16];
    uint8_t ack[5];
    uint8_t big[1800];
    uint8_t two[800];
    int tx_before;

    cfg_base(&cfg);
    cfg.rate_adapt = 1;
    cfg.max_retries = 1;
    cfg.timeout_ms = 5;
    node_start(&cfg);

    fill_payload(data, sizeof(data), 1);
    CHECK( rx_frame(PEER_HI, data, sizeof(data), 0) );
    for( int i = 0; i < 5; i++ ){
        test_advance_ms(300);
        rx_ack_frame(PEER_HI, ack, build_legacy_ack(ack, EVM_M10, 0));
    }
    CHECK( halow_ack_peer_stats_by_mac(PEER_HI, &ps) && ps.tx_mcs == 7 );

    fill_payload(data, sizeof(data), 2);
    CHECK( rx_frame(PEER_LO, data, sizeof(data), EVM_M30) );
    test_advance_ms(3000);
    for( uint8_t cycle = 0; cycle < 5; cycle++ ){
        uint8_t small[100];
        fill_payload(small, sizeof(small), cycle);
        CHECK( halow_ack_tx(small, sizeof(small), PEER_LO) == 0 );
        run_ticks(8, 5);
    }
    CHECK( halow_ack_peer_stats_by_mac(PEER_LO, &ps) );
    CHECK( ps.tx_mcs == 1 );

    fill_payload(big, sizeof(big), 0x42);
    CHECK( halow_ack_tx(big, sizeof(big), PEER_LO) == 0 );
    CHECK( test_tx_count() >= 1 );
    {
        const test_tx_cap_t *t = test_tx_at(test_tx_count() - 1);
        CHECK( t->len == 1800 );
        CHECK( memcmp(t->buf, big, 1800) == 0 );
        rx_ack_frame(PEER_LO, ack,
                     build_legacy_ack(ack, EVM_M30,
                                      (uint16_t)(fnv1a(t->buf, t->len) & 0xFFFF)));
    }

    tx_before = test_tx_count();
    fill_payload(two, sizeof(two), 0x43);
    CHECK( halow_ack_tx(two, sizeof(two), PEER_HI) == 0 );
    CHECK( test_tx_count() == tx_before );
    fill_payload(two, sizeof(two), 0x44);
    CHECK( halow_ack_tx(two, sizeof(two), PEER_HI) == 0 );
    CHECK( test_tx_count() == tx_before );
    run_ticks(1, 5);
    CHECK( test_tx_count() == tx_before + 1 );
    {
        const test_tx_cap_t *t = test_tx_at(test_tx_count() - 1);
        CHECK( t->buf[0] == 0xA5 && t->buf[1] == 0xAD );
        CHECK( t->buf[2] == 2 );
        CHECK( t->len == 3 + 2 * 2 + 2 * 800 );
    }
}

static void t_ack_evm_zero_encoding( void ){
    halow_ack_config_t cfg;
    uint8_t f[24];
    int acks;

    cfg_base(&cfg);
    node_start(&cfg);

    fill_payload(f, sizeof(f), 1);
    CHECK( rx_frame(PEER_E, f, sizeof(f), 0) );
    acks = count_ack_frames();
    CHECK( acks == 1 );
    {
        const test_tx_cap_t *a = test_tx_at(0);
        CHECK( a->buf[0] == 0xA5 && a->buf[1] == 0x5A );
        CHECK( a->buf[2] == 0x80 );
    }
}

static void t_sixteen_peers_evict_lru( void ){
    halow_ack_config_t cfg;
    halow_ack_stats_t st;
    halow_ack_peer_stats_t ps;
    uint8_t m[6];
    uint8_t f[16];

    cfg_base(&cfg);
    cfg.window = 16;
    node_start(&cfg);

    for( uint8_t id = 1; id <= 16; id++ ){
        peer_mac(m, id);
        fill_payload(f, sizeof(f), id);
        CHECK( rx_frame(m, f, sizeof(f), 0) );
    }
    halow_ack_stats_get(&st);
    CHECK( st.peers == 16 );

    peer_mac(m, 1);
    CHECK( halow_ack_peer_stats_by_mac(m, &ps) );

    peer_mac(m, 0x80);
    fill_payload(f, sizeof(f), 0x80);
    CHECK( rx_frame(m, f, sizeof(f), 0) );

    halow_ack_stats_get(&st);
    CHECK( st.peers == 16 );
    peer_mac(m, 1);
    CHECK( !halow_ack_peer_stats_by_mac(m, &ps) );
    peer_mac(m, 0x80);
    CHECK( halow_ack_peer_stats_by_mac(m, &ps) );
}

static void t_peer_evict_protected_by_buf( void ){
    halow_ack_config_t cfg;
    halow_ack_stats_t st;
    halow_ack_peer_stats_t ps;
    uint8_t m[6];
    uint8_t f[16];
    uint8_t frame[100];

    cfg_base(&cfg);
    cfg.window = 16;
    node_start(&cfg);

    fill_payload(frame, sizeof(frame), 1);
    CHECK( halow_ack_tx(frame, sizeof(frame), PEER_A) == 0 );
    run_ticks(2, 5);
    halow_ack_stats_get(&st);
    CHECK( st.outstanding == 1 );

    for( uint8_t id = 2; id <= 16; id++ ){
        peer_mac(m, id);
        fill_payload(f, sizeof(f), id);
        CHECK( rx_frame(m, f, sizeof(f), 0) );
    }

    peer_mac(m, 0x90);
    fill_payload(f, sizeof(f), 0x90);
    CHECK( rx_frame(m, f, sizeof(f), 0) );

    CHECK( halow_ack_peer_stats_by_mac(PEER_A, &ps) );
    peer_mac(m, 2);
    CHECK( !halow_ack_peer_stats_by_mac(m, &ps) );
    peer_mac(m, 0x90);
    CHECK( halow_ack_peer_stats_by_mac(m, &ps) );
}

static void t_pool_exhaustion( void ){
    halow_ack_config_t cfg;
    halow_ack_stats_t st;
    uint8_t m[6];
    uint8_t f[100];

    cfg_base(&cfg);
    cfg.agg = 0;
    cfg.window = 8;
    node_start(&cfg);

    for( uint8_t id = 1; id <= 8; id++ ){
        peer_mac(m, id);
        fill_payload(f, sizeof(f), id);
        CHECK( halow_ack_tx(f, sizeof(f), m) == 0 );
    }
    CHECK( test_tx_count() == 8 );

    halow_ack_stats_get(&st);
    CHECK( st.outstanding == 8 );
    CHECK( !halow_ack_tx_ready() );

    peer_mac(m, 9);
    fill_payload(f, sizeof(f), 9);
    for( int i = 0; i < 8; i++ ){
        CHECK( halow_ack_tx(f, sizeof(f), m) == 0 );
    }
    CHECK( halow_ack_tx(f, sizeof(f), m) == HALOW_ACK_TX_THROTTLE );
    CHECK( test_tx_count() == 8 );

    halow_ack_stats_get(&st);
    CHECK( st.dropped == 0 );
}

static void t_window_runtime_change( void ){
    halow_ack_config_t cfg;
    uint8_t f[100];

    cfg_base(&cfg);
    cfg.window = 4;
    cfg.timeout_ms = 500;
    node_start(&cfg);

    for( uint8_t i = 0; i < 4; i++ ){
        fill_payload(f, sizeof(f), i);
        CHECK( halow_ack_tx(f, sizeof(f), PEER_A) == 0 );
        run_ticks(2, 5);
    }
    CHECK( test_tx_count() == 4 );

    fill_payload(f, sizeof(f), 9);
    CHECK( halow_ack_tx(f, sizeof(f), PEER_A) == 0 );
    run_ticks(3, 5);
    CHECK( test_tx_count() == 4 );

    cfg.window = 8;
    halow_ack_config_apply(&cfg);
    run_ticks(3, 5);
    CHECK( test_tx_count() == 5 );

    cfg.window = 3;
    halow_ack_config_apply(&cfg);
    fill_payload(f, sizeof(f), 0x0A);
    CHECK( halow_ack_tx(f, sizeof(f), PEER_A) == 0 );
    run_ticks(3, 5);
    CHECK( test_tx_count() == 5 );
}

static void t_dedup_ring_wrap( void ){
    halow_ack_config_t cfg;
    uint8_t x[32];
    uint8_t y[32];

    cfg_base(&cfg);
    node_start(&cfg);

    fill_payload(x, sizeof(x), 1);
    CHECK( rx_frame(PEER_B, x, sizeof(x), 0) );
    CHECK( !rx_frame(PEER_B, x, sizeof(x), 0) );

    for( uint8_t i = 0; i < 16; i++ ){
        fill_payload(y, sizeof(y), (uint8_t)(i + 2));
        CHECK( rx_frame(PEER_B, y, sizeof(y), 0) );
    }
    CHECK( rx_frame(PEER_B, x, sizeof(x), 0) );
    CHECK( !rx_frame(PEER_B, x, sizeof(x), 0) );
}

static void t_blockack_partial_bitmap( void ){
    halow_ack_config_t cfg;
    halow_ack_stats_t st;
    uint8_t frame[300];
    uint8_t ack[14];

    cfg_base(&cfg);
    cfg.window = 16;
    node_start(&cfg);
    env_peer_ready(PEER_D);

    for( uint8_t i = 0; i < 3; i++ ){
        fill_payload(frame, sizeof(frame), i);
        CHECK( halow_ack_tx(frame, sizeof(frame), PEER_D) == 0 );
        run_ticks(2, 5);
    }
    halow_ack_stats_get(&st);
    CHECK( st.outstanding == 3 );
    CHECK( st.env_tx_bundles == 3 );

    (void)build_env_ack(ack, EVM_M10, (uint16_t)(0 - 61));
    env_ack_bit(ack, 61);
    env_ack_bit(ack, 63);
    rx_ack_frame(PEER_D, ack, 14);

    halow_ack_stats_get(&st);
    CHECK( st.acked == 2 );
    CHECK( st.outstanding == 1 );
}

static void t_config_migration_reseed( void ){
    halow_ack_config_t live;
    int16_t v = 0;

    test_time_reset();
    configdb_reset();
    test_tx_reset();
    test_vacancy_set(100000);
    test_kv_set("cfg.hack.ver", 2);
    test_kv_set("cfg.hack.retry", 8);
    halow_ack_init();

    halow_ack_config_get_live(&live);
    CHECK( live.max_retries == 3 );
    CHECK( live.timeout_ms == 100 );
    CHECK( live.window == 10 );
    CHECK( live.ack_fids == 16 );

    CHECK( test_kv_get("cfg.hack.ver", &v) == 0 && v == 3 );
    CHECK( test_kv_get("cfg.hack.retry", &v) == 0 && v == 3 );
}

/* ================= long soaks ================= */

static void t_soak_fid_roundtrip( void ){
    halow_ack_config_t cfg;
    halow_ack_stats_t st;
    uint8_t f[100];

    cfg_base(&cfg);
    cfg.agg = 0;
    cfg.window = 16;
    node_start(&cfg);

    for( int i = 0; i < 1000; i++ ){
        fill_payload(f, sizeof(f), (uint8_t)i);
        CHECK( halow_ack_tx(f, sizeof(f), PEER_A) == 0 );
        ack_fid(PEER_A, fid_of(f, sizeof(f)));
        if( (i % 50) == 49 ) halow_ack_tick();
    }
    run_ticks(2, 5);

    halow_ack_stats_get(&st);
    CHECK( test_tx_count() == 1000 );
    CHECK( st.tx_frames == 1000 );
    CHECK( st.acked == 1000 );
    CHECK( st.dropped == 0 );
    CHECK( st.outstanding == 0 );
    CHECK( st.acks_rx_dup == 0 );
    CHECK( st.ack_rtt_hits == 1000 );
}

static void t_soak_bundle_delayed_ack( void ){
    halow_ack_config_t cfg;
    halow_ack_stats_t st;
    uint8_t f[200];
    uint16_t lost[12];
    int lost_n = 0;

    cfg_base(&cfg);
    cfg.window = 16;
    cfg.timeout_ms = 30;
    cfg.max_retries = 5;
    node_start(&cfg);

    for( int i = 0; i < 500; i++ ){
        fill_payload(f, sizeof(f), (uint8_t)i);
        CHECK( halow_ack_tx(f, sizeof(f), PEER_A) == 0 );
        run_ticks(1, 5);
        if( (i % 3) == 0 ){
            lost[lost_n++] = fid_of(f, sizeof(f));
            if( lost_n == 10 ){
                for( int k = 0; k < lost_n; k++ ) ack_fid(PEER_A, lost[k]);
                lost_n = 0;
            }
        }else{
            ack_fid(PEER_A, fid_of(f, sizeof(f)));
        }
    }
    run_ticks(10, 10);
    for( int k = 0; k < lost_n; k++ ) ack_fid(PEER_A, lost[k]);
    run_ticks(3, 5);

    halow_ack_stats_get(&st);
    CHECK( st.tx_frames == 500 );
    CHECK( st.acked == 500 );
    CHECK( st.dropped == 0 );
    CHECK( st.outstanding == 0 );
    CHECK( st.retransmitted >= 100 );
    CHECK( test_tx_count() >= 600 );
}

static void t_soak_lossy_exhaust( void ){
    halow_ack_config_t cfg;
    halow_ack_stats_t st;
    uint8_t f[100];

    cfg_base(&cfg);
    cfg.agg = 0;
    cfg.window = 16;
    cfg.timeout_ms = 10;
    cfg.max_retries = 1;
    node_start(&cfg);

    for( int i = 0; i < 500; i++ ){
        fill_payload(f, sizeof(f), (uint8_t)i);
        CHECK( halow_ack_tx(f, sizeof(f), PEER_A) == 0 );
        if( (i % 4) != 0 ) ack_fid(PEER_A, fid_of(f, sizeof(f)));
        run_ticks(1, 25);
    }

    halow_ack_stats_get(&st);
    CHECK( st.tx_frames == 500 );
    CHECK( st.acked == 375 );
    CHECK( st.dropped == 125 );
    CHECK( st.drop_exhaust == 125 );
    CHECK( st.outstanding == 0 );
    CHECK( test_tx_count() == 375 + 2 * 125 );
}

static void t_soak_bidir_two_peers( void ){
    halow_ack_config_t cfg;
    halow_ack_stats_t st;
    halow_ack_peer_stats_t pa, pb;
    uint8_t f[120];
    uint16_t pend_fid = 0;
    uint8_t rx[64];

    cfg_base(&cfg);
    cfg.window = 16;
    node_start(&cfg);

    for( int i = 0; i < 300; i++ ){
        fill_payload(f, sizeof(f), (uint8_t)i);
        CHECK( halow_ack_tx(f, sizeof(f), PEER_A) == 0 );
        run_ticks(1, 5);
        ack_fid(PEER_A, fid_of(f, sizeof(f)));

        fill_payload(f, sizeof(f), (uint8_t)(i + 77));
        CHECK( halow_ack_tx(f, sizeof(f), PEER_B) == 0 );
        run_ticks(1, 5);
        if( pend_fid != 0u ){
            ack_fid(PEER_B, pend_fid);
            pend_fid = 0;
        }
        if( (i % 50) == 49 ){
            pend_fid = fid_of(f, sizeof(f));
        }else{
            ack_fid(PEER_B, fid_of(f, sizeof(f)));
        }

        fill_payload(rx, sizeof(rx), (uint8_t)(i + 200));
        CHECK( rx_frame(PEER_A, rx, sizeof(rx), EVM_M10) );
    }
    run_ticks(3, 10);
    if( pend_fid != 0u ) ack_fid(PEER_B, pend_fid);
    run_ticks(2, 5);

    halow_ack_stats_get(&st);
    CHECK( st.tx_frames == 600 );
    CHECK( st.dropped == 0 );
    CHECK( st.outstanding == 0 );

    CHECK( halow_ack_peer_stats_by_mac(PEER_A, &pa) && pa.acked == 300 );
    CHECK( halow_ack_peer_stats_by_mac(PEER_B, &pb) && pb.acked == 300 );

    fill_payload(f, sizeof(f), 0xEE);
    CHECK( halow_ack_tx(f, sizeof(f), PEER_A) == 0 );
    run_ticks(1, 5);
    {
        uint16_t fa = fid_of(f, sizeof(f));
        halow_ack_stats_get(&st);
        CHECK( st.outstanding == 1 );
        ack_fid(PEER_B, fa);
        halow_ack_stats_get(&st);
        CHECK( st.outstanding == 1 );
        CHECK( st.acks_rx_dup >= 1 );
        ack_fid(PEER_A, fa);
        halow_ack_stats_get(&st);
        CHECK( st.outstanding == 0 );
    }
}

static void t_soak_multipeer_pressure( void ){
    halow_ack_config_t cfg;
    halow_ack_stats_t st;
    fid_ring_t ring;
    uint8_t m[6];
    uint8_t f[100];

    cfg_base(&cfg);
    cfg.window = 8;
    cfg.timeout_ms = 50;
    cfg.max_retries = 3;
    node_start(&cfg);
    fr_clear(&ring);

    for( int i = 0; i < 2000; i++ ){
        peer_mac(m, (uint8_t)(i % 16 + 1));
        fill_payload(f, sizeof(f), (uint8_t)i);
        CHECK( halow_ack_tx(f, sizeof(f), m) == 0 );
        run_ticks(1, 5);
        fr_push(&ring, m, fid_of(f, sizeof(f)));
        if( (i % 97) != 96 ) fr_ack_all(&ring);
    }
    for( int k = 0; k < 10; k++ ){
        run_ticks(2, 5);
        fr_ack_all(&ring);
        halow_ack_stats_get(&st);
        if( st.outstanding == 0 ) break;
    }

    halow_ack_stats_get(&st);
    CHECK( st.tx_frames == 2000 );
    CHECK( st.outstanding == 0 );
    CHECK( st.drop_throttle == 0 );
    CHECK( st.acked + st.dropped == st.tx_frames );
    CHECK( st.peers == 16 );
}

static void t_soak_window_one_serial( void ){
    halow_ack_config_t cfg;
    halow_ack_stats_t st;
    uint8_t f[80];

    cfg_base(&cfg);
    cfg.agg = 0;
    cfg.window = 1;
    node_start(&cfg);

    for( int i = 0; i < 300; i++ ){
        fill_payload(f, sizeof(f), (uint8_t)i);
        CHECK( halow_ack_tx(f, sizeof(f), PEER_A) == 0 );
        halow_ack_stats_get(&st);
        CHECK( st.outstanding == 1 );
        ack_fid(PEER_A, fid_of(f, sizeof(f)));
        halow_ack_stats_get(&st);
        CHECK( st.outstanding == 0 );
    }

    halow_ack_stats_get(&st);
    CHECK( st.tx_frames == 300 );
    CHECK( st.acked == 300 );
    CHECK( st.dropped == 0 );
    CHECK( test_tx_count() == 300 );
}

/* ================= edge cases ================= */

static void t_edge_frame_size_boundaries( void ){
    halow_ack_config_t cfg;
    halow_ack_stats_t st;
    static uint8_t big[65536];
    int wire;

    cfg_base(&cfg);
    cfg.window = 16;
    node_start(&cfg);

    fill_payload(big, 1, 1);
    CHECK( halow_ack_tx(big, 1, PEER_A) == 0 );
    CHECK( test_tx_count() == 0 );
    run_ticks(1, 5);
    CHECK( test_tx_count() == 1 && test_tx_at(0)->len == 1 );
    ack_fid(PEER_A, fid_of(big, 1));

    fill_payload(big, 2040, 2);
    CHECK( halow_ack_tx(big, 2040, PEER_A) == 0 );
    CHECK( test_tx_count() == 1 );
    run_ticks(1, 5);
    CHECK( test_tx_count() == 2 && test_tx_at(1)->len == 2040 );
    ack_fid(PEER_A, fid_of(big, 2040));

    fill_payload(big, 2041, 3);
    wire = test_tx_count();
    CHECK( halow_ack_tx(big, 2041, PEER_A) == 0 );
    CHECK( test_tx_count() == wire + 1 );
    ack_fid(PEER_A, fid_of(big, 2041));

    fill_payload(big, 2048, 4);
    wire = test_tx_count();
    CHECK( halow_ack_tx(big, 2048, PEER_A) == 0 );
    CHECK( test_tx_count() == wire + 1 );
    CHECK( test_tx_at(wire)->len == 2048 );
    ack_fid(PEER_A, fid_of(big, 2048));

    fill_payload(big, 2049, 5);
    wire = test_tx_count();
    CHECK( halow_ack_tx(big, 2049, PEER_A) == 0 );
    CHECK( test_tx_count() == wire + 1 );
    CHECK( test_tx_at(wire)->len == 2049 );

    fill_payload(big, 65535, 6);
    wire = test_tx_count();
    CHECK( halow_ack_tx(big, 65535, PEER_A) == 0 );
    CHECK( test_tx_count() == wire + 1 );
    CHECK( test_tx_last()->len == 65535 );

    halow_ack_stats_get(&st);
    CHECK( st.outstanding == 0 );
    CHECK( st.tx_frames == 6 );
}

static void t_edge_bundle_exact_fit( void ){
    halow_ack_config_t cfg;
    uint8_t f[1024];
    int wire;

    cfg_base(&cfg);
    cfg.window = 16;
    node_start(&cfg);

    fill_payload(f, 1019, 1);
    CHECK( halow_ack_tx(f, 1019, PEER_A) == 0 );
    fill_payload(f, 1019, 2);
    CHECK( halow_ack_tx(f, 1019, PEER_A) == 0 );
    CHECK( test_tx_count() == 0 );
    run_ticks(1, 5);
    CHECK( test_tx_count() == 1 );
    CHECK( test_tx_at(0)->len == 3 + 2 * 2 + 2 * 1019 );
    CHECK( test_tx_at(0)->buf[0] == 0xA5 && test_tx_at(0)->buf[1] == 0xAD );
    CHECK( test_tx_at(0)->buf[2] == 2 );

    node_start(&cfg);
    env_peer_ready(PEER_D);
    fill_payload(f, 1019, 3);
    CHECK( halow_ack_tx(f, 1019, PEER_D) == 0 );
    fill_payload(f, 1019, 4);
    CHECK( halow_ack_tx(f, 1019, PEER_D) == 0 );
    run_ticks(1, 5);
    CHECK( test_tx_count() >= 1 );
    {
        const test_tx_cap_t *b = test_tx_at(test_tx_count() - 1);
        CHECK( b->len == 2048 );
        CHECK( b->buf[0] == 0xA5 && b->buf[1] == 0x5A && b->buf[2] == 0x10 );
    }

    node_start(&cfg);
    fill_payload(f, 1019, 5);
    CHECK( halow_ack_tx(f, 1019, PEER_A) == 0 );
    fill_payload(f, 1020, 6);
    CHECK( halow_ack_tx(f, 1020, PEER_A) == 0 );
    run_ticks(2, 5);
    CHECK( test_tx_count() == 2 );
    CHECK( test_tx_at(0)->len == 1019 );
    CHECK( test_tx_at(1)->len == 1020 );
    wire = 0; (void)wire;
}

static void t_edge_seq_rollover( void ){
    halow_ack_config_t cfg;
    halow_ack_stats_t st;
    uint8_t f[300];
    uint8_t ack[14];
    uint16_t seq;
    int wire0;

    cfg_base(&cfg);
    cfg.window = 16;
    node_start(&cfg);
    env_peer_ready(PEER_D);
    wire0 = test_tx_count();

    for( uint32_t i = 0; i < 65537u; i++ ){
        fill_payload(f, sizeof(f), (uint8_t)i);
        CHECK( halow_ack_tx(f, sizeof(f), PEER_D) == 0 );
        run_ticks(1, 2);
        const test_tx_cap_t *b = test_tx_last();
        CHECK( b->buf[0] == 0xA5 && b->buf[1] == 0x5A && b->buf[2] == 0x10 );
        seq = (uint16_t)((uint16_t)b->buf[3] | ((uint16_t)b->buf[4] << 8));
        CHECK( seq != 0xFFFFu );
        if( i == 65535u ) CHECK( seq == 0u );
        if( i == 65536u ) CHECK( seq == 1u );
        if( i == 65535u ) CHECK( test_tx_count() - wire0 == 65536 );

        (void)build_env_ack(ack, EVM_M10, (uint16_t)(seq - 63));
        env_ack_bit(ack, 63);
        rx_ack_frame(PEER_D, ack, 14);
        if( (i % 4096u) == 0u ){
            halow_ack_stats_get(&st);
            CHECK( st.outstanding == 0 );
        }
    }

    halow_ack_stats_get(&st);
    CHECK( st.env_tx_bundles == 65537 );
    CHECK( st.acked == 65537 );
    CHECK( st.outstanding == 0 );
}

static void t_edge_backoff_exact_timing( void ){
    halow_ack_config_t cfg;
    halow_ack_stats_t st;
    uint8_t f[100];
    uint32_t t = 0;

    cfg_base(&cfg);
    cfg.agg = 0;
    cfg.timeout_ms = 10;
    cfg.max_retries = 8;
    node_start(&cfg);

    fill_payload(f, sizeof(f), 1);
    CHECK( halow_ack_tx(f, sizeof(f), PEER_A) == 0 );
    CHECK( test_tx_count() == 1 );

    struct { uint32_t at; int wire; } expect[] = {
        {9, 1}, {10, 2}, {29, 2}, {30, 3}, {69, 3}, {70, 4},
        {149, 4}, {150, 5}, {229, 5}, {230, 6}, {309, 6}, {310, 7},
        {389, 7}, {390, 8}, {469, 8}, {470, 9}, {549, 9}, {550, 9},
    };
    for( unsigned k = 0; k < sizeof(expect) / sizeof(expect[0]); k++ ){
        test_advance_ms(expect[k].at - t);
        t = expect[k].at;
        halow_ack_tick();
        CHECK( test_tx_count() == expect[k].wire );
    }

    halow_ack_stats_get(&st);
    CHECK( st.dropped == 1 );
    CHECK( st.drop_exhaust == 1 );
    CHECK( st.drop_deadline == 0 );
    CHECK( st.retransmitted == 8 );
}

static void t_edge_ack_len_parity( void ){
    halow_ack_stats_t st;
    uint8_t a[40];

    node_start(NULL);
    memset(a, 0, sizeof(a));
    a[0] = 0xA5; a[1] = 0x5A; a[2] = 0xF6;

    CHECK( rx_frame(PEER_B, a, 3, 0) );
    CHECK( rx_frame(PEER_B, a, 4, 0) );
    CHECK( !rx_frame(PEER_B, a, 5, 0) );
    CHECK( rx_frame(PEER_B, a, 6, 0) );
    CHECK( !rx_frame(PEER_B, a, 35, 0) );
    CHECK( rx_frame(PEER_B, a, 36, 0) );
    CHECK( rx_frame(PEER_B, a, 37, 0) );

    halow_ack_stats_get(&st);
    CHECK( st.acks_rx_frames == 2 );

    CHECK( halow_ack_is_internal_frame(a, 5) );
    CHECK( !halow_ack_is_internal_frame(a, 6) );
    CHECK( halow_ack_is_internal_frame(a, 35) );
    CHECK( !halow_ack_is_internal_frame(a, 37) );
}

static void t_edge_fid_zero_and_ack_storm( void ){
    halow_ack_config_t cfg;
    halow_ack_stats_t st;
    uint8_t f[100];
    uint8_t ack[5];
    uint16_t fid;

    cfg_base(&cfg);
    cfg.agg = 0;
    node_start(&cfg);

    fill_payload(f, sizeof(f), 1);
    CHECK( halow_ack_tx(f, sizeof(f), PEER_A) == 0 );
    fid = fid_of(f, sizeof(f));

    rx_ack_frame(PEER_A, ack, build_legacy_ack(ack, EVM_M10, 0));
    halow_ack_stats_get(&st);
    CHECK( st.outstanding == 1 );
    CHECK( st.acks_rx_dup == 0 );

    rx_ack_frame(PEER_A, ack, build_legacy_ack(ack, EVM_M10, 0x1234));
    halow_ack_stats_get(&st);
    CHECK( st.outstanding == 1 );
    CHECK( st.acks_rx_dup == 1 );

    for( int i = 0; i < 100; i++ ){
        rx_ack_frame(PEER_A, ack, build_legacy_ack(ack, EVM_M10, fid));
    }
    halow_ack_stats_get(&st);
    CHECK( st.acked == 1 );
    CHECK( st.acks_rx_dup == 100 );
    CHECK( st.outstanding == 0 );
}

static void t_edge_blockack_bitmap_extremes( void ){
    halow_ack_config_t cfg;
    halow_ack_stats_t st;
    uint8_t f[300];
    uint8_t ack[14];

    cfg_base(&cfg);
    cfg.window = 16;
    node_start(&cfg);
    env_peer_ready(PEER_D);

    for( uint8_t i = 0; i < 3; i++ ){
        fill_payload(f, sizeof(f), i);
        CHECK( halow_ack_tx(f, sizeof(f), PEER_D) == 0 );
        run_ticks(2, 5);
    }
    halow_ack_stats_get(&st);
    CHECK( st.outstanding == 3 );

    (void)build_env_ack(ack, EVM_M10, (uint16_t)(2 - 63));
    rx_ack_frame(PEER_D, ack, 14);
    halow_ack_stats_get(&st);
    CHECK( st.outstanding == 3 );
    CHECK( st.env_rx_acks == 1 );

    (void)build_env_ack(ack, EVM_M10, 1000);
    memset(&ack[6], 0xFF, 8);
    rx_ack_frame(PEER_D, ack, 14);
    halow_ack_stats_get(&st);
    CHECK( st.outstanding == 3 );

    (void)build_env_ack(ack, EVM_M10, (uint16_t)(2 - 63));
    memset(&ack[6], 0xFF, 8);
    rx_ack_frame(PEER_D, ack, 14);
    halow_ack_stats_get(&st);
    CHECK( st.outstanding == 0 );
    CHECK( st.acked == 3 );
}

static void t_edge_park_timeout( void ){
    halow_ack_config_t cfg;
    halow_ack_stats_t st;
    uint8_t f[100];
    uint16_t fid1;

    cfg_base(&cfg);
    cfg.agg = 0;
    cfg.window = 1;
    cfg.timeout_ms = 300;
    cfg.max_retries = 8;
    node_start(&cfg);

    fill_payload(f, sizeof(f), 1);
    CHECK( halow_ack_tx(f, sizeof(f), PEER_A) == 0 );
    CHECK( test_tx_count() == 1 );
    fid1 = fid_of(f, sizeof(f));

    fill_payload(f, sizeof(f), 2);
    CHECK( halow_ack_tx(f, sizeof(f), PEER_A) == 0 );
    CHECK( test_tx_count() == 1 );

    run_ticks(90, 50);

    halow_ack_stats_get(&st);
    CHECK( st.drop_throttle == 1 );
    CHECK( st.dropped == 1 );
    CHECK( st.drop_deadline == 0 );

    ack_fid(PEER_A, fid1);
    halow_ack_stats_get(&st);
    CHECK( st.outstanding == 0 );

    fill_payload(f, sizeof(f), 3);
    CHECK( halow_ack_tx(f, sizeof(f), PEER_A) == 0 );
}

static void t_edge_ack_hold_extremes( void ){
    halow_ack_config_t cfg;
    uint8_t f[24];

    cfg_base(&cfg);
    cfg.ack_hold_ms = 20;
    cfg.ack_fids = 1;
    node_start(&cfg);
    for( uint8_t i = 0; i < 3; i++ ){
        fill_payload(f, sizeof(f), i);
        CHECK( rx_frame(PEER_E, f, sizeof(f), EVM_M10) );
    }
    CHECK( count_ack_frames() == 3 );

    cfg.ack_fids = 16;
    node_start(&cfg);
    for( uint8_t i = 0; i < 15; i++ ){
        fill_payload(f, sizeof(f), (uint8_t)(i + 10));
        CHECK( rx_frame(PEER_E, f, sizeof(f), EVM_M10) );
    }
    CHECK( count_ack_frames() == 0 );
    fill_payload(f, sizeof(f), 0x40);
    CHECK( rx_frame(PEER_E, f, sizeof(f), EVM_M10) );
    CHECK( count_ack_frames() == 1 );
}

static void t_edge_env_bundle_nsub_zero( void ){
    halow_ack_stats_t st;
    uint8_t data[16];
    uint8_t short_env[6]  = {0xA5, 0x5A, 0x10, 0x00, 0x00, 0x00};
    uint8_t nsub0[8]      = {0xA5, 0x5A, 0x10, 0x00, 0x00, 0x00, 0x11, 0x22};

    node_start(NULL);

    fill_payload(data, sizeof(data), 1);
    CHECK( rx_frame(PEER_B, data, sizeof(data), 0) );

    CHECK( !rx_frame(PEER_B, short_env, sizeof(short_env), 0) );
    halow_ack_stats_get(&st);
    CHECK( st.rx_env_unk == 1 );

    CHECK( rx_frame(PEER_B, nsub0, sizeof(nsub0), 0) );
    halow_ack_stats_get(&st);
    CHECK( st.env_rx_bundles == 1 );
}

static void t_edge_stale_reheard_compat_reset( void ){
    halow_ack_config_t cfg;
    halow_ack_peer_stats_t ps;
    uint8_t data[16];
    uint8_t ack[5];

    cfg_base(&cfg);
    cfg.rate_adapt = 1;
    node_start(&cfg);
    env_peer_ready(PEER_D);

    rx_ack_frame(PEER_D, ack, build_legacy_ack(ack, EVM_M10, 0));
    CHECK( halow_ack_peer_stats_by_mac(PEER_D, &ps) && ps.compat == 2 );

    test_advance_ms(61000);
    fill_payload(data, sizeof(data), 0x50);
    CHECK( rx_frame(PEER_D, data, sizeof(data), 0) );

    CHECK( halow_ack_peer_stats_by_mac(PEER_D, &ps) );
    CHECK( ps.compat == 1 );
    CHECK( ps.tx_mcs == 7 );
}

static void t_edge_vacancy_flap( void ){
    halow_ack_config_t cfg;
    halow_ack_stats_t st;
    fid_ring_t ring;
    uint8_t f[100];
    int wire_prev;

    cfg_base(&cfg);
    cfg.window = 8;
    cfg.timeout_ms = 50;
    cfg.max_retries = 3;
    node_start(&cfg);
    fr_clear(&ring);

    for( int i = 0; i < 60; i++ ){
        test_vacancy_set( (i % 6 < 3) ? 100000u : 100u );
        fill_payload(f, sizeof(f), (uint8_t)i);
        CHECK( halow_ack_tx(f, sizeof(f), PEER_A) == 0 );
        wire_prev = test_tx_count();
        run_ticks(2, 5);
        if( test_tx_count() > wire_prev ){
            const test_tx_cap_t *b = test_tx_at(test_tx_count() - 1);
            fr_push(&ring, PEER_A, (uint16_t)(fnv1a(b->buf, b->len) & 0xFFFFu));
        }
        if( (i % 4) == 3 ) fr_ack_all(&ring);
    }

    test_vacancy_set(100000);
    for( int k = 0; k < 30; k++ ){
        wire_prev = test_tx_count();
        run_ticks(2, 10);
        if( test_tx_count() > wire_prev ){
            const test_tx_cap_t *b = test_tx_last();
            fr_push(&ring, PEER_A, (uint16_t)(fnv1a(b->buf, b->len) & 0xFFFFu));
        }
        fr_ack_all(&ring);
        halow_ack_stats_get(&st);
        if( st.outstanding == 0 ) break;
    }

    halow_ack_stats_get(&st);
    CHECK( st.outstanding == 0 );
    CHECK( st.dropped == 0 );
    CHECK( st.tx_frames == 60 );
    CHECK( st.acked == (uint32_t)test_tx_count() );
    CHECK( st.acked >= 1 );
}

static void t_edge_rapid_reconfig( void ){
    halow_ack_config_t cfg;
    halow_ack_stats_t st;
    fid_ring_t ring;
    uint8_t m[6];
    uint8_t f[100];

    cfg_base(&cfg);
    node_start(&cfg);
    fr_clear(&ring);

    for( int i = 0; i < 300; i++ ){
        if( (i % 10) == 0 ){
            cfg_base(&cfg);
            cfg.window  = ( (i / 10) % 2 ) ? 16u : 1u;
            cfg.agg     = ( (i / 10) % 2 );
            cfg.env     = ( (i / 10) % 2 );
            cfg.timeout_ms = ( (i / 10) % 2 ) ? 200u : 20u;
            halow_ack_config_apply(&cfg);
        }
        peer_mac(m, (uint8_t)((i % 2) ? 0x11 : 0x22));
        fill_payload(f, sizeof(f), (uint8_t)i);
        CHECK( halow_ack_tx(f, sizeof(f), m) == 0 );
        run_ticks(2, 5);
        fr_push(&ring, m, fid_of(f, sizeof(f)));
        fr_ack_all(&ring);
    }

    cfg_base(&cfg);
    halow_ack_config_apply(&cfg);
    for( int k = 0; k < 30; k++ ){
        run_ticks(2, 10);
        fr_ack_all(&ring);
        halow_ack_stats_get(&st);
        if( st.outstanding == 0 ) break;
    }

    halow_ack_stats_get(&st);
    CHECK( st.tx_frames == 300 );
    CHECK( st.outstanding == 0 );
    CHECK( st.acked + st.dropped == st.tx_frames );
}

int main( void ){
#ifndef __csky__
    setvbuf(stdout, NULL, _IONBF, 0);
#endif
    struct { const char *name; void (*fn)(void); } tests[] = {
        {"init_defaults",               t_init_defaults},
        {"config_clamp",                t_config_clamp},
        {"broadcast_noack_bc_repeat",   t_broadcast_noack},
        {"bundle_flush_fid_ack",        t_bundle_flush_fid_ack},
        {"retry_exhaust",               t_retry_exhaust},
        {"slot_lifetime_deadline",      t_slot_lifetime_deadline},
        {"rx_dedup",                    t_rx_dedup},
        {"cumulative_ack_coalesce",     t_cumulative_ack_coalesce},
        {"env_compat_upgrade",          t_env_compat_upgrade},
        {"env_blockack_roundtrip",      t_env_blockack_roundtrip},
        {"env_probe_8th_ack",           t_env_probe_8th_ack},
        {"env_unknown_malformed",       t_env_unknown_malformed},
        {"l0_downgrade_magic_recovery", t_l0_downgrade_magic_recovery},
        {"throttle_pend_park_drain",    t_throttle_pend_park_drain},
        {"window_gate",                 t_window_gate},
        {"tx_ready_gating",             t_tx_ready_gating},
        {"ra_upshift",                  t_ra_upshift},
        {"is_internal_frame",           t_is_internal_frame},
        {"agg_size_per_mcs",            t_agg_size_per_mcs},
        {"ack_evm_zero_encoding",       t_ack_evm_zero_encoding},
        {"sixteen_peers_evict_lru",     t_sixteen_peers_evict_lru},
        {"peer_evict_protected_by_buf", t_peer_evict_protected_by_buf},
        {"pool_exhaustion",            t_pool_exhaustion},
        {"window_runtime_change",       t_window_runtime_change},
        {"dedup_ring_wrap",             t_dedup_ring_wrap},
        {"blockack_partial_bitmap",     t_blockack_partial_bitmap},
        {"config_migration_reseed",     t_config_migration_reseed},
        {"soak_fid_roundtrip",          t_soak_fid_roundtrip},
        {"soak_bundle_delayed_ack",     t_soak_bundle_delayed_ack},
        {"soak_lossy_exhaust",          t_soak_lossy_exhaust},
        {"soak_bidir_two_peers",        t_soak_bidir_two_peers},
        {"soak_multipeer_pressure",     t_soak_multipeer_pressure},
        {"soak_window_one_serial",      t_soak_window_one_serial},
        {"edge_frame_size_boundaries",  t_edge_frame_size_boundaries},
        {"edge_bundle_exact_fit",       t_edge_bundle_exact_fit},
        {"edge_seq_rollover",           t_edge_seq_rollover},
        {"edge_backoff_exact_timing",   t_edge_backoff_exact_timing},
        {"edge_ack_len_parity",         t_edge_ack_len_parity},
        {"edge_fid_zero_and_ack_storm", t_edge_fid_zero_and_ack_storm},
        {"edge_blockack_bitmap_extremes", t_edge_blockack_bitmap_extremes},
        {"edge_park_timeout",           t_edge_park_timeout},
        {"edge_ack_hold_extremes",      t_edge_ack_hold_extremes},
        {"edge_env_bundle_nsub_zero",   t_edge_env_bundle_nsub_zero},
        {"edge_stale_reheard_compat_reset", t_edge_stale_reheard_compat_reset},
        {"edge_vacancy_flap",           t_edge_vacancy_flap},
        {"edge_rapid_reconfig",         t_edge_rapid_reconfig},
    };

    printf("halow_ack host tests: %d scenarios\n", (int)(sizeof(tests) / sizeof(tests[0])));
    for( unsigned i = 0; i < sizeof(tests) / sizeof(tests[0]); i++ ){
        int pass_before = g_pass;
        int fail_before = g_fail;
        printf("  %-30s", tests[i].name);
        tests[i].fn();
        if( g_pass == pass_before && g_fail == fail_before ) printf(" [no checks]\n");
        else if( g_fail == fail_before )                      printf(" ok\n");
        else                                                  printf(" FAIL\n");
    }
    printf("\n%d checks passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
