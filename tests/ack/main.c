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
    c->ack_hold_ms  = 0;
    c->rate_adapt   = 0;
    c->window       = 8;
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
    CHECK( st.heap_bytes == 0 && st.heap_fail == 0 );

    halow_ack_config_get_live(&live);
    CHECK( live.max_retries == 3 );
    CHECK( live.timeout_ms == 100 );
    CHECK( live.window == 10 );
    CHECK( live.ack_fids == 16 );
    CHECK( live.agg == 1 );
    CHECK( live.env == 1 );
    CHECK( live.agg_bytes == 4000 );

    CHECK( test_kv_get("cfg.hack.ver", &v) == 0 && v == 4 );
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
    cfg.ack_hold_ms = 999;
    cfg.bc_repeat   = 9;
    cfg.agg_bytes   = 9999;
    cfg.ra_loss_up   = 50;
    cfg.ra_loss_down = 20;
    halow_ack_config_apply(&cfg);

    halow_ack_config_get_live(&live);
    CHECK( live.timeout_ms == 300 );
    CHECK( live.max_retries == 8 );
    CHECK( live.window == 16 );
    CHECK( live.ack_fids == 16 );
    CHECK( live.ack_hold_ms == 100 );
    CHECK( live.bc_repeat == 3 );
    CHECK( live.agg_bytes == 4000 );
    CHECK( live.ra_loss_up == 5 && live.ra_loss_down == 30 );

    cfg.agg_bytes = 0;
    halow_ack_config_apply(&cfg);
    halow_ack_config_get_live(&live);
    CHECK( live.agg_bytes == 4000 );
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

/* THROTTLE contract with the TCP side: the staged bundle swallows frames
 * until it is full; once full and unflushable (no DMA room) the caller gets
 * THROTTLE -- the "recv window closes" signal. Room returns -> one bundle
 * on the wire, every frame inside, nothing lost. */
static void t_throttle_staging_drain( void ){
    halow_ack_config_t cfg;
    halow_ack_stats_t st;
    uint8_t f[700];
    int staged_ok = 0;

    cfg_base(&cfg);
    node_start(&cfg);
    test_vacancy_set(100);

    fill_payload(f, sizeof(f), 1);
    for( int i = 0; i < 5; i++ ){
        fill_payload(f, sizeof(f), (uint8_t)(i + 1));
        CHECK( halow_ack_tx(f, sizeof(f), PEER_A) == 0 );
        staged_ok++;
    }
    fill_payload(f, sizeof(f), 0x55);
    CHECK( halow_ack_tx(f, sizeof(f), PEER_A) == HALOW_ACK_TX_THROTTLE );
    CHECK( test_tx_count() == 0 );

    test_vacancy_set(100000);
    run_ticks(2, 5);
    CHECK( test_tx_count() == 1 );
    {
        const test_tx_cap_t *b = test_tx_at(0);
        CHECK( b->buf[0] == 0xA5 && b->buf[1] == 0xAD );
        CHECK( b->buf[2] == staged_ok );
        CHECK( b->len == 3u + 2u*staged_ok + 700u*staged_ok );
        ack_fid(PEER_A, (uint16_t)(fnv1a(b->buf, b->len) & 0xFFFFu));
    }

    halow_ack_stats_get(&st);
    CHECK( st.dropped == 0 );
    CHECK( st.drop_throttle == 0 );
    CHECK( st.outstanding == 0 );
    CHECK( st.acked == 1 );
    CHECK( st.tx_frames == (uint32_t)staged_ok );
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

    /* window full: no slot, no parking -- THROTTLE is the TCP backpressure */
    peer_mac(m, 9);
    fill_payload(f, sizeof(f), 9);
    CHECK( halow_ack_tx(f, sizeof(f), m) == HALOW_ACK_TX_THROTTLE );
    CHECK( test_tx_count() == 8 );

    /* one ACK frees a slot: the frame goes through */
    {
        uint16_t fid = (uint16_t)(fnv1a(test_tx_at(0)->buf, test_tx_at(0)->len) & 0xFFFFu);
        peer_mac(m, 1);
        ack_fid(m, fid);
    }
    peer_mac(m, 9);
    CHECK( halow_ack_tx(f, sizeof(f), m) == 0 );
    CHECK( test_tx_count() == 9 );

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

    CHECK( test_kv_get("cfg.hack.ver", &v) == 0 && v == 4 );
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

    /* 4000 = biggest single payload that may ride a bundle (2x2000 MTU);
     * it fills the bundle alone and leaves immediately, unwrapped to plain */
    fill_payload(big, 4000, 2);
    wire = test_tx_count();
    CHECK( halow_ack_tx(big, 4000, PEER_A) == 0 );
    CHECK( test_tx_count() == wire + 1 );
    CHECK( test_tx_at(wire)->len == 4000 );
    ack_fid(PEER_A, fid_of(big, 4000));

    /* 4001..4022: too big to bundle, still plain-tracked */
    fill_payload(big, 4001, 3);
    wire = test_tx_count();
    CHECK( halow_ack_tx(big, 4001, PEER_A) == 0 );
    run_ticks(1, 5);
    CHECK( test_tx_count() == wire + 1 && test_tx_at(wire)->len == 4001 );
    ack_fid(PEER_A, fid_of(big, 4001));

    fill_payload(big, 4022, 4);
    wire = test_tx_count();
    CHECK( halow_ack_tx(big, 4022, PEER_A) == 0 );
    run_ticks(1, 5);
    CHECK( test_tx_count() == wire + 1 && test_tx_at(wire)->len == 4022 );
    ack_fid(PEER_A, fid_of(big, 4022));

    /* over ACK_WIRE_MAX: untracked broadcast, goes out immediately */
    fill_payload(big, 4023, 5);
    wire = test_tx_count();
    CHECK( halow_ack_tx(big, 4023, PEER_A) == 0 );
    CHECK( test_tx_count() == wire + 1 );
    CHECK( test_tx_last()->len == 4023 );

    fill_payload(big, 65535, 6);
    wire = test_tx_count();
    CHECK( halow_ack_tx(big, 65535, PEER_A) == 0 );
    CHECK( test_tx_count() == wire + 1 );
    CHECK( test_tx_last()->len == 65535 );

    halow_ack_stats_get(&st);
    CHECK( st.outstanding == 0 );
    CHECK( st.tx_frames == 6 );
    CHECK( st.heap_bytes == 0 );
}

static void t_edge_bundle_exact_fit( void ){
    halow_ack_config_t cfg;
    static uint8_t f[4200];

    cfg_base(&cfg);
    cfg.window = 16;
    node_start(&cfg);

    /* 2x2000 == HALOW_ACK_AGG_PAYLOAD_MAX exactly: one legacy bundle,
     * wire = 3 hdr + 2*2 lens + 4000 payload; the second append fills the
     * bundle and it goes out at once -- nothing waits */
    fill_payload(f, 2000, 1);
    CHECK( halow_ack_tx(f, 2000, PEER_A) == 0 );
    CHECK( test_tx_count() == 0 );
    fill_payload(f, 2000, 2);
    CHECK( halow_ack_tx(f, 2000, PEER_A) == 0 );
    CHECK( test_tx_count() == 1 );
    CHECK( test_tx_at(0)->len == 3u + 2u*2u + 2u*2000u );
    CHECK( test_tx_at(0)->buf[0] == 0xA5 && test_tx_at(0)->buf[1] == 0xAD );
    CHECK( test_tx_at(0)->buf[2] == 2 );
    ack_fid(PEER_A, (uint16_t)(fnv1a(test_tx_at(0)->buf, test_tx_at(0)->len) & 0xFFFFu));

    /* envelope peer: same 2x2000 -> env wire = 6 hdr + 4 lens + 4000 = 4010 */
    node_start(&cfg);
    env_peer_ready(PEER_D);
    fill_payload(f, 2000, 3);
    CHECK( halow_ack_tx(f, 2000, PEER_D) == 0 );
    fill_payload(f, 2000, 4);
    CHECK( halow_ack_tx(f, 2000, PEER_D) == 0 );
    run_ticks(1, 5);
    CHECK( test_tx_count() >= 1 );
    {
        const test_tx_cap_t *b = test_tx_at(test_tx_count() - 1);
        CHECK( b->len == 4010 );
        CHECK( b->buf[0] == 0xA5 && b->buf[1] == 0x5A && b->buf[2] == 0x10 );
        CHECK( b->buf[5] == 2 );
    }

    /* 8x500 fills both nsub and payload caps at once: legacy wire 4019 */
    node_start(&cfg);
    for( uint8_t i = 0; i < 8; i++ ){
        fill_payload(f, 500, (uint8_t)(i + 1));
        CHECK( halow_ack_tx(f, 500, PEER_A) == 0 );
    }
    CHECK( test_tx_count() == 1 );
    CHECK( test_tx_at(0)->buf[2] == 8 );
    CHECK( test_tx_at(0)->len == 3u + 2u*8u + 8u*500u );

    /* 2000 + 2001 exceeds the 4000 payload cap: first flushes alone, second
     * rides the next bundle and goes out as a plain single */
    node_start(&cfg);
    fill_payload(f, 2000, 0x21);
    CHECK( halow_ack_tx(f, 2000, PEER_A) == 0 );
    fill_payload(f, 2001, 0x22);
    CHECK( halow_ack_tx(f, 2001, PEER_A) == 0 );
    CHECK( test_tx_count() == 1 );
    run_ticks(1, 5);
    CHECK( test_tx_count() == 2 );
    CHECK( test_tx_at(0)->len == 2000 );
    CHECK( test_tx_at(1)->len == 2001 );
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

/* A bundle stuck staged for ACK_AGG_MAX_HOLD_MS (RF gates closed the whole
 * time) is dropped with drop_throttle -- it must never wedge the peer. */
static void t_edge_staging_timeout( void ){
    halow_ack_config_t cfg;
    halow_ack_stats_t st;
    uint8_t f[100];
    uint16_t fid1;

    cfg_base(&cfg);
    cfg.window = 1;
    cfg.timeout_ms = 300;
    cfg.max_retries = 8;
    node_start(&cfg);

    fill_payload(f, sizeof(f), 1);
    CHECK( halow_ack_tx(f, sizeof(f), PEER_A) == 0 );
    run_ticks(1, 5);
    CHECK( test_tx_count() == 1 );
    fid1 = fid_of(f, sizeof(f));

    fill_payload(f, sizeof(f), 2);
    CHECK( halow_ack_tx(f, sizeof(f), PEER_A) == 0 );
    CHECK( test_tx_count() == 1 );

    run_ticks(30, 50);

    halow_ack_stats_get(&st);
    CHECK( st.drop_throttle == 1 );
    CHECK( st.dropped == 1 );
    CHECK( st.drop_deadline == 0 );

    ack_fid(PEER_A, fid1);
    halow_ack_stats_get(&st);
    CHECK( st.outstanding == 0 );
    CHECK( st.heap_bytes == 0 );

    /* window free again: the peer takes traffic immediately */
    {
        int wire = test_tx_count();
        fill_payload(f, sizeof(f), 3);
        CHECK( halow_ack_tx(f, sizeof(f), PEER_A) == 0 );
        run_ticks(1, 5);
        CHECK( test_tx_count() == wire + 1 );
    }
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

/* ============ full path: TCP bytes -> SLIP -> RNS -> bundle -> air ============ */

#include "halow_pkg_handler.h"
#include "rns/stream_parser.h"
#include "rns/link_db.h"
#include "rns/link_parser.h"

static rns_stream_decoder_t g_dec;

static int32_t fp_frame_cb( uint8_t *payload, uint16_t len, void *user ){
    (void)user;
    return halow_pkg_handler_tcp_to_rf(payload, len);
}

static void fp_node_start( const halow_ack_config_t *cfg ){
    test_time_reset();
    configdb_reset();
    test_tx_reset();
    test_tcp_reset();
    test_vacancy_set(100000);
    test_malloc_reset();
    rns_mtu_limit_set(500);
    rns_stream_decoder_init(&g_dec, fp_frame_cb);
    halow_pkg_handler_init();
    if( cfg != NULL ) halow_ack_config_apply(cfg);
}

static int32_t fp_feed( const uint8_t *data, uint16_t len, uint16_t *consumed ){
    return rns_stream_decoder_process(&g_dec, data, len, NULL, consumed);
}

static void fp_idle( void ){
    halow_ack_flush();
}

/* type-1 RNS packet: [flags][hops][dest_hash16][context] payload
 * flags = hdr(0)<<6 | dest_type<<2 | packet_type; the dest hash IS the
 * link id: one dest_seed per link, payload_seed varies per packet */
static uint16_t rns_pkt_build( uint8_t *out, uint8_t dest_seed, uint8_t payload_seed,
                               uint16_t payload_len,
                               uint8_t packet_type, uint8_t dest_type ){
    uint16_t total = (uint16_t)(2 + 16 + 1 + payload_len);
    out[0] = (uint8_t)((dest_type << 2) | packet_type);
    out[1] = 1;
    memset(&out[2], dest_seed, 16);
    out[18] = 0;
    fill_payload(&out[19], payload_len, payload_seed);
    return total;
}

/* LINKREQUEST with the MTU signalling field at payload+64 */
static uint16_t rns_lr_build( uint8_t *out, uint8_t seed, uint32_t mtu ){
    uint16_t payload_len = 96;
    uint32_t off = 19u + 64u;
    uint32_t sig = mtu & 0x1FFFFFu;
    (void)rns_pkt_build(out, seed, seed, payload_len, RNS_PACKET_TYPE_LINKREQUEST,
                        RNS_DESTINATION_TYPE_SINGLE);
    out[off]     = (uint8_t)(sig >> 16);
    out[off + 1] = (uint8_t)(sig >> 8);
    out[off + 2] = (uint8_t)sig;
    return (uint16_t)(19 + payload_len);
}

static uint32_t rns_lr_mtu_of( const uint8_t *pkt, uint16_t len ){
    uint32_t off = (uint32_t)len - 96u + 64u;
    return ( (uint32_t)pkt[off] << 16 ) | ( (uint32_t)pkt[off + 1] << 8 ) | pkt[off + 2];
}

static uint16_t slip_encode( uint8_t *out, const uint8_t *pkt, uint16_t len ){
    uint16_t n = 0;
    out[n++] = 0x7E;
    for( uint16_t i = 0; i < len; i++ ){
        if( pkt[i] == 0x7E || pkt[i] == 0x7D ){
            out[n++] = 0x7D;
            out[n++] = (uint8_t)(pkt[i] ^ 0x20);
        }else{
            out[n++] = pkt[i];
        }
    }
    out[n++] = 0x7E;
    return n;
}

#define SLIDEC_MAX_FRAMES 320
#define SLIDEC_MAX_LEN    2060

typedef struct {
    uint8_t buf[SLIDEC_MAX_FRAMES][SLIDEC_MAX_LEN];
    uint16_t len[SLIDEC_MAX_FRAMES];
    int n;
    int in_frame;
    int esc;
    uint16_t pos;
} slipdec_t;

static void slipdec_init( slipdec_t *d ){
    memset(d, 0, sizeof(*d));
}

static void slipdec_feed( slipdec_t *d, const uint8_t *data, uint16_t len ){
    for( uint16_t i = 0; i < len; i++ ){
        uint8_t b = data[i];
        if( b == 0x7E ){
            if( d->in_frame && d->pos > 0 && d->n < SLIDEC_MAX_FRAMES )
                d->len[d->n++] = d->pos;
            d->in_frame = 1;
            d->esc = 0;
            d->pos = 0;
            continue;
        }
        if( !d->in_frame ) continue;
        if( d->esc ){
            b ^= 0x20;
            d->esc = 0;
        }else if( b == 0x7D ){
            d->esc = 1;
            continue;
        }
        if( d->pos < SLIDEC_MAX_LEN ) d->buf[d->n][d->pos++] = b;
    }
}

/* split a captured wire frame into its RNS sub-packets (plain = itself) */
static int wire_subs( const test_tx_cap_t *t, const uint8_t *subs[8], uint16_t lens[8] ){
    if( t->len >= 4 && t->buf[0] == 0xA5 && t->buf[1] == 0xAD && t->buf[2] >= 2 ){
        int n = 0;
        uint32_t off = 3;
        for( uint8_t i = 0; i < t->buf[2] && n < 8; i++ ){
            uint16_t sl = (uint16_t)(t->buf[off] | ((uint16_t)t->buf[off + 1] << 8));
            subs[n] = &t->buf[off + 2];
            lens[n] = sl;
            n++;
            off += 2u + sl;
        }
        return n;
    }
    if( t->len >= 8 && t->buf[0] == 0xA5 && t->buf[1] == 0x5A &&
        t->buf[2] == 0x10 && (t->buf[2] & 0x0F) == 0 ){
        int n = 0;
        uint32_t off = 6;
        for( uint8_t i = 0; i < t->buf[5] && n < 8; i++ ){
            uint16_t sl = (uint16_t)(t->buf[off] | ((uint16_t)t->buf[off + 1] << 8));
            subs[n] = &t->buf[off + 2];
            lens[n] = sl;
            n++;
            off += 2u + sl;
        }
        return n;
    }
    subs[0] = t->buf;
    lens[0] = t->len;
    return 1;
}

static void fp_ack_all_pending( void ){
    for( int i = 0; i < test_tx_count(); i++ ){
        const test_tx_cap_t *t = test_tx_at(i);
        if( t == NULL ) continue;
        if( memcmp(t->mac, mac_broadcast, 6) == 0 ) continue;
        if( halow_ack_is_internal_frame(t->buf, t->len) ) continue;
        ack_fid(t->mac, (uint16_t)(fnv1a(t->buf, t->len) & 0xFFFFu));
    }
}

/* the tcps loop: feed bytes, on THROTTLE stop exactly where consumed says,
 * free ACK slots and retry the held frame -- no byte fed twice, none lost */
static void fp_pump( const uint8_t *data, uint16_t len ){
    uint32_t off = 0;
    int guard = 0;
    while( off < len ){
        uint16_t consumed = 0;
        int32_t r = fp_feed(&data[off], (uint16_t)(len - off), &consumed);
        if( r != HALOW_ACK_TX_THROTTLE ){
            off += (consumed != 0u) ? consumed : (uint16_t)(len - off);
            continue;
        }
        if( consumed != 0u ){
            off += consumed;
            continue;
        }
        if( rns_stream_decoder_retry_held(&g_dec, NULL) != HALOW_ACK_TX_THROTTLE ){
            off += 0;
            continue;
        }
        CHECK( ++guard < 2000 );
        run_ticks(2, 5);
        fp_ack_all_pending();
    }
    fp_ack_all_pending();
}

static void t_fp_single_broadcast_learn( void ){
    halow_ack_config_t cfg;
    static uint8_t pkt[300];
    static uint8_t stream[700];
    uint16_t plen, wlen;
    uint16_t consumed = 0;
    slipdec_t dec;

    cfg_base(&cfg);
    fp_node_start(&cfg);

    plen = rns_pkt_build(pkt, 0x42, 0x42, 200, RNS_PACKET_TYPE_DATA, RNS_DESTINATION_TYPE_LINK);
    wlen = slip_encode(stream, pkt, plen);

    CHECK( fp_feed(stream, wlen, &consumed) == 0 );
    CHECK( consumed == wlen );
    CHECK( test_tx_count() == 1 );
    {
        const test_tx_cap_t *t = test_tx_at(0);
        CHECK( t->len == plen );
        CHECK( memcmp(t->buf, pkt, plen) == 0 );
        CHECK( memcmp(t->mac, mac_broadcast, 6) == 0 );
    }

    /* peer receives it: exact packet comes back out on the TCP side */
    slipdec_init(&dec);
    halow_pkg_handler_rf_to_tcp((uint8_t *)test_tx_at(0)->buf, test_tx_at(0)->len,
                                PEER_A, MAC_ME, EVM_M10);
    CHECK( test_tcp_count() == 1 );
    slipdec_feed(&dec, test_tcp_at(0)->buf, test_tcp_at(0)->len);
    CHECK( dec.n == 1 );
    CHECK( dec.len[0] == plen );
    CHECK( memcmp(dec.buf[0], pkt, plen) == 0 );

    /* link learned the peer: the next packet goes unicast, gets staged */
    test_tx_reset();
    CHECK( fp_feed(stream, wlen, &consumed) == 0 );
    CHECK( test_tx_count() == 0 );
    fp_idle();
    CHECK( test_tx_count() == 1 );
    CHECK( memcmp(test_tx_at(0)->mac, PEER_A, 6) == 0 );
    CHECK( test_tx_at(0)->len == plen );
}

static void t_fp_stream_framing_edges( void ){
    halow_ack_config_t cfg;
    static uint8_t pkt[220];
    static uint8_t stream[600];
    uint16_t plen, wlen;
    uint16_t consumed = 0;

    cfg_base(&cfg);
    fp_node_start(&cfg);

    /* payload stuffed with both special bytes */
    plen = rns_pkt_build(pkt, 0x7E, 0x7E, 190, RNS_PACKET_TYPE_DATA, RNS_DESTINATION_TYPE_LINK);
    for( uint16_t i = 19; i < plen; i += 2 ) pkt[i] = (uint8_t)((i & 1) ? 0x7E : 0x7D);
    wlen = slip_encode(stream, pkt, plen);

    /* leading garbage is skipped, an empty frame (FLAG FLAG) is ignored */
    {
        static uint8_t noisy[640];
        uint16_t n = 0;
        noisy[n++] = 'X'; noisy[n++] = 0x7D; noisy[n++] = 0x7E;
        noisy[n++] = 0x7E; noisy[n++] = 0x7E;      /* empty frame */
        memcpy(&noisy[n], stream, wlen);
        n += wlen;
        noisy[n++] = 0x7E;                          /* trailing flag */
        wlen = n;
        memcpy(stream, noisy, n);
    }

    /* byte-by-byte feed: reassembly across arbitrarily split chunks */
    for( uint16_t i = 0; i < wlen; i++ ){
        CHECK( fp_feed(&stream[i], 1, &consumed) == 0 );
        CHECK( consumed == 1 );
    }
    fp_idle();
    CHECK( test_tx_count() == 1 );
    {
        const uint8_t *subs[8];
        uint16_t lens[8];
        const test_tx_cap_t *t = test_tx_at(0);
        CHECK( wire_subs(t, subs, lens) == 1 );
        CHECK( lens[0] == plen );
        CHECK( memcmp(subs[0], pkt, plen) == 0 );
    }
}

static void t_fp_mtu_clamp( void ){
    halow_ack_config_t cfg;
    static uint8_t pkt[200];
    static uint8_t stream[500];
    uint16_t plen, wlen, consumed = 0;
    rns_link_db_link_t link;
    rns_link_packet_info_t info;
    uint8_t link_id[16];

    cfg_base(&cfg);
    fp_node_start(&cfg);

    /* advertise 1280 -> clamped to the 500 limit on the wire */
    plen = rns_lr_build(pkt, 0x77, 1280);
    wlen = slip_encode(stream, pkt, plen);
    CHECK( fp_feed(stream, wlen, &consumed) == 0 );
    CHECK( test_tx_count() == 1 );
    CHECK( rns_lr_mtu_of(test_tx_at(0)->buf, test_tx_at(0)->len) == 500 );
    CHECK( rns_link_parser_parse(test_tx_at(0)->buf, test_tx_at(0)->len, &info) == RNS_RET_OK );
    CHECK( rns_link_db_link_snapshot_by_id(info.link_id, &link) );
    CHECK( link.effective_mtu == 500 );

    /* under the limit: left untouched */
    test_tx_reset();
    plen = rns_lr_build(pkt, 0x78, 300);
    wlen = slip_encode(stream, pkt, plen);
    CHECK( fp_feed(stream, wlen, &consumed) == 0 );
    CHECK( test_tx_count() == 1 );
    CHECK( rns_lr_mtu_of(test_tx_at(0)->buf, test_tx_at(0)->len) == 300 );

    /* limit raised to 2000: 5000 clamps to 2000, 1280 stays */
    rns_mtu_limit_set(2000);
    test_tx_reset();
    plen = rns_lr_build(pkt, 0x79, 5000);
    wlen = slip_encode(stream, pkt, plen);
    CHECK( fp_feed(stream, wlen, &consumed) == 0 );
    CHECK( test_tx_count() == 1 );
    CHECK( rns_lr_mtu_of(test_tx_at(0)->buf, test_tx_at(0)->len) == 2000 );

    test_tx_reset();
    plen = rns_lr_build(pkt, 0x7A, 1280);
    wlen = slip_encode(stream, pkt, plen);
    CHECK( fp_feed(stream, wlen, &consumed) == 0 );
    CHECK( test_tx_count() == 1 );
    CHECK( rns_lr_mtu_of(test_tx_at(0)->buf, test_tx_at(0)->len) == 1280 );

    (void)link_id;
}

static void t_fp_bundle_glue( void ){
    halow_ack_config_t cfg;
    static uint8_t pkt[8][520];
    static uint8_t stream[8 * 1100];
    uint16_t plen[8];
    uint32_t n = 0;

    cfg_base(&cfg);
    fp_node_start(&cfg);

    /* learn the peer MAC so later packets go unicast */
    plen[0] = rns_pkt_build(pkt[0], 0x33, 0x33, 100, RNS_PACKET_TYPE_DATA, RNS_DESTINATION_TYPE_LINK);
    n = slip_encode(stream, pkt[0], plen[0]);
    {
        uint16_t consumed = 0;
        CHECK( fp_feed(stream, n, &consumed) == 0 );
        fp_idle();
        CHECK( test_tx_count() >= 1 );
        halow_pkg_handler_rf_to_tcp((uint8_t *)test_tx_at(0)->buf, test_tx_at(0)->len,
                                    PEER_A, MAC_ME, EVM_M10);
    }

    /* 8 x 500-B packets in ONE lwip chunk: glued into a single 8-sub wire
     * frame (2*8 lens + 8*500 payload = the 4000-B cap) that leaves the
     * moment it is full -- no waiting for anything */
    test_tx_reset();
    n = 0;
    for( uint8_t i = 0; i < 8; i++ ){
        plen[i] = rns_pkt_build(pkt[i], 0x33, (uint8_t)(0x40 + i), 500 - 19,
                                RNS_PACKET_TYPE_DATA, RNS_DESTINATION_TYPE_LINK);
        CHECK( plen[i] == 500 );
        n += slip_encode(&stream[n], pkt[i], plen[i]);
    }
    {
        uint16_t consumed = 0;
        CHECK( fp_feed(stream, (uint16_t)n, &consumed) == 0 );
        CHECK( consumed == n );
    }
    CHECK( test_tx_count() == 1 );
    {
        const uint8_t *subs[8];
        uint16_t lens[8];
        const test_tx_cap_t *t = test_tx_at(0);
        CHECK( t->buf[0] == 0xA5 && t->buf[1] == 0xAD && t->buf[2] == 8 );
        CHECK( t->len == 3u + 2u*8u + 8u*500u );
        int ns = wire_subs(t, subs, lens);
        CHECK( ns == 8 );
        for( int i = 0; i < ns; i++ ){
            CHECK( lens[i] == plen[i] );
            CHECK( memcmp(subs[i], pkt[i], plen[i]) == 0 );
        }
    }
    fp_idle();
    CHECK( test_tx_count() == 1 );

    /* the bundle holds heap memory until the peer ACKs it */
    {
        halow_ack_stats_t st;
        halow_ack_stats_get(&st);
        CHECK( st.outstanding == 1 );
        CHECK( st.heap_bytes > 4000u );
        fp_ack_all_pending();
        halow_ack_stats_get(&st);
        CHECK( st.outstanding == 0 );
        CHECK( st.heap_bytes == 0 );
    }
}

static void t_fp_partial_bundle_on_idle( void ){
    halow_ack_config_t cfg;
    static uint8_t pkt[3][520];
    static uint8_t stream[3 * 1100];
    uint16_t plen[3];
    uint32_t n = 0;

    cfg_base(&cfg);
    fp_node_start(&cfg);

    plen[0] = rns_pkt_build(pkt[0], 0x33, 0x33, 100, RNS_PACKET_TYPE_DATA, RNS_DESTINATION_TYPE_LINK);
    n = slip_encode(stream, pkt[0], plen[0]);
    {
        uint16_t consumed = 0;
        CHECK( fp_feed(stream, (uint16_t)n, &consumed) == 0 );
        fp_idle();
        CHECK( test_tx_count() >= 1 );
        halow_pkg_handler_rf_to_tcp((uint8_t *)test_tx_at(0)->buf, test_tx_at(0)->len,
                                    PEER_A, MAC_ME, EVM_M10);
    }

    /* 3 packets in one chunk, bundle NOT full: nothing on the air until the
     * TCP side runs dry -- then the incomplete frame goes out immediately */
    test_tx_reset();
    n = 0;
    for( uint8_t i = 0; i < 3; i++ ){
        plen[i] = rns_pkt_build(pkt[i], 0x33, (uint8_t)(0x50 + i), 500 - 19,
                                RNS_PACKET_TYPE_DATA, RNS_DESTINATION_TYPE_LINK);
        CHECK( plen[i] == 500 );
        n += slip_encode(&stream[n], pkt[i], plen[i]);
    }
    {
        uint16_t consumed = 0;
        CHECK( fp_feed(stream, (uint16_t)n, &consumed) == 0 );
        CHECK( consumed == n );
    }
    CHECK( test_tx_count() == 0 );
    fp_idle();
    CHECK( test_tx_count() == 1 );
    {
        const uint8_t *subs[8];
        uint16_t lens[8];
        const test_tx_cap_t *t = test_tx_at(0);
        CHECK( t->buf[2] == 3 );
        int ns = wire_subs(t, subs, lens);
        CHECK( ns == 3 );
        for( int i = 0; i < ns; i++ ){
            CHECK( lens[i] == plen[i] );
            CHECK( memcmp(subs[i], pkt[i], plen[i]) == 0 );
        }
    }
}

static void t_fp_two_x_2000_bundle( void ){
    halow_ack_config_t cfg;
    static uint8_t pkt[3][2100];
    static uint8_t stream[3 * 4200];
    uint16_t plen[3];
    uint32_t n = 0;

    cfg_base(&cfg);
    fp_node_start(&cfg);
    rns_mtu_limit_set(2000);

    plen[0] = rns_pkt_build(pkt[0], 0x60, 0x60, 100, RNS_PACKET_TYPE_DATA, RNS_DESTINATION_TYPE_LINK);
    n = slip_encode(stream, pkt[0], plen[0]);
    {
        uint16_t consumed = 0;
        CHECK( fp_feed(stream, (uint16_t)n, &consumed) == 0 );
        fp_idle();
        CHECK( test_tx_count() >= 1 );
        halow_pkg_handler_rf_to_tcp((uint8_t *)test_tx_at(0)->buf, test_tx_at(0)->len,
                                    PEER_A, MAC_ME, EVM_M10);
    }

    /* MTU 2000: two max-MTU packets ride one frame (4007 wire) and the
     * third overflows the 4000 payload cap -> own plain frame */
    test_tx_reset();
    n = 0;
    for( uint8_t i = 0; i < 3; i++ ){
        plen[i] = rns_pkt_build(pkt[i], 0x60, (uint8_t)(0x61 + i), 2000 - 19,
                                RNS_PACKET_TYPE_DATA, RNS_DESTINATION_TYPE_LINK);
        CHECK( plen[i] == 2000 );
        n += slip_encode(&stream[n], pkt[i], plen[i]);
    }
    {
        uint16_t consumed = 0;
        CHECK( fp_feed(stream, (uint16_t)n, &consumed) == 0 );
    }
    fp_idle();
    CHECK( test_tx_count() == 2 );
    {
        const uint8_t *subs[8];
        uint16_t lens[8];
        const test_tx_cap_t *t = test_tx_at(0);
        CHECK( t->buf[0] == 0xA5 && t->buf[1] == 0xAD && t->buf[2] == 2 );
        CHECK( t->len == 3u + 4u + 2u*plen[0] );
        CHECK( t->len == 4007 );
        CHECK( wire_subs(t, subs, lens) == 2 );
        CHECK( lens[0] == plen[0] && memcmp(subs[0], pkt[0], plen[0]) == 0 );
        CHECK( lens[1] == plen[1] && memcmp(subs[1], pkt[1], plen[1]) == 0 );
        t = test_tx_at(1);
        CHECK( t->len == plen[2] );
        CHECK( memcmp(t->buf, pkt[2], plen[2]) == 0 );
    }
}

static void t_fp_throttle_blast_resume( void ){
    halow_ack_config_t cfg;
    static uint8_t pkt[12][460];
    static uint8_t stream[12 * 950];
    uint16_t plen[12];
    uint32_t n = 0;

    cfg_base(&cfg);
    cfg.window = 2;
    fp_node_start(&cfg);

    plen[0] = rns_pkt_build(pkt[0], 0x90, 0x90, 100, RNS_PACKET_TYPE_DATA, RNS_DESTINATION_TYPE_LINK);
    n = slip_encode(stream, pkt[0], plen[0]);
    {
        uint16_t consumed = 0;
        CHECK( fp_feed(stream, (uint16_t)n, &consumed) == 0 );
        fp_idle();
        CHECK( test_tx_count() >= 1 );
        halow_pkg_handler_rf_to_tcp((uint8_t *)test_tx_at(0)->buf, test_tx_at(0)->len,
                                    PEER_A, MAC_ME, EVM_M10);
        fp_ack_all_pending();
    }

    /* blast 12 frames through a 2-slot window: the decoder holds the frame
     * that got THROTTLE, consumed accounting is exact, nothing is lost or
     * duplicated on the wire */
    test_tx_reset();
    n = 0;
    for( uint8_t i = 0; i < 12; i++ ){
        plen[i] = rns_pkt_build(pkt[i], 0x90, (uint8_t)(0x91 + i), 400,
                                RNS_PACKET_TYPE_DATA, RNS_DESTINATION_TYPE_LINK);
        n += slip_encode(&stream[n], pkt[i], plen[i]);
    }
    fp_pump(stream, (uint16_t)n);
    fp_idle();
    run_ticks(3, 5);
    fp_ack_all_pending();

    {
        int seen[12] = {0};
        int total = 0;
        for( int i = 0; i < test_tx_count(); i++ ){
            const uint8_t *subs[8];
            uint16_t lens[8];
            const test_tx_cap_t *t = test_tx_at(i);
            CHECK( !halow_ack_is_internal_frame(t->buf, t->len) );
            int ns = wire_subs(t, subs, lens);
            for( int s = 0; s < ns; s++ ){
                int matched = -1;
                for( uint8_t k = 0; k < 12; k++ ){
                    if( lens[s] == plen[k] && memcmp(subs[s], pkt[k], plen[k]) == 0 ){
                        matched = k;
                        break;
                    }
                }
                CHECK( matched >= 0 );
                if( matched >= 0 ){
                    CHECK( seen[matched] == 0 );
                    seen[matched] = 1;
                    total++;
                }
            }
        }
        CHECK( total == 12 );
    }

    {
        halow_ack_stats_t st;
        halow_ack_stats_get(&st);
        CHECK( st.outstanding == 0 );
        CHECK( st.dropped == 0 );
        CHECK( st.heap_bytes == 0 );
    }
}

static void t_fp_heap_fail_throttle( void ){
    halow_ack_config_t cfg;
    static uint8_t pkt[300];
    static uint8_t stream[700];
    uint16_t plen, wlen, consumed = 0;
    halow_ack_stats_t st;

    cfg_base(&cfg);
    fp_node_start(&cfg);

    plen = rns_pkt_build(pkt, 0xA0, 0xA0, 200, RNS_PACKET_TYPE_DATA, RNS_DESTINATION_TYPE_LINK);
    wlen = slip_encode(stream, pkt, plen);

    /* first frame learns the peer via RX; ack it so the slot is free */
    CHECK( fp_feed(stream, wlen, &consumed) == 0 );
    fp_idle();
    CHECK( test_tx_count() >= 1 );
    halow_pkg_handler_rf_to_tcp((uint8_t *)test_tx_at(0)->buf, test_tx_at(0)->len,
                                PEER_A, MAC_ME, EVM_M10);
    fp_ack_all_pending();

    /* frame-buffer malloc fails -> THROTTLE, counted, frame held by decoder */
    test_tx_reset();
    test_malloc_fail_next(1);
    consumed = 0;
    CHECK( fp_feed(stream, wlen, &consumed) == HALOW_ACK_TX_THROTTLE );
    halow_ack_stats_get(&st);
    CHECK( st.heap_fail == 1 );
    CHECK( st.tx_frames == 1 );   /* only the warmup frame got through */
    CHECK( test_tx_count() == 0 );

    /* heap recovers: the held frame goes through, bytes are not re-fed */
    test_malloc_reset();
    CHECK( rns_stream_decoder_retry_held(&g_dec, NULL) == 0 );
    fp_idle();
    CHECK( test_tx_count() == 1 );
    CHECK( test_tx_at(0)->len == plen );
    CHECK( memcmp(test_tx_at(0)->buf, pkt, plen) == 0 );
}

static void t_fp_roundtrip_soak( void ){
    halow_ack_config_t cfg;
    enum { N = 250 };
    static uint8_t pkt[N][2100];
    static uint8_t stream[5200];
    static slipdec_t dec;
    uint16_t plen[N];
    uint32_t lcg = 12345u;
    halow_ack_stats_t st;

    cfg_base(&cfg);
    cfg.window = 16;
    fp_node_start(&cfg);
    rns_mtu_limit_set(2000);

    /* packet 0: broadcast warmup (learns the peer MAC on delivery) */
    plen[0] = rns_pkt_build(pkt[0], 0x01, 0x01, 111, RNS_PACKET_TYPE_DATA, RNS_DESTINATION_TYPE_LINK);
    {
        uint16_t consumed = 0;
        uint32_t n = slip_encode(stream, pkt[0], plen[0]);
        CHECK( fp_feed(stream, (uint16_t)n, &consumed) == 0 );
        fp_idle();
        CHECK( test_tx_count() >= 1 );
        halow_pkg_handler_rf_to_tcp((uint8_t *)test_tx_at(0)->buf, test_tx_at(0)->len,
                                    PEER_A, MAC_ME, EVM_M10);
        fp_ack_all_pending();
    }

    slipdec_init(&dec);
    test_tx_reset();
    test_tcp_reset();

    for( int i = 1; i < N; i++ ){
        uint16_t payload = (uint16_t)(60 + (lcg % 1941));
        uint32_t n = 0;
        lcg = lcg * 1103515245u + 12345u;
        plen[i] = rns_pkt_build(pkt[i], 0x01, (uint8_t)i, payload,
                                RNS_PACKET_TYPE_DATA, RNS_DESTINATION_TYPE_LINK);
        n = slip_encode(stream, pkt[i], plen[i]);
        /* random chunk split, like real TCP segments */
        {
            uint32_t off = 0;
            while( off < n ){
                uint32_t chunk = 1 + (lcg % 700);
                uint16_t consumed = 0;
                if( chunk > n - off ) chunk = n - off;
                CHECK( fp_feed(&stream[off], (uint16_t)chunk, &consumed) == 0 );
                CHECK( consumed == chunk );
                off += chunk;
                lcg = lcg * 1103515245u + 12345u;
            }
        }
        fp_idle();
        fp_ack_all_pending();
    }

    /* deliver every DATA wire frame to the peer's TCP side */
    for( int i = 0; i < test_tx_count() && i < TEST_TX_CAP_N; i++ ){
        const test_tx_cap_t *t = test_tx_at(i);
        if( t == NULL || t->len > TEST_TX_CAP_LEN ) continue;
        if( halow_ack_is_internal_frame(t->buf, t->len) ) continue;
        halow_pkg_handler_rf_to_tcp((uint8_t *)t->buf, t->len, PEER_A, MAC_ME, EVM_M10);
    }
    fp_ack_all_pending();

    /* everything sent must come back in order, byte-exact (packet 0 was the
     * pre-reset warmup and is excluded) */
    CHECK( test_tcp_count() >= N - 1 );
    for( int i = 0; i < test_tcp_count(); i++ ){
        slipdec_feed(&dec, test_tcp_at(i)->buf, test_tcp_at(i)->len);
    }
    CHECK( dec.n == N - 1 );
    if( dec.n == N - 1 ){
        for( int i = 1; i < N; i++ ){
            CHECK( dec.len[i - 1] == plen[i] );
            CHECK( memcmp(dec.buf[i - 1], pkt[i], plen[i]) == 0 );
        }
    }

    halow_ack_stats_get(&st);
    CHECK( st.outstanding == 0 );
    CHECK( st.dropped == 0 );
    CHECK( st.drop_throttle == 0 );
    CHECK( st.heap_bytes == 0 );
    CHECK( st.tx_frames == (uint32_t)N );
}

static void t_fp_rx_edge_bundles( void ){
    halow_ack_config_t cfg;
    uint8_t leg_trunc[16] = {0xA5, 0xAD, 0x01, 0x10, 0x00};
    uint8_t leg_tail[14]  = {0xA5, 0xAD, 0x01, 0x02, 0x00, 'H', 'i', 0xFF};
    uint8_t env_short[6]  = {0xA5, 0x5A, 0x10, 0x00, 0x00, 0x00};
    uint8_t env_bad[12]   = {0xA5, 0x5A, 0x10, 0x00, 0x00, 0x02, 0x05, 0x00, 1, 2, 3, 4};
    uint8_t sub[64];
    uint8_t env_ok[6 + 2 + 64];
    uint8_t data[64];
    uint16_t slen;
    halow_ack_stats_t st;

    cfg_base(&cfg);
    fp_node_start(&cfg);
    test_tx_reset();
    test_tcp_reset();

    /* a well-formed env bundle whose sub IS a valid RNS packet */
    slen = rns_pkt_build(sub, 0xB1, 0xB2, 40, RNS_PACKET_TYPE_DATA,
                         RNS_DESTINATION_TYPE_LINK);
    env_ok[0] = 0xA5; env_ok[1] = 0x5A; env_ok[2] = 0x10;
    env_ok[3] = 0x00; env_ok[4] = 0x00; env_ok[5] = 0x01;
    env_ok[6] = (uint8_t)(slen & 0xFF);
    env_ok[7] = (uint8_t)(slen >> 8);
    memcpy(&env_ok[8], sub, slen);

    fill_payload(data, sizeof(data), 1);
    CHECK( rx_frame(PEER_A, data, sizeof(data), 0) );

    /* truncated sub / trailing garbage / short env / bad sub count: no delivery */
    halow_pkg_handler_rf_to_tcp(leg_trunc, sizeof(leg_trunc), PEER_A, MAC_ME, EVM_M10);
    halow_pkg_handler_rf_to_tcp(leg_tail, sizeof(leg_tail), PEER_A, MAC_ME, EVM_M10);
    halow_pkg_handler_rf_to_tcp(env_short, sizeof(env_short), PEER_A, MAC_ME, EVM_M10);
    halow_pkg_handler_rf_to_tcp(env_bad, sizeof(env_bad), PEER_A, MAC_ME, EVM_M10);
    CHECK( test_tcp_count() == 0 );

    halow_ack_stats_get(&st);
    CHECK( st.rx_env_unk >= 1 );

    /* well-formed env bundle with one sub delivers exactly the sub */
    halow_pkg_handler_rf_to_tcp(env_ok, (uint16_t)(8 + slen), PEER_A, MAC_ME, EVM_M10);
    CHECK( test_tcp_count() == 1 );
    {
        slipdec_t dec;
        slipdec_init(&dec);
        slipdec_feed(&dec, test_tcp_at(0)->buf, test_tcp_at(0)->len);
        CHECK( dec.n == 1 );
        CHECK( dec.len[0] == slen );
        CHECK( memcmp(dec.buf[0], sub, slen) == 0 );
    }

    /* retransmitted bundle is deduped: delivered exactly once */
    halow_pkg_handler_rf_to_tcp(env_ok, (uint16_t)(8 + slen), PEER_A, MAC_ME, EVM_M10);
    CHECK( test_tcp_count() == 1 );
}

static void t_fp_tcp_ring_full( void ){
    halow_ack_config_t cfg;
    uint8_t pkt[80];

    cfg_base(&cfg);
    fp_node_start(&cfg);

    fill_payload(pkt, sizeof(pkt), 9);
    test_tcp_full_set(1);
    halow_pkg_handler_rf_to_tcp(pkt, sizeof(pkt), PEER_A, MAC_ME, EVM_M10);
    CHECK( test_tcp_count() == 0 );
    CHECK( g_tx_dbg.rf_tcp_dropped == 1 );
    test_tcp_full_set(0);
    fill_payload(pkt, sizeof(pkt), 10);   /* different frame: dedup must not eat it */
    halow_pkg_handler_rf_to_tcp(pkt, sizeof(pkt), PEER_A, MAC_ME, EVM_M10);
    CHECK( test_tcp_count() == 1 );
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
        {"throttle_staging_drain",      t_throttle_staging_drain},
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
        {"edge_staging_timeout",        t_edge_staging_timeout},
        {"edge_ack_hold_extremes",      t_edge_ack_hold_extremes},
        {"edge_env_bundle_nsub_zero",   t_edge_env_bundle_nsub_zero},
        {"edge_stale_reheard_compat_reset", t_edge_stale_reheard_compat_reset},
        {"edge_vacancy_flap",           t_edge_vacancy_flap},
        {"edge_rapid_reconfig",         t_edge_rapid_reconfig},
        {"fp_single_broadcast_learn",   t_fp_single_broadcast_learn},
        {"fp_stream_framing_edges",     t_fp_stream_framing_edges},
        {"fp_mtu_clamp",                t_fp_mtu_clamp},
        {"fp_bundle_glue",              t_fp_bundle_glue},
        {"fp_partial_bundle_on_idle",   t_fp_partial_bundle_on_idle},
        {"fp_two_x_2000_bundle",        t_fp_two_x_2000_bundle},
        {"fp_throttle_blast_resume",    t_fp_throttle_blast_resume},
        {"fp_heap_fail_throttle",       t_fp_heap_fail_throttle},
        {"fp_roundtrip_soak",           t_fp_roundtrip_soak},
        {"fp_rx_edge_bundles",          t_fp_rx_edge_bundles},
        {"fp_tcp_ring_full",            t_fp_tcp_ring_full},
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
