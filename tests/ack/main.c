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

    for( uint8_t i = 0; i < 4; i++ ){
        fill_payload(f, sizeof(f), i);
        CHECK( halow_ack_tx(f, sizeof(f), PEER_A) == 0 );
    }
    fill_payload(f, sizeof(f), 9);
    CHECK( halow_ack_tx(f, sizeof(f), PEER_A) == HALOW_ACK_TX_THROTTLE );
    CHECK( test_tx_count() == 0 );

    test_vacancy_set(100000);
    run_ticks(3, 5);
    CHECK( test_tx_count() == 2 );
    CHECK( test_tx_at(0)->buf[0] == 0xA5 && test_tx_at(0)->buf[1] == 0xAD );
    CHECK( test_tx_at(0)->buf[2] == 2 );
    CHECK( test_tx_at(1)->buf[2] == 2 );

    halow_ack_stats_get(&st);
    CHECK( st.dropped == 0 );
    CHECK( st.drop_throttle == 0 );
    CHECK( st.outstanding == 2 );
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
    CHECK( halow_ack_tx(f, sizeof(f), m) == 0 );
    CHECK( halow_ack_tx(f, sizeof(f), m) == 0 );
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

int main( void ){
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
