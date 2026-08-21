#include "sys_config.h"
#define LOG_LOCAL_LEVEL LOG_LEVEL_HALOW_PKG_HANDLER
#include "basic_include.h"
#include "lib/logc/log.h"
#include "halow.h"
#include "utils.h"
#include "halow_ack.h"
#include "tcp_server.h"
#include "harness.h"
#include "halow_pkg_handler.h"
#include "rns/stream_parser.h"
#include "rns/link_db.h"
#include "rns/link_parser.h"
#include "rns/link_utils.h"

#include <stdio.h>
#include <string.h>
#include "helpers.h"
#include "test_fw.h"

void t_edge_frame_size_boundaries( void ){
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

void t_edge_bundle_exact_fit( void ){
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

void t_edge_seq_rollover( void ){
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

void t_edge_backoff_exact_timing( void ){
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

void t_edge_ack_len_parity( void ){
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

void t_edge_fid_zero_and_ack_storm( void ){
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

void t_edge_blockack_bitmap_extremes( void ){
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
void t_edge_staging_timeout( void ){
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

void t_edge_ack_hold_extremes( void ){
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

void t_edge_env_bundle_nsub_zero( void ){
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

void t_edge_stale_reheard_compat_reset( void ){
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

void t_edge_vacancy_flap( void ){
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

void t_edge_rapid_reconfig( void ){
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


