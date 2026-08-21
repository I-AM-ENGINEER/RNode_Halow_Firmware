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

void t_soak_fid_roundtrip( void ){
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

void t_soak_bundle_delayed_ack( void ){
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

void t_soak_lossy_exhaust( void ){
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

void t_soak_bidir_two_peers( void ){
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

void t_soak_multipeer_pressure( void ){
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

void t_soak_window_one_serial( void ){
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

