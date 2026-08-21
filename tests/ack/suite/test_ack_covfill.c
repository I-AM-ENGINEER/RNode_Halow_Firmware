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

void t_cov_ack_misc( void ){
    halow_ack_config_t cfg, live;
    halow_ack_stats_t st;
    const uint8_t *o = NULL;
    uint16_t ol = 0;

    node_start(NULL);

    /* radio_quiet / link_busy transitions (fresh boot: quiet) */
    CHECK( halow_ack_radio_quiet() );
    CHECK( !halow_ack_link_busy() );
    {
        uint8_t f[64];
        fill_payload(f, sizeof(f), 1);
        CHECK( halow_ack_tx(f, sizeof(f), PEER_A) == 0 );
        CHECK( !halow_ack_radio_quiet() );
        CHECK( halow_ack_link_busy() );
        run_ticks(2, 5);
        CHECK( !halow_ack_radio_quiet() );   /* outstanding buf */
        ack_fid(PEER_A, fid_of(f, sizeof(f)));
        {
            halow_ack_stats_t dbg;
            halow_ack_stats_get(&dbg);
        }
        {
            halow_ack_stats_t dbg;
            halow_ack_stats_get(&dbg);
        }
        CHECK( halow_ack_link_busy() );      /* recent TX window still open */
        test_advance_ms(10000);
        CHECK( !halow_ack_link_busy() );
        CHECK( halow_ack_radio_quiet() );
    }

    /* on_rx argument guards */
    CHECK( halow_ack_on_rx(NULL, 5, PEER_A, MAC_ME, 0, &o, &ol) );
    o = NULL; ol = 0;
    CHECK( halow_ack_on_rx((const uint8_t *)"x", 1, PEER_A, MAC_ME, 0, NULL, &ol) );
    o = NULL; ol = 0;
    CHECK( halow_ack_on_rx((const uint8_t *)"x", 1, PEER_A, MAC_ME, 0, &o, NULL) );

    /* config_load happy path: version matches -> keys are read back */
    test_kv_set("cfg.hack.ver", 4);
    test_kv_set("cfg.hack.tmo", 33);
    test_kv_set("cfg.hack.aggbytes", 1000);
    test_kv_set("cfg.hack.ra", 0);
    halow_ack_config_load(&cfg);
    CHECK( cfg.timeout_ms == 33 );
    CHECK( cfg.agg_bytes == 1000 );
    halow_ack_config_apply(&cfg);
    halow_ack_config_get_live(&live);
    CHECK( live.agg_bytes == 1000 );

    /* apply with RA on converts DEFAULT-mcs peers to the RA start rate */
    {
        halow_ack_peer_stats_t ps;
        uint8_t f[32];
        fill_payload(f, sizeof(f), 2);
        CHECK( rx_frame(PEER_B, f, sizeof(f), EVM_M10) );
        cfg.rate_adapt = 1;
        halow_ack_config_apply(&cfg);
        CHECK( halow_ack_peer_stats_by_mac(PEER_B, &ps) && ps.tx_mcs == 7 );
    }

    /* zero-length payload: single-sub unwrap rejects the empty sub */
    {
        uint8_t f[8];
        CHECK( halow_ack_tx(f, 0, PEER_A) == 0 );
        halow_ack_flush();
        halow_ack_stats_get(&st);
        CHECK( st.dropped >= 1 );
        CHECK( st.heap_bytes == 0 );
    }
}

void t_cov_ra_walk_and_stale( void ){
    halow_ack_config_t cfg;
    halow_ack_peer_stats_t ps;
    halow_ack_stats_t st;
    uint8_t ack[5];
    uint8_t data[16];

    cfg_base(&cfg);
    cfg.rate_adapt = 1;
    node_start(&cfg);

    fill_payload(data, sizeof(data), 1);
    CHECK( rx_frame(PEER_R, data, sizeof(data), EVM_M10) );
    CHECK( halow_ack_peer_stats_by_mac(PEER_R, &ps) && ps.tx_mcs == 4 );

    /* walk MCS 4 -> 5 -> 6 -> 7 one step per gap */
    for( int m = 5; m <= 7; m++ ){
        test_advance_ms(300);
        rx_ack_frame(PEER_R, ack, build_legacy_ack(ack, EVM_M10, 0));
        CHECK( halow_ack_peer_stats_by_mac(PEER_R, &ps) && ps.tx_mcs == (uint8_t)m );
    }

    /* stale peer (no ACK for > RA_STALE) resets to the EVM ceiling on tick */
    test_advance_ms(61000);
    halow_ack_tick();
    CHECK( halow_ack_peer_stats_by_mac(PEER_R, &ps) );
    CHECK( ps.tx_mcs == 7 );
    halow_ack_stats_get(&st);
    CHECK( st.outstanding == 0 );
}

void t_cov_slot_exhaust_untracked( void ){
    halow_ack_config_t cfg;
    halow_ack_stats_t st;
    uint8_t m[6];
    uint8_t f[100];

    cfg_base(&cfg);
    cfg.agg = 0;
    cfg.window = 16;
    node_start(&cfg);

    /* 16 peers, one in-flight frame each */
    for( uint8_t id = 1; id <= 16; id++ ){
        peer_mac(m, id);
        fill_payload(f, sizeof(f), id);
        CHECK( halow_ack_tx(f, sizeof(f), m) == 0 );
    }
    CHECK( test_tx_count() == 16 );

    /* 17th peer: no slot, no eviction candidate (all protected) -> the
     * frame still leaves, untracked (no retry slot, counted as TX) */
    peer_mac(m, 0x71);
    fill_payload(f, sizeof(f), 0x71);
    CHECK( halow_ack_tx(f, sizeof(f), m) == 0 );
    CHECK( test_tx_count() == 17 );
    CHECK( test_tx_last()->len == 100 );

    halow_ack_stats_get(&st);
    CHECK( st.outstanding == 16 );
    CHECK( st.tx_frames == 17 );
    CHECK( st.heap_bytes > 0 );
}

void t_cov_ack_tx_fail( void ){
    halow_ack_config_t cfg;
    halow_ack_stats_t st;
    uint8_t f[100];

    cfg_base(&cfg);
    cfg.bc_repeat = 2;
    node_start(&cfg);

    /* fid-ACK TX fails */
    fill_payload(f, sizeof(f), 1);
    CHECK( rx_frame(PEER_E, f, sizeof(f), EVM_M10) );
    test_tx_reset();
    test_tx_fail_next(1);
    fill_payload(f, sizeof(f), 2);
    CHECK( rx_frame(PEER_E, f, sizeof(f), EVM_M10) );
    halow_ack_stats_get(&st);
    CHECK( st.acks_tx_fail == 1 );

    /* broadcast with failing radio -> THROTTLE to the caller */
    fill_payload(f, sizeof(f), 3);
    test_tx_fail_next(1);
    CHECK( halow_ack_tx(f, sizeof(f), mac_broadcast) == HALOW_ACK_TX_THROTTLE );

    /* env-ACK TX fails */
    {
        halow_ack_peer_stats_t ps;
        env_peer_ready(PEER_D);
        CHECK( halow_ack_peer_stats_by_mac(PEER_D, &ps) && ps.compat == 2 );
        test_tx_fail_next(1);
        fill_payload(f, sizeof(f), 4);
        CHECK( rx_frame(PEER_D, f, sizeof(f), EVM_M10) );
        halow_ack_stats_get(&st);
        CHECK( st.acks_tx_fail == 2 );
    }
}

void t_cov_env_seq_jump( void ){
    halow_ack_config_t cfg;
    halow_ack_stats_t st;
    uint8_t sub[64];
    uint8_t env[6 + 2 + 64];
    uint16_t slen;

    cfg_base(&cfg);
    node_start(&cfg);
    env_peer_ready(PEER_D);

    slen = rns_pkt_build(sub, 0xD1, 0xD2, 40, RNS_PACKET_TYPE_DATA,
                         RNS_DESTINATION_TYPE_LINK);
    for( uint16_t seq = 0; seq < 300; seq += 100 ){
        env[0] = 0xA5; env[1] = 0x5A; env[2] = 0x10;
        env[3] = (uint8_t)(seq & 0xFF);
        env[4] = (uint8_t)(seq >> 8);
        env[5] = 1;
        env[6] = (uint8_t)(slen & 0xFF);
        env[7] = (uint8_t)(slen >> 8);
        memcpy(&env[8], sub, slen);
        CHECK( rx_frame(PEER_D, env, (uint16_t)(8 + slen), 0) );
    }
    halow_ack_stats_get(&st);
    CHECK( st.env_rx_bundles == 4 );   /* ready probe + 3 jumps (>= 64 resets) */
}

void t_cov_gap_fill( void ){
    halow_ack_config_t cfg;
    static uint8_t pkt[3][520];
    static uint8_t stream[1100];
    uint16_t plen[3];
    uint16_t consumed = 0;
    rns_link_packet_info_t info;

    cfg_base(&cfg);
    cfg.agg = 0;
    cfg.window = 1;
    fp_node_start(&cfg);

    /* learn the peer, then keep one frame in flight so the next THROTTLEs */
    plen[0] = rns_pkt_build(pkt[0], 0xB5, 0xB5, 300, RNS_PACKET_TYPE_DATA, RNS_DESTINATION_TYPE_LINK);
    CHECK( fp_feed(stream, slip_encode(stream, pkt[0], plen[0]), &consumed) == 0 );
    fp_idle();
    CHECK( test_tx_count() == 1 );
    halow_pkg_handler_rf_to_tcp((uint8_t *)test_tx_at(0)->buf, test_tx_at(0)->len,
                                PEER_A, MAC_ME, EVM_M10);

    plen[1] = rns_pkt_build(pkt[1], 0xB5, 0xB6, 300, RNS_PACKET_TYPE_DATA, RNS_DESTINATION_TYPE_LINK);
    {
        uint16_t w = slip_encode(stream, pkt[1], plen[1]);
        CHECK( fp_feed(stream, w, &consumed) == 0 );   /* frame 2 in flight */
    }

    /* frame 3 fills the window -> THROTTLE, frame held in the decoder */
    plen[2] = rns_pkt_build(pkt[2], 0xB5, 0xB7, 300, RNS_PACKET_TYPE_DATA, RNS_DESTINATION_TYPE_LINK);
    {
        uint16_t w = slip_encode(stream, pkt[2], plen[2]);
        CHECK( fp_feed(stream, w, &consumed) == HALOW_ACK_TX_THROTTLE );
        CHECK( consumed == w );
    }

    /* explicit retry while still saturated: THROTTLE again */
    CHECK( rns_stream_decoder_retry_held(&g_dec, NULL) == HALOW_ACK_TX_THROTTLE );

    /* feeding NEW bytes retries the held frame first: THROTTLE, consumed 0 */
    {
        uint8_t one = 0x7E;
        CHECK( fp_feed(&one, 1, &consumed) == HALOW_ACK_TX_THROTTLE );
        CHECK( consumed == 0 );
    }

    /* free the window: the held frame goes through on retry, no re-feed */
    ack_fid(PEER_A, (uint16_t)(fnv1a(pkt[1], plen[1]) & 0xFFFFu));
    CHECK( rns_stream_decoder_retry_held(&g_dec, NULL) == 0 );
    fp_idle();
    fp_idle();
    {
        halow_ack_stats_t st;
        halow_ack_stats_get(&st);
        CHECK( st.dropped == 0 );
        CHECK( st.tx_frames == 3 );
    }

    /* type-2 LINKREQUEST: sha256 link id over the type-2 hash body */
    {
        uint8_t lr[140];
        uint16_t l = rns_lr_build(lr, 0xB8, 1280);
        lr[0] |= 0x40;
        memmove(&lr[35], &lr[19], (size_t)(l - 19));
        memcpy(&lr[19], lr, 16);
        lr[34] = 0;
        CHECK( rns_link_parser_parse(lr, l, &info) == RNS_RET_OK );
        CHECK( info.valid );
        CHECK( info.context == RNS_CONTEXT_NONE );
    }

    /* link_db: NULL guard, PROOF state machine, LR state on TX */
    {
        rns_link_db_link_t link;
        uint8_t p[140];
        uint16_t l;
        CHECK( rns_link_db_package_register(NULL, RNS_PACKET_DIRECTION_RX, NULL, 0, false, false)
               == RNS_RET_NULLPTR );
        /* PROOF packet on a fresh link -> PROOF_RECEIVED */
        l = rns_pkt_build(p, 0xB9, 0xB9, 100, RNS_PACKET_TYPE_PROOF, RNS_DESTINATION_TYPE_SINGLE);
        CHECK( rns_link_parser_parse(p, l, &info) == RNS_RET_OK );
        CHECK( rns_link_db_package_register(&info, RNS_PACKET_DIRECTION_RX, PEER_A, 0, false, true) == RNS_RET_OK );
        CHECK( rns_link_db_link_snapshot_by_id(info.link_id, &link) );
        CHECK( link.state == RNS_LINK_STATE_PROOF_RECEIVED );
        /* context LINKPROOF reaches the same state on another fresh link */
        l = rns_pkt_build(p, 0xBA, 0xBA, 100, RNS_PACKET_TYPE_DATA, RNS_DESTINATION_TYPE_LINK);
        p[18] = (uint8_t)RNS_CONTEXT_LINKPROOF;
        CHECK( rns_link_parser_parse(p, l, &info) == RNS_RET_OK );
        CHECK( rns_link_db_package_register(&info, RNS_PACKET_DIRECTION_RX, PEER_A, 0, false, true) == RNS_RET_OK );
        CHECK( rns_link_db_link_snapshot_by_id(info.link_id, &link) );
        CHECK( link.state == RNS_LINK_STATE_PROOF_RECEIVED );
        /* LINK-dest data opens a fresh link */
        l = rns_pkt_build(p, 0xBB, 0xBB, 100, RNS_PACKET_TYPE_DATA, RNS_DESTINATION_TYPE_LINK);
        CHECK( rns_link_parser_parse(p, l, &info) == RNS_RET_OK );
        CHECK( rns_link_db_package_register(&info, RNS_PACKET_DIRECTION_RX, PEER_A, 0, false, true) == RNS_RET_OK );
        CHECK( rns_link_db_link_snapshot_by_id(info.link_id, &link) );
        CHECK( link.state == RNS_LINK_STATE_OPEN );
    }
}

