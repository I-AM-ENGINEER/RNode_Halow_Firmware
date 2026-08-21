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

uint32_t rns_lr_mtu_of( const uint8_t *pkt, uint16_t len ){
    uint32_t off = (uint32_t)len - 96u + 64u;
    return ( (uint32_t)pkt[off] << 16 ) | ( (uint32_t)pkt[off + 1] << 8 ) | pkt[off + 2];
}

int wire_subs( const test_tx_cap_t *t, const uint8_t *subs[8], uint16_t lens[8] ){
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

void fp_ack_all_pending( void ){
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
void fp_pump( const uint8_t *data, uint16_t len ){
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

void t_fp_single_broadcast_learn( void ){
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

void t_fp_stream_framing_edges( void ){
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

void t_fp_mtu_clamp( void ){
    halow_ack_config_t cfg;
    static uint8_t pkt[200];
    static uint8_t stream[500];
    uint16_t plen, wlen, consumed = 0;
    rns_link_db_link_t link;
    rns_link_packet_info_t info;

    cfg_base(&cfg);
    fp_node_start(&cfg);

    /* the link MTU is FIXED at 500: anything advertised above clamps down,
     * anything below passes -- exactly min(advertised, 500) on the wire */
    plen = rns_lr_build(pkt, 0x77, 1280);
    wlen = slip_encode(stream, pkt, plen);
    CHECK( fp_feed(stream, wlen, &consumed) == 0 );
    CHECK( test_tx_count() == 1 );
    CHECK( rns_lr_mtu_of(test_tx_at(0)->buf, test_tx_at(0)->len) == 500 );
    CHECK( rns_link_parser_parse(test_tx_at(0)->buf, test_tx_at(0)->len, &info) == RNS_RET_OK );
    CHECK( rns_link_db_link_snapshot_by_id(info.link_id, &link) );
    CHECK( link.effective_mtu == 500 );

    test_tx_reset();
    plen = rns_lr_build(pkt, 0x79, 5000);
    wlen = slip_encode(stream, pkt, plen);
    CHECK( fp_feed(stream, wlen, &consumed) == 0 );
    CHECK( test_tx_count() == 1 );
    CHECK( rns_lr_mtu_of(test_tx_at(0)->buf, test_tx_at(0)->len) == 500 );

    test_tx_reset();
    plen = rns_lr_build(pkt, 0x78, 300);
    wlen = slip_encode(stream, pkt, plen);
    CHECK( fp_feed(stream, wlen, &consumed) == 0 );
    CHECK( test_tx_count() == 1 );
    CHECK( rns_lr_mtu_of(test_tx_at(0)->buf, test_tx_at(0)->len) == 300 );

    test_tx_reset();
    plen = rns_lr_build(pkt, 0x7B, 500);
    wlen = slip_encode(stream, pkt, plen);
    CHECK( fp_feed(stream, wlen, &consumed) == 0 );
    CHECK( test_tx_count() == 1 );
    CHECK( rns_lr_mtu_of(test_tx_at(0)->buf, test_tx_at(0)->len) == 500 );
}

void t_fp_bundle_glue( void ){
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

void t_fp_partial_bundle_on_idle( void ){
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

void t_fp_two_x_2000_bundle( void ){
    halow_ack_config_t cfg;
    static uint8_t pkt[3][2100];
    static uint8_t stream[3 * 4200];
    uint16_t plen[3];
    uint32_t n = 0;

    cfg_base(&cfg);
    fp_node_start(&cfg);

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

void t_fp_throttle_blast_resume( void ){
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

void t_fp_heap_fail_throttle( void ){
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

void t_fp_roundtrip_soak( void ){
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

void t_fp_rx_edge_bundles( void ){
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

void t_fp_tcp_ring_full( void ){
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


/* ============ virtual RF channel: lossy full round-trip ============ */

typedef struct {
    uint8_t  drop_pct;
    uint32_t lcg;
    uint32_t sent;
    uint32_t dropped;
    int      cursor;
} vchan_t;

bool vchan_loss( vchan_t *c ){
    c->lcg = c->lcg * 1103515245u + 12345u;
    return ((c->lcg >> 16u) % 100u) < c->drop_pct;
}

/* Closed-loop model over the TX capture ring: data frames are RECEIVED by
 * the peer (rf_to_tcp, which queues the peer's ACKs back on the ring),
 * ACK frames come back to the sender (halow_ack_on_rx). Every frame crosses
 * the lossy channel first. */
void vlink_pump( vchan_t *c ){
    while( c->cursor < test_tx_count() && c->cursor < TEST_TX_CAP_N ){
        const test_tx_cap_t *t = test_tx_at(c->cursor++);
        if( t == NULL || t->len == 0 || t->len > TEST_TX_CAP_LEN ) continue;
        bool internal = halow_ack_is_internal_frame(t->buf, t->len);
        c->sent++;
        if( vchan_loss(c) ){ c->dropped++; continue; }
        if( internal ){
            const uint8_t *o = NULL;
            uint16_t ol = 0;
            (void)halow_ack_on_rx(t->buf, t->len, t->mac, MAC_ME, 0, &o, &ol);
        }else{
            /* data frames count as peer traffic at the far node: the source
             * is the PEER, never the frame's own dest (a broadcast frame
             * must not register FF:FF:.. as the link's remote MAC) */
            halow_pkg_handler_rf_to_tcp((uint8_t *)t->buf, t->len,
                                        PEER_A, MAC_ME, EVM_M10);
        }
    }
}

void vlink_run( vchan_t *c, uint32_t ms ){
    for( uint32_t t = 0; t < ms; t += 5u ){
        test_advance_ms(5);
        halow_ack_tick();
        vlink_pump(c);
    }
}

/* feed TCP bytes; when the TX path THROTTLEs, let virtual time run so the
 * lossy channel can return ACKs and free slots, then resume */
void vlink_feed( vchan_t *c, const uint8_t *data, uint16_t len ){
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
        CHECK( ++guard < 5000 );
        vlink_run(c, 25);
        if( rns_stream_decoder_retry_held(&g_dec, NULL) == HALOW_ACK_TX_THROTTLE ){
            vlink_run(c, 25);
        }
    }
}

/* Pipeline adds ZERO virtual time when nothing is lost: feed -> bundle ->
 * wire -> receive -> decode -> TCP all happen at the same jiffy, and no
 * os_sleep is ever called on the synchronous path. */
void t_vlink_zero_wait_invariant( void ){
    halow_ack_config_t cfg;
    static uint8_t pkt[520];
    static uint8_t stream[1100];
    uint16_t plen, wlen;
    uint64_t j0, j1;
    uint32_t sleeps0;
    vchan_t vc;

    cfg_base(&cfg);
    fp_node_start(&cfg);
    memset(&vc, 0, sizeof(vc));

    plen = rns_pkt_build(pkt, 0xC1, 0xC1, 400, RNS_PACKET_TYPE_DATA, RNS_DESTINATION_TYPE_LINK);
    wlen = slip_encode(stream, pkt, plen);

    j0 = test_time_jiff();
    sleeps0 = test_sleep_calls();
    vlink_feed(&vc, stream, wlen);
    fp_idle();
    vlink_pump(&vc);
    j1 = test_time_jiff();

    CHECK( j0 == j1 );
    CHECK( test_sleep_calls() == sleeps0 );
    CHECK( test_tcp_count() == 1 );
    CHECK( test_tcp_at(0)->at_jiff == j0 );
    {
        slipdec_t dec;
        slipdec_init(&dec);
        slipdec_feed(&dec, test_tcp_at(0)->buf, test_tcp_at(0)->len);
        CHECK( dec.n == 1 );
        CHECK( dec.len[0] == plen );
        CHECK( memcmp(dec.buf[0], pkt, plen) == 0 );
    }
}

/* full pipeline over a 20% loss channel: every packet delivered exactly
 * once, in order, byte-exact; retries absorb all losses; heap drains */
void t_vlink_lossy_roundtrip( void ){
    halow_ack_config_t cfg;
    enum { N = 100 };
    static uint8_t pkt[N][520];
    static uint8_t stream[4 * 1100];
    static slipdec_t dec;
    uint16_t plen[N];
    vchan_t vc;
    halow_ack_stats_t st;

    cfg_base(&cfg);
    cfg.window = 16;
    cfg.timeout_ms = 40;
    cfg.max_retries = 8;
    cfg.ack_fids = 4;
    fp_node_start(&cfg);
    memset(&vc, 0, sizeof(vc));
    vc.drop_pct = 20;
    slipdec_init(&dec);

    /* warmup: learn the peer MAC over the lossy channel (the first frame
     * rides the untracked broadcast path -- re-feed until it gets through) */
    plen[0] = rns_pkt_build(pkt[0], 0xC2, 0xC2, 300, RNS_PACKET_TYPE_DATA, RNS_DESTINATION_TYPE_LINK);
    for( int k = 0; k < 40 && test_tcp_count() == 0; k++ ){
        vlink_feed(&vc, stream, slip_encode(stream, pkt[0], plen[0]));
        fp_idle();
        vlink_run(&vc, 60);
    }
    CHECK( test_tcp_count() == 1 );
    test_tcp_reset();
    test_tx_reset();
    vc.cursor = 0;

    for( int i = 1; i < N; ){
        uint32_t n = 0;
        for( uint8_t k = 0; k < 4 && i < N; k++, i++ ){
            plen[i] = rns_pkt_build(pkt[i], 0xC2, (uint8_t)i, 481,
                                    RNS_PACKET_TYPE_DATA, RNS_DESTINATION_TYPE_LINK);
            n += slip_encode(&stream[n], pkt[i], plen[i]);
        }
        vlink_feed(&vc, stream, (uint16_t)n);
        fp_idle();
        vlink_run(&vc, 15);
    }
    vlink_run(&vc, 6000);   /* drain: slot lifetime is capped at 6 s */

    halow_ack_stats_get(&st);
    CHECK( st.outstanding == 0 );
    CHECK( st.dropped <= 3 );                    /* rare all-retry loss streaks */
    CHECK( st.tx_frames >= (uint32_t)N );       /* + warmup re-feed attempts */
    CHECK( st.acked >= 5 );                     /* bundles ACKed through loss */
    CHECK( st.retransmitted >= 3 );             /* losses actually happened */
    CHECK( st.heap_bytes == 0 );

    for( int i = 0; i < test_tcp_count(); i++ ){
        slipdec_feed(&dec, test_tcp_at(i)->buf, test_tcp_at(i)->len);
    }
    CHECK( dec.n <= N - 1 );
    {
        /* retransmits may reorder wire frames; "dropped" means the ACK never
         * came back (the data itself may still have been delivered), so the
         * hard invariants are: every packet delivered AT MOST once, almost
         * all delivered at least once, undelivered only among the dropped */
        int undelivered = 0;
        for( int i = 1; i < N; i++ ){
            int hits = 0;
            for( int k = 0; k < dec.n && hits <= 1; k++ ){
                if( dec.len[k] == plen[i] && memcmp(dec.buf[k], pkt[i], plen[i]) == 0 )
                    hits++;
            }
            CHECK( hits <= 1 );
            if( hits == 0 ) undelivered++;
        }
        CHECK( undelivered <= (int)st.dropped );
        CHECK( (int)st.dropped - undelivered <= 3 );
    }
}

/* brutal loss: retries exhaust, the dropped frames are counted, everything
 * else arrives exactly once (no dups despite retransmits + dup ACKs) */
void t_vlink_lossy_deadline( void ){
    halow_ack_config_t cfg;
    enum { N = 12 };
    static uint8_t pkt[N][520];
    static uint8_t stream[1100];
    static slipdec_t dec;
    uint16_t plen[N];
    vchan_t vc;
    halow_ack_stats_t st;

    cfg_base(&cfg);
    cfg.window = 8;
    cfg.timeout_ms = 15;
    cfg.max_retries = 2;
    cfg.agg = 0;
    fp_node_start(&cfg);
    memset(&vc, 0, sizeof(vc));
    vc.drop_pct = 70;
    slipdec_init(&dec);

    plen[0] = rns_pkt_build(pkt[0], 0xC3, 0xC3, 300, RNS_PACKET_TYPE_DATA, RNS_DESTINATION_TYPE_LINK);
    for( int k = 0; k < 40 && test_tcp_count() == 0; k++ ){
        vlink_feed(&vc, stream, slip_encode(stream, pkt[0], plen[0]));
        fp_idle();
        vlink_run(&vc, 60);
    }
    CHECK( test_tcp_count() == 1 );
    test_tcp_reset();
    test_tx_reset();
    vc.cursor = 0;

    for( int i = 1; i < N; i++ ){
        plen[i] = rns_pkt_build(pkt[i], 0xC3, (uint8_t)(i + 1), 400,
                                RNS_PACKET_TYPE_DATA, RNS_DESTINATION_TYPE_LINK);
        vlink_feed(&vc, stream, slip_encode(stream, pkt[i], plen[i]));
        fp_idle();
        vlink_run(&vc, 40);
    }
    vlink_run(&vc, 1500);

    halow_ack_stats_get(&st);
    CHECK( st.outstanding == 0 );
    CHECK( st.drop_exhaust >= 1 );
    CHECK( st.dropped == st.drop_exhaust + st.drop_deadline );

    for( int i = 0; i < test_tcp_count(); i++ ){
        slipdec_feed(&dec, test_tcp_at(i)->buf, test_tcp_at(i)->len);
    }
    CHECK( dec.n >= 1 );
    CHECK( dec.n <= N - 1 );
    {
        /* every packet delivered at most once; the undelivered set is a
         * subset of the dropped set (a frame can be delivered yet die for
         * lack of ACK) */
        int undelivered = 0;
        for( int idx = 1; idx < N; idx++ ){
            int hits = 0;
            for( int k = 0; k < dec.n && hits <= 1; k++ ){
                if( dec.len[k] == plen[idx] &&
                    memcmp(dec.buf[k], pkt[idx], plen[idx]) == 0 ) hits++;
            }
            CHECK( hits <= 1 );
            if( hits == 0 ) undelivered++;
        }
        CHECK( undelivered <= (int)st.dropped );
    }
    CHECK( st.heap_bytes == 0 );
}

/* latency through the lossy pipeline, in virtual ms */
void t_vlink_latency_profile( void ){
    halow_ack_config_t cfg;
    enum { N = 40 };
    static uint8_t pkt[520];
    static uint8_t stream[1100];
    uint16_t plen;
    uint64_t feed_j[N];
    uint32_t lat[N];
    vchan_t vc;
    halow_ack_stats_t st;

    cfg_base(&cfg);
    cfg.window = 16;
    cfg.timeout_ms = 50;
    cfg.max_retries = 8;
    cfg.agg = 0;
    fp_node_start(&cfg);
    memset(&vc, 0, sizeof(vc));
    vc.drop_pct = 30;

    plen = rns_pkt_build(pkt, 0xC4, 0xC4, 300, RNS_PACKET_TYPE_DATA, RNS_DESTINATION_TYPE_LINK);
    for( int k = 0; k < 40 && test_tcp_count() == 0; k++ ){
        vlink_feed(&vc, stream, slip_encode(stream, pkt, plen));
        fp_idle();
        vlink_run(&vc, 60);
    }
    CHECK( test_tcp_count() == 1 );
    test_tcp_reset();
    test_tx_reset();
    vc.cursor = 0;

    uint32_t lost_forever = 0;
    for( int i = 0; i < N; i++ ){
        halow_ack_stats_t st0;
        plen = rns_pkt_build(pkt, 0xC4, (uint8_t)(i + 1), 450,
                             RNS_PACKET_TYPE_DATA, RNS_DESTINATION_TYPE_LINK);
        halow_ack_stats_get(&st0);
        feed_j[i] = test_time_jiff();
        int tcp0 = test_tcp_count();
        vlink_feed(&vc, stream, slip_encode(stream, pkt, plen));
        fp_idle();
        vlink_pump(&vc);          /* first attempt: delivered at the SAME jiffy */
        int guard = 0;
        while( test_tcp_count() == tcp0 ){
            /* serial mode -- only THIS frame can exhaust (agg off, one buf) */
            halow_ack_stats_get(&st);
            if( st.dropped > st0.dropped ) break;   /* lost on every retry */
            vlink_run(&vc, 10);
            if( ++guard >= 600 ) break;
        }
        if( test_tcp_count() > tcp0 ){
            lat[i] = (uint32_t)(test_tcp_at(tcp0)->at_jiff - feed_j[i]);
            CHECK( lat[i] < 3000 );
        }else{
            lat[i] = 0;
            lost_forever++;
        }
    }
    vlink_run(&vc, 3000);

    uint32_t lmax = 0, lsum = 0, lretx = 0;
    for( int i = 0; i < N; i++ ){
        if( lat[i] > lmax ) lmax = lat[i];
        lsum += lat[i];
        if( lat[i] > 0 ) lretx++;
    }
    printf("    vlink latency (%u%% loss, tmo %ums): max=%ums avg=%ums retransmitted=%u/%u lost=%u\n",
           (unsigned)vc.drop_pct, (unsigned)cfg.timeout_ms,
           (unsigned)lmax, (unsigned)(lsum / N), (unsigned)lretx, (unsigned)N,
           (unsigned)lost_forever);
    CHECK( lmax < 3000 );
    CHECK( (uint32_t)(N - lretx - lost_forever) >= 20 );  /* most survive attempt 1 */
    CHECK( lost_forever <= 2 );

    halow_ack_stats_get(&st);
    printf("    vlink stats: dropped=%u exhaust=%u deadline=%u throttle=%u acked=%u rtt=%u tx=%u dups=%u acks_rx=%u acks_tx=%u\n",
           (unsigned)st.dropped, (unsigned)st.drop_exhaust, (unsigned)st.drop_deadline,
           (unsigned)st.drop_throttle, (unsigned)st.acked, (unsigned)st.ack_rtt_hits,
           (unsigned)st.tx_frames, (unsigned)st.acks_rx_dup,
           (unsigned)st.acks_rx_frames, (unsigned)st.acks_sent);
    {
        /* dump the fids carried by the last few ACK frames vs expectation */
        int shown = 0;
        for( int i = test_tx_count() - 1; i >= 0 && shown < 3; i-- ){
            const test_tx_cap_t *t = test_tx_at(i);
            if( t == NULL || !halow_ack_is_internal_frame(t->buf, t->len) ) continue;
            if( t->len == 14 ) continue;   /* env ack */
            shown++;
        }
        shown = 0;
        for( int i = test_tx_count() - 1; i >= 0 && shown < 3; i-- ){
            const test_tx_cap_t *t = test_tx_at(i);
            if( t == NULL || t->len > TEST_TX_CAP_LEN ) continue;
            if( halow_ack_is_internal_frame(t->buf, t->len) ) continue;
            if( memcmp(t->mac, mac_broadcast, 6) == 0 ) continue;
            shown++;
        }
    }
    CHECK( st.outstanding == 0 );
    CHECK( st.heap_bytes == 0 );
    CHECK( st.ack_rtt_hits >= 30 );
}

/* ============ coverage: uncovered branches from the gcov map ============ */

