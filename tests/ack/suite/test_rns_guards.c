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

void t_cov_type2_and_parse_fail( void ){
    halow_ack_config_t cfg;
    static uint8_t pkt[300];
    static uint8_t stream[700];
    uint16_t plen, wlen, consumed = 0;
    extern volatile uint32_t g_dbg_rns_tx_parse_fail;

    cfg_base(&cfg);
    fp_node_start(&cfg);

    /* valid type-2 header packet: [flags|0x40][hops][dest16][tid16][ctx] */
    plen = rns_pkt_build(pkt, 0xD3, 0xD3, 100, RNS_PACKET_TYPE_DATA,
                         RNS_DESTINATION_TYPE_LINK);
    pkt[0] |= 0x40;
    memmove(&pkt[35], &pkt[19], 100);
    memcpy(&pkt[19], pkt, 16);      /* transport id */
    pkt[34] = 0;
    pkt[18] = 16;                   /* keep dest sane */
    wlen = slip_encode(stream, pkt, 35 + 100);
    CHECK( fp_feed(stream, wlen, &consumed) == 0 );
    CHECK( test_tx_count() == 1 );
    CHECK( test_tx_at(0)->len == 35 + 100 );

    /* short type-2 packet -> parser rejects, counted, nothing on air */
    test_tx_reset();
    plen = rns_pkt_build(pkt, 0xD4, 0xD4, 5, RNS_PACKET_TYPE_DATA,
                         RNS_DESTINATION_TYPE_LINK);
    pkt[0] |= 0x40;
    wlen = slip_encode(stream, pkt, plen);
    {
        uint32_t f0 = g_dbg_rns_tx_parse_fail;
        CHECK( fp_feed(stream, wlen, &consumed) == 0 );
        CHECK( g_dbg_rns_tx_parse_fail == f0 + 1 );
        CHECK( test_tx_count() == 0 );
    }

    /* garbage frame from TCP: parse fail, no crash, stream stays in sync */
    {
        static uint8_t junk[40];
        for( uint8_t i = 0; i < sizeof(junk); i++ ) junk[i] = (uint8_t)(i + 1);
        wlen = slip_encode(stream, junk, sizeof(junk));
        CHECK( fp_feed(stream, wlen, &consumed) == 0 );
        CHECK( g_dbg_rns_tx_parse_fail >= 1 );
    }
}

void t_cov_utils_guards( void ){
    rns_link_packet_info_t info;
    uint8_t pkt[140];
    uint32_t orig = 0;
    uint16_t plen;

    plen = rns_pkt_build(pkt, 0xD5, 0xD5, 96, RNS_PACKET_TYPE_DATA,
                         RNS_DESTINATION_TYPE_LINK);
    CHECK( rns_link_parser_parse(pkt, plen, &info) == RNS_RET_OK );

    CHECK( rns_link_utils_clamp_mtu(NULL, plen, &info, 500, &orig) == RNS_RET_NULLPTR );
    CHECK( rns_link_utils_clamp_mtu(pkt, plen, NULL, 500, &orig) == RNS_RET_NULLPTR );
    CHECK( rns_link_utils_clamp_mtu(pkt, plen, &info, 500, &orig) == RNS_RET_INVALID_PACKET_TYPE );
    CHECK( rns_link_utils_get_mtu(NULL, plen, &info, &orig) == RNS_RET_NULLPTR );
    CHECK( rns_link_utils_get_mtu(pkt, plen, NULL, &orig) == RNS_RET_NULLPTR );
    CHECK( rns_link_utils_get_mtu(pkt, plen, &info, NULL) == RNS_RET_NULLPTR );
    CHECK( rns_link_utils_get_mtu(pkt, plen, &info, &orig) == RNS_RET_INVALID_PACKET_TYPE );

    /* LINKREQUEST with a too-short payload */
    plen = rns_pkt_build(pkt, 0xD6, 0xD6, 10, RNS_PACKET_TYPE_LINKREQUEST,
                         RNS_DESTINATION_TYPE_SINGLE);
    CHECK( rns_link_parser_parse(pkt, plen, &info) == RNS_RET_OK );
    CHECK( rns_link_utils_get_mtu(pkt, plen, &info, &orig) == RNS_RET_PACKET_TOO_SHORT );
    CHECK( rns_link_utils_clamp_mtu(pkt, plen, &info, 500, &orig) == RNS_RET_PACKET_TOO_SHORT );

    /* parser guards */
    CHECK( rns_link_parser_parse(NULL, plen, &info) == RNS_RET_NULLPTR );
    CHECK( rns_link_parser_parse(pkt, plen, NULL) == RNS_RET_NULLPTR );
    CHECK( rns_link_parser_parse(pkt, 5, &info) == RNS_RET_PACKET_TOO_SHORT );
}

int fp_null_cb( uint8_t *payload, uint16_t len, void *user ){
    (void)payload; (void)len; (void)user;
    return 0;
}

void t_cov_stream_guards( void ){
    static rns_stream_decoder_t d;
    static uint8_t buf[11000];
    uint8_t small[8];
    uint16_t consumed = 0;
    uint8_t *out = NULL;
    uint32_t outlen = 0;

    rns_stream_decoder_init(NULL, fp_null_cb);
    rns_stream_decoder_reset(NULL);
    CHECK( rns_stream_decoder_retry_held(NULL, NULL) == 0 );
    CHECK( rns_stream_decoder_process(NULL, small, 1, NULL, &consumed) == 0 );
    CHECK( consumed == 0 );
    CHECK( rns_stream_decoder_process(&d, NULL, 5, NULL, &consumed) == 0 );

    rns_stream_decoder_init(&d, NULL);      /* no callback: frames dropped */
    small[0] = 0x7E; small[1] = 1; small[2] = 2; small[3] = 0x7E;
    CHECK( rns_stream_decoder_process(&d, small, 4, NULL, &consumed) == 0 );
    CHECK( consumed == 4 );

    rns_stream_decoder_init(&d, fp_null_cb);
    CHECK( rns_stream_decoder_retry_held(&d, NULL) == 0 );   /* nothing held */
    rns_stream_decoder_reset(&d);
    CHECK( d.state == 0 && d.frame_len == 0 && !d.held );

    /* frame larger than the 10 KB buffer: overflow, decoder resyncs */
    buf[0] = 0x7E;
    for( uint32_t i = 1; i < sizeof(buf) - 1; i++ ) buf[i] = (uint8_t)(i & 0x7D);
    buf[sizeof(buf) - 1] = 0x7E;
    CHECK( rns_stream_decoder_process(&d, buf, sizeof(buf), NULL, &consumed) == 0 );
    CHECK( consumed == sizeof(buf) );
    small[0] = 0x7E; small[1] = 9; small[2] = 0x7E;
    CHECK( rns_stream_decoder_process(&d, small, 3, NULL, &consumed) == 0 );

    /* encode_alloc argument guards */
    CHECK( rns_stream_encode_alloc(NULL, 5, &out, &outlen) == -1 );
    CHECK( rns_stream_encode_alloc(small, 0, &out, &outlen) == -1 );
    CHECK( rns_stream_encode_alloc(small, 3, NULL, &outlen) == -1 );
    CHECK( rns_stream_encode_alloc(small, 3, &out, NULL) == -1 );
}

uint8_t  zc_cap_buf[64];
uint16_t zc_cap_len;

int32_t zc_capture_cb( uint8_t *payload, uint16_t len, void *user ){
    (void)user;
    if( len <= sizeof(zc_cap_buf) ) memcpy(zc_cap_buf, payload, len);
    zc_cap_len = len;
    return 0;
}

void t_zero_copy_rx_encode( void ){
    /* rns_stream_encode_frame: size-first/encode-second, exact equality with
     * encode_alloc, cap-too-small writes nothing, escape round-trip */
    static const uint8_t mixed[] = {0x7E, 0x01, 0x7D, 0x02, 0x7E, 0x7D, 0x00, 0x7E};
    static uint8_t enc[64];
    static uint8_t enc2[64];
    uint8_t *heap_frame = NULL;
    uint32_t heap_len = 0;
    uint32_t need;

    need = rns_stream_encode_frame(NULL, 0u, mixed, sizeof(mixed));
    CHECK( need == 2u + sizeof(mixed) + 5u );          /* 3x FLAG + 2x ESC */

    memset(enc2, 0xAA, sizeof(enc2));
    CHECK( rns_stream_encode_frame(enc2, need - 1u, mixed, sizeof(mixed)) == need );
    CHECK( enc2[0] == 0xAA );                          /* cap too small: no write */

    CHECK( rns_stream_encode_frame(enc, sizeof(enc), mixed, sizeof(mixed)) == need );
    CHECK( rns_stream_encode_alloc(mixed, sizeof(mixed), &heap_frame, &heap_len) == 0 );
    CHECK( heap_len == need );
    CHECK( memcmp(enc, heap_frame, need) == 0 );
    free(heap_frame);

    /* round-trip through the real decoder */
    {
        static rns_stream_decoder_t d;
        uint16_t consumed = 0;
        rns_stream_decoder_init(&d, zc_capture_cb);
        zc_cap_len = 0xFFFFu;
        CHECK( rns_stream_decoder_process(&d, enc, (uint16_t)need, NULL, &consumed) == 0 );
        CHECK( consumed == need );
        CHECK( zc_cap_len == sizeof(mixed) );
        CHECK( memcmp(zc_cap_buf, mixed, sizeof(mixed)) == 0 );
    }

    /* tcp_server_send_owned: ownership contract + leak-freedom */
    {
        uint32_t live0 = test_malloc_live_bytes();
        uint32_t blocks0 = test_malloc_live_blocks();
        uint8_t *b;

        CHECK( tcp_server_send_owned(NULL, 4) == -2 );

        test_tcp_reset();
        b = os_malloc(need);
        CHECK( b != NULL );
        memcpy(b, enc, need);
        CHECK( tcp_server_send_owned(b, need) == 0 );   /* buffer consumed */
        CHECK( test_tcp_count() == 1 );
        CHECK( memcmp(test_tcp_at(0)->buf, enc, need) == 0 );
        CHECK( test_malloc_live_bytes() == live0 );
        CHECK( test_malloc_live_blocks() == blocks0 );

        test_tcp_full_set(1);                           /* ring full: freed, -1 */
        b = os_malloc(8);
        CHECK( b != NULL );
        CHECK( tcp_server_send_owned(b, 8) == -1 );
        CHECK( test_malloc_live_bytes() == live0 );
        CHECK( test_malloc_live_blocks() == blocks0 );
        test_tcp_full_set(0);
    }

    /* full RX->TCP deliver path must be heap-neutral now (one os_malloc,
     * freed inside send_owned) */
    {
        static uint8_t pkt[128];
        static uint8_t wire[160];
        uint16_t plen;
        uint32_t live0 = test_malloc_live_bytes();
        uint32_t blocks0 = test_malloc_live_blocks();
        const uint8_t peer[6] = {0x22,0x22,0x22,0x22,0x22,0x22};
        const uint8_t me[6]   = {0x00,0x00,0x00,0x00,0x00,0x01};

        plen = rns_pkt_build(pkt, 0x51, 0x5A, 60, RNS_PACKET_TYPE_DATA,
                             RNS_DESTINATION_TYPE_LINK);
        test_tcp_reset();
        halow_pkg_handler_rf_to_tcp(pkt, plen, peer, me, -12);
        CHECK( test_tcp_count() == 1 );
        CHECK( test_malloc_live_bytes() == live0 );
        CHECK( test_malloc_live_blocks() == blocks0 );

        /* captured wire bytes == SLIP of the RNS frame */
        plen = rns_stream_encode_frame(wire, sizeof(wire), pkt, plen);
        CHECK( test_tcp_at(0)->len == plen );
        if( memcmp(test_tcp_at(0)->buf, wire, plen) != 0 ){
            for( uint32_t k = 0; k < plen; k++ ){
                if( test_tcp_at(0)->buf[k] != wire[k] ){
                    printf("    dbg zc diff @%u cap=%02x wire=%02x plen=%u\n",
                           k, test_tcp_at(0)->buf[k], wire[k], plen);
                    break;
                }
            }
            CHECK( 0 );
        }
    }
}

/* ============ legacy-detector / Reticulum compat suite ============
 * Wire formats verified against:
 *  - markqvist/Reticulum RNS/Packet.py: flags = (header<<6)|(cflag<<5)|
 *    (ttype<<4)|(dtype<<2)|ptype, header_type <= 1 => first byte < 0x80,
 *    second byte = hops (< PATHFINDER_M = 16)
 *  - deployed old firmware (git 8b6cf95): legacy bundle [A5][AD][nsub 2..8]
 *    ([len_le16][sub])* -- single subs are UNWRAPPED, nsub=1 never emitted;
 *    fid ACK [A5][5A][evm int8, unsigned >= 0x80][fid_le16 x n]
 * Our internal magics all start with 0xA5 => a real Reticulum packet can
 * never be misdetected. These tests prove it exhaustively and pin the
 * positive/edge behavior of the detectors. */

extern volatile uint32_t g_dbg_rns_rx_calls;
extern volatile uint32_t g_dbg_rns_rx_parse_fail;

/* Build a frame with the REAL Reticulum Packet.py layout */
