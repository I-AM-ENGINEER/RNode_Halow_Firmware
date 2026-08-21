#include "sys_config.h"
#define LOG_LOCAL_LEVEL LOG_LEVEL_HALOW_PKG_HANDLER
#include "basic_include.h"
#include "halow.h"
#include "utils.h"
#include "halow_ack.h"
#include "halow_pkg_handler.h"
#include "rns/stream_parser.h"
#include "rns/link_parser.h"
#include "harness.h"

#include <string.h>

static const uint8_t MAC_ME[6] = {0x00,0x00,0x00,0x00,0x00,0x01};
static const uint8_t PEER[6]   = {0x11,0x11,0x11,0x11,0x11,0x11};

#define EVM_M10 ((int8_t)(-10))

static uint32_t fnv1a( const uint8_t *p, uint16_t len ){
    uint32_t h = 2166136261u;
    while( len-- ){
        h ^= (uint32_t)(*p++);
        h *= 16777619u;
    }
    return h;
}

static void fill_payload( uint8_t *p, uint16_t len, uint8_t seed ){
    for( uint16_t i = 0; i < len; i++ ) p[i] = (uint8_t)(seed + i);
}

static void ack_fid( const uint8_t *mac, uint16_t fid ){
    uint8_t a[5];
    const uint8_t *o = NULL;
    uint16_t ol = 0;
    a[0] = 0xA5; a[1] = 0x5A; a[2] = 0xF6;
    a[3] = (uint8_t)(fid & 0xFF); a[4] = (uint8_t)(fid >> 8);
    (void)halow_ack_on_rx(a, 5, mac, MAC_ME, 0, &o, &ol);
}

static uint16_t pkt_build( uint8_t *out, uint8_t dest_seed, uint8_t payload_seed,
                           uint16_t payload_len ){
    uint16_t total = (uint16_t)(2 + 16 + 1 + payload_len);
    out[0] = (uint8_t)((RNS_DESTINATION_TYPE_LINK << 2) | RNS_PACKET_TYPE_DATA);
    out[1] = 1;
    memset(&out[2], dest_seed, 16);
    out[18] = 0;
    fill_payload(&out[19], payload_len, payload_seed);
    return total;
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

static int bench_noop_cb( uint8_t *payload, uint16_t len, void *user ){
    (void)payload; (void)len; (void)user;
    return 0;
}

static int bench_tx_cb( uint8_t *payload, uint16_t len, void *user ){
    (void)user;
    return halow_pkg_handler_tcp_to_rf(payload, len);
}

/* ack only the wire frames that appeared since *acked_upto (O(new frames)) */
static void ack_new_frames( int *acked_upto ){
    for( ; *acked_upto < test_tx_count() && *acked_upto < TEST_TX_CAP_N; (*acked_upto)++ ){
        const test_tx_cap_t *t = test_tx_at(*acked_upto);
        if( t != NULL && t->len != 0 && t->len <= TEST_TX_CAP_LEN &&
            !halow_ack_is_internal_frame(t->buf, t->len) &&
            memcmp(t->mac, mac_broadcast, 6) != 0 ){
            ack_fid(t->mac, (uint16_t)(fnv1a(t->buf, t->len) & 0xFFFFu));
        }
    }
}

static rns_stream_decoder_t g_dec;

enum { PKT_N = 64, PLAIN_LEN = 500 };

static uint8_t g_pkt[PKT_N][520];
static uint8_t g_slip[PKT_N][1100];
static uint16_t g_plen[PKT_N];
static uint16_t g_slen[PKT_N];

int main( void ){
    halow_ack_config_t cfg;
    rns_link_packet_info_t info;
    const uint8_t *o = NULL;
    uint16_t ol = 0;
    uint8_t r[120];

    halow_ack_config_set_default(&cfg);
    cfg.timeout_ms  = 50;
    cfg.max_retries = 8;
    cfg.ack_hold_ms = 0;
    cfg.rate_adapt  = 0;
    cfg.window      = 16;

    test_time_reset();
    configdb_reset();
    test_tx_reset();
    test_tcp_reset();
    test_vacancy_set(100000);
    rns_stream_decoder_init(&g_dec, bench_noop_cb);
    halow_ack_init();
    halow_ack_config_apply(&cfg);

    for( int i = 0; i < PKT_N; i++ ){
        g_plen[i] = pkt_build(g_pkt[i], 0x31, (uint8_t)i, PLAIN_LEN - 19);
        g_slen[i] = slip_encode(g_slip[i], g_pkt[i], g_plen[i]);
    }

    /* ---- stage 1: SLIP decode only ---- */
    printf("stage:slip iters=12800\n");
    for( int k = 0; k < 200; k++ )
        for( int i = 0; i < PKT_N; i++ ){
            uint16_t consumed = 0;
            (void)rns_stream_decoder_process(&g_dec, g_slip[i], g_slen[i], NULL, &consumed);
        }

    /* ---- stage 2: RNS header parse ---- */
    printf("stage:parse iters=25600\n");
    for( int k = 0; k < 400; k++ )
        for( int i = 0; i < PKT_N; i++ )
            (void)rns_link_parser_parse(g_pkt[i], g_plen[i], &info);

    /* ---- stage 3: sha256 link-id (LINKREQUEST parse) ---- */
    printf("stage:sha256_lr iters=6400\n");
    for( int k = 0; k < 100; k++ )
        for( int i = 0; i < PKT_N; i++ ){
            g_pkt[i][0] = (uint8_t)(RNS_DESTINATION_TYPE_SINGLE << 2) | RNS_PACKET_TYPE_LINKREQUEST;
            (void)rns_link_parser_parse(g_pkt[i], g_plen[i], &info);
            g_pkt[i][0] = (uint8_t)(RNS_DESTINATION_TYPE_LINK << 2) | RNS_PACKET_TYPE_DATA;
        }

    /* ---- stage 4: RX->TCP stream encode (SLIP + malloc/free) ---- */
    printf("stage:encode iters=6400\n");
    for( int k = 0; k < 100; k++ )
        for( int i = 0; i < PKT_N; i++ ){
            uint8_t *out = NULL;
            uint32_t outlen = 0;
            (void)rns_stream_encode_alloc(g_pkt[i], g_plen[i], &out, &outlen);
            free(out);
        }

    /* ---- stage 5: full TX pipeline, plain 500-B frames
     * (TCP bytes -> SLIP -> RNS -> bundle/heap -> air -> ACK back) ---- */
    printf("stage:tx_plain iters=3780\n");
    rns_stream_decoder_init(&g_dec, bench_tx_cb);
    {
        int acked_upto = 0;
        uint16_t consumed = 0;

        /* learn the peer once over the broadcast path */
        (void)rns_stream_decoder_process(&g_dec, g_slip[0], g_slen[0], NULL, &consumed);
        halow_ack_flush();
        halow_pkg_handler_rf_to_tcp((uint8_t *)test_tx_at(0)->buf, test_tx_at(0)->len,
                                    PEER, MAC_ME, EVM_M10);
        test_tx_reset();

        for( int k = 0; k < 60; k++ ){
            for( int i = 1; i < PKT_N; i++ ){
                uint32_t off = 0;
                while( off < g_slen[i] ){
                    consumed = 0;
                    int32_t rr = rns_stream_decoder_process(&g_dec, &g_slip[i][off],
                                                            (uint16_t)(g_slen[i] - off),
                                                            NULL, &consumed);
                    if( rr != HALOW_ACK_TX_THROTTLE ){
                        off += (consumed != 0u) ? consumed : (uint16_t)(g_slen[i] - off);
                        continue;
                    }
                    if( consumed != 0u ){ off += consumed; continue; }
                    halow_ack_tick();
                    ack_new_frames(&acked_upto);
                    if( rns_stream_decoder_retry_held(&g_dec, NULL) == HALOW_ACK_TX_THROTTLE ){
                        ack_new_frames(&acked_upto);
                    }
                }
                halow_ack_flush();
                ack_new_frames(&acked_upto);
            }
            /* keep the capture ring far from its 1024 cap: drain, then roll */
            halow_ack_flush();
            ack_new_frames(&acked_upto);
            test_tx_reset();
            acked_upto = 0;
        }
        {
            halow_ack_stats_t st;
            halow_ack_stats_get(&st);
            printf("stage:tx_plain stats outstanding=%u acked=%u retx=%u env=%u drops=%u\n",
                   (unsigned)st.outstanding, (unsigned)st.acked,
                   (unsigned)st.retransmitted, (unsigned)st.env_tx_bundles,
                   (unsigned)st.dropped);
        }
    }

    /* ---- stage 6: full RX pipeline (air -> dedup -> RNS -> TCP encode) ---- */
    printf("stage:rx_deliver iters=19200\n");
    {
        static uint8_t wire[TEST_TCP_CAP_LEN];
        for( int k = 0; k < 300; k++ ){
            for( int i = 0; i < PKT_N; i++ ){
                uint16_t wl = pkt_build(wire, (uint8_t)(0x40 + (i & 7)),
                                        (uint8_t)(k + i), PLAIN_LEN - 19);
                wire[19] = (uint8_t)k;
                wire[20] = (uint8_t)(k >> 8);
                wire[21] = (uint8_t)i;
                halow_pkg_handler_rf_to_tcp(wire, wl, PEER, MAC_ME, EVM_M10);
                if( (i & 7) == 7 ) test_tcp_reset();
            }
        }
    }

    /* ---- stage 7: dedup-suppressed RX re-delivery ---- */
    printf("stage:rx_dedup iters=19200\n");
    for( int k = 0; k < 300; k++ )
        for( int i = 0; i < PKT_N; i++ )
            (void)halow_ack_on_rx(g_pkt[i], g_plen[i], PEER, MAC_ME, EVM_M10, &o, &ol);

    /* ---- stage 8: empty tick (baseline) ---- */
    printf("stage:tick iters=100000\n");
    for( int i = 0; i < 100000; i++ )
        halow_ack_tick();

    /* ---- stage 9: RX + immediate ACK TX (radio both ways) ---- */
    printf("stage:rx_ack iters=12800\n");
    for( int k = 0; k < 200; k++ )
        for( int i = 0; i < PKT_N; i++ ){
            fill_payload(r, sizeof(r), (uint8_t)(k + i));
            (void)halow_ack_on_rx(r, sizeof(r), PEER, MAC_ME, EVM_M10, &o, &ol);
        }

    {
        halow_ack_stats_t st;
        halow_ack_stats_get(&st);
        printf("bench: done tx=%d acked=%u heap=%u\n",
               test_tx_count(), (unsigned)st.acked, (unsigned)st.heap_bytes);
    }
    return 0;
}
