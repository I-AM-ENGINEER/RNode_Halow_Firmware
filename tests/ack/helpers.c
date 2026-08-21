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

const uint8_t MAC_ME[6]  = {0x00,0x00,0x00,0x00,0x00,0x01};
const uint8_t PEER_A[6]  = {0x11,0x11,0x11,0x11,0x11,0x11};
const uint8_t PEER_B[6]  = {0x22,0x22,0x22,0x22,0x22,0x22};
const uint8_t PEER_C[6]  = {0x33,0x33,0x33,0x33,0x33,0x33};
const uint8_t PEER_D[6]  = {0x44,0x44,0x44,0x44,0x44,0x44};
const uint8_t PEER_E[6]  = {0x55,0x55,0x55,0x55,0x55,0x55};
const uint8_t PEER_R[6]  = {0x66,0x66,0x66,0x66,0x66,0x66};
const uint8_t PEER_LO[6] = {0x77,0x77,0x77,0x77,0x77,0x77};
const uint8_t PEER_HI[6] = {0x88,0x88,0x88,0x88,0x88,0x88};


uint32_t fnv1a( const uint8_t *p, uint16_t len ){
    uint32_t h = 2166136261u;
    while( len-- ){
        h ^= (uint32_t)(*p++);
        h *= 16777619u;
    }
    return h;
}

void cfg_base( halow_ack_config_t *c ){
    halow_ack_config_set_default(c);
    c->timeout_ms   = 50;
    c->max_retries  = 2;
    c->ack_hold_ms  = 0;
    c->rate_adapt   = 0;
    c->window       = 8;
    c->bc_repeat    = 1;
}

void node_start( const halow_ack_config_t *cfg ){
    test_time_reset();
    configdb_reset();
    test_tx_reset();
    test_vacancy_set(100000);
    halow_ack_init();
    if( cfg != NULL ) halow_ack_config_apply(cfg);
}

void run_ticks( int n, uint32_t step_ms ){
    for( int i = 0; i < n; i++ ){
        test_advance_ms(step_ms);
        halow_ack_tick();
    }
}

bool rx_frame( const uint8_t *src, const uint8_t *payload, uint16_t len, int8_t evm ){
    const uint8_t *out = NULL;
    uint16_t out_len = 0;
    bool delivered = halow_ack_on_rx(payload, len, src, MAC_ME, evm, &out, &out_len);
    CHECK( delivered == (out == payload && out_len == len) );
    return delivered;
}

void rx_ack_frame( const uint8_t *src, const uint8_t *ack, uint16_t len ){
    const uint8_t *out = NULL;
    uint16_t out_len = 0;
    (void)halow_ack_on_rx(ack, len, src, MAC_ME, 0, &out, &out_len);
}

uint16_t build_legacy_ack( uint8_t *buf, int8_t evm, uint16_t fid ){
    buf[0] = 0xA5; buf[1] = 0x5A; buf[2] = (uint8_t)evm;
    buf[3] = (uint8_t)(fid & 0xFF); buf[4] = (uint8_t)(fid >> 8);
    return 5;
}

uint16_t build_env_ack( uint8_t *buf, int8_t evm, uint16_t base ){
    buf[0] = 0xA5; buf[1] = 0x5A; buf[2] = 0x11;
    buf[3] = (uint8_t)evm;
    buf[4] = (uint8_t)(base & 0xFF); buf[5] = (uint8_t)(base >> 8);
    memset(&buf[6], 0, 8);
    return 14;
}

void env_ack_bit( uint8_t *buf, uint8_t bit ){
    buf[6 + bit / 8] |= (uint8_t)(1u << (bit % 8));
}

int count_ack_frames( void ){
    int n = 0;
    for( int i = 0; i < test_tx_count(); i++ ){
        const test_tx_cap_t *t = test_tx_at(i);
        if( t->len >= 3 && t->buf[0] == 0xA5 && t->buf[1] == 0x5A &&
            t->buf[2] != 0x10 ) n++;
    }
    return n;
}

int count_env_ack_frames( void ){
    int n = 0;
    for( int i = 0; i < test_tx_count(); i++ ){
        const test_tx_cap_t *t = test_tx_at(i);
        if( t->len == 14 && t->buf[0] == 0xA5 && t->buf[1] == 0x5A && t->buf[2] == 0x11 ) n++;
    }
    return n;
}

void fill_payload( uint8_t *p, uint16_t len, uint8_t seed ){
    for( uint16_t i = 0; i < len; i++ ) p[i] = (uint8_t)(seed + i);
}

void peer_mac( uint8_t *m, uint8_t id ){
    memset(m, id, 6);
}

void fr_clear( fid_ring_t *r ){
    memset(r, 0, sizeof(*r));
}

void fr_push( fid_ring_t *r, const uint8_t *mac, uint16_t fid ){
    memcpy(r->mac[r->n], mac, 6);
    r->fid[r->n] = fid;
    r->n = (r->n + 1) % 32;
}

void fr_ack_all( const fid_ring_t *r ){
    uint8_t ack[5];
    for( int k = 0; k < 32; k++ ){
        if( r->fid[k] != 0u )
            rx_ack_frame(r->mac[k], ack, build_legacy_ack(ack, EVM_M10, r->fid[k]));
    }
}

void ack_fid( const uint8_t *mac, uint16_t fid ){
    uint8_t ack[5];
    rx_ack_frame(mac, ack, build_legacy_ack(ack, EVM_M10, fid));
}

uint16_t fid_of( const uint8_t *p, uint16_t len ){
    return (uint16_t)(fnv1a(p, len) & 0xFFFFu);
}

void env_peer_ready( const uint8_t *mac ){
    uint8_t data[16];
    uint8_t env[12] = {0xA5, 0x5A, 0x10, 0x05, 0x00, 0x01, 0x04, 0x00, 'A', 'B', 'C', 'D'};
    fill_payload(data, sizeof(data), 1);
    CHECK( rx_frame(mac, data, sizeof(data), 0) );
    CHECK( rx_frame(mac, env, sizeof(env), 0) );
}

/* ============================== tests ============================== */

rns_stream_decoder_t g_dec;

int32_t fp_frame_cb( uint8_t *payload, uint16_t len, void *user ){
    (void)user;
    return halow_pkg_handler_tcp_to_rf(payload, len);
}

void fp_node_start( const halow_ack_config_t *cfg ){
    test_time_reset();
    configdb_reset();
    test_tx_reset();
    test_tcp_reset();
    test_vacancy_set(100000);
    test_malloc_reset();
    rns_stream_decoder_init(&g_dec, fp_frame_cb);
    halow_pkg_handler_init();
    if( cfg != NULL ) halow_ack_config_apply(cfg);
}

int32_t fp_feed( const uint8_t *data, uint16_t len, uint16_t *consumed ){
    return rns_stream_decoder_process(&g_dec, data, len, NULL, consumed);
}

void fp_idle( void ){
    halow_ack_flush();
}

/* type-1 RNS packet: [flags][hops][dest_hash16][context] payload
 * flags = hdr(0)<<6 | dest_type<<2 | packet_type; the dest hash IS the
 * link id: one dest_seed per link, payload_seed varies per packet */
uint16_t rns_pkt_build( uint8_t *out, uint8_t dest_seed, uint8_t payload_seed,
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
uint16_t rns_lr_build( uint8_t *out, uint8_t seed, uint32_t mtu ){
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

uint16_t slip_encode( uint8_t *out, const uint8_t *pkt, uint16_t len ){
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


void slipdec_init( slipdec_t *d ){
    memset(d, 0, sizeof(*d));
}

void slipdec_feed( slipdec_t *d, const uint8_t *data, uint16_t len ){
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
