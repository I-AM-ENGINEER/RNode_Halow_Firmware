#include "sys_config.h"
#define LOG_LOCAL_LEVEL LOG_LEVEL_HALOW_PKG_HANDLER
#include "basic_include.h"
#include "halow.h"
#include "utils.h"
#include "halow_ack.h"
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

int main( void ){
    halow_ack_config_t cfg;
    uint8_t f[200];
    uint8_t r[120];
    const uint8_t *o = NULL;
    uint16_t ol = 0;

    halow_ack_config_set_default(&cfg);
    cfg.timeout_ms  = 50;
    cfg.max_retries = 8;
    cfg.agg_hold_ms = 2;
    cfg.ack_hold_ms = 0;
    cfg.rate_adapt  = 0;
    cfg.window      = 16;
    cfg.data_gap_ms = 0;

    test_time_reset();
    configdb_reset();
    test_tx_reset();
    test_vacancy_set(100000);
    halow_ack_init();
    halow_ack_config_apply(&cfg);

    for( int i = 0; i < 30000; i++ ){
        fill_payload(f, sizeof(f), (uint8_t)i);
        (void)halow_ack_tx(f, sizeof(f), PEER);
        halow_ack_tick();
        ack_fid(PEER, (uint16_t)(fnv1a(f, sizeof(f)) & 0xFFFFu));
    }
    printf("bench: tx+ack 30000\n");

    for( int i = 0; i < 30000; i++ ){
        fill_payload(r, sizeof(r), (uint8_t)i);
        (void)halow_ack_on_rx(r, sizeof(r), PEER, MAC_ME, EVM_M10, &o, &ol);
        if( (i % 16) == 0 ) halow_ack_tick();
    }
    printf("bench: rx+dedup 30000\n");

    for( int i = 0; i < 8; i++ ){
        fill_payload(f, sizeof(f), (uint8_t)i);
        (void)halow_ack_tx(f, sizeof(f), PEER);
    }
    halow_ack_tick();
    for( int i = 0; i < 100000; i++ ) halow_ack_tick();
    printf("bench: tick 100000\n");
    printf("bench: done tx=%d\n", test_tx_count());
    return 0;
}
