#ifndef TEST_HELPERS_H
#define TEST_HELPERS_H

#include <stdint.h>
#include <stdbool.h>

#include "halow.h"
#include "halow_ack.h"
#include "harness.h"

/* peer MACs used across scenario files */
extern const uint8_t MAC_ME[6];
extern const uint8_t PEER_A[6];
extern const uint8_t PEER_B[6];
extern const uint8_t PEER_C[6];
extern const uint8_t PEER_D[6];
extern const uint8_t PEER_E[6];
extern const uint8_t PEER_R[6];
extern const uint8_t PEER_LO[6];
extern const uint8_t PEER_HI[6];

#define EVM_M10 ((int8_t)(-10))
#define EVM_M25 ((int8_t)(-25))
#define EVM_M30 ((int8_t)(-30))

/* SLIP decoder capture bounds (slipdec_t) */
#define SLIDEC_MAX_FRAMES 320
#define SLIDEC_MAX_LEN    2060

extern const uint8_t MAC_ME[6];
extern const uint8_t PEER_A[6];
extern const uint8_t PEER_B[6];
extern const uint8_t PEER_C[6];
extern const uint8_t PEER_D[6];
extern const uint8_t PEER_E[6];
extern const uint8_t PEER_R[6];
extern const uint8_t PEER_LO[6];
extern const uint8_t PEER_HI[6];
uint32_t fnv1a( const uint8_t *p, uint16_t len );
void cfg_base( halow_ack_config_t *c );
void node_start( const halow_ack_config_t *cfg );
void run_ticks( int n, uint32_t step_ms );
bool rx_frame( const uint8_t *src, const uint8_t *payload, uint16_t len, int8_t evm );
void rx_ack_frame( const uint8_t *src, const uint8_t *ack, uint16_t len );
uint16_t build_legacy_ack( uint8_t *buf, int8_t evm, uint16_t fid );
uint16_t build_env_ack( uint8_t *buf, int8_t evm, uint16_t base );
void env_ack_bit( uint8_t *buf, uint8_t bit );
int count_ack_frames( void );
int count_env_ack_frames( void );
void fill_payload( uint8_t *p, uint16_t len, uint8_t seed );
void peer_mac( uint8_t *m, uint8_t id );
typedef struct {
    uint16_t fid[32];
    uint8_t  mac[32][6];
    int      n;
} fid_ring_t;

void fr_clear( fid_ring_t *r );
void fr_push( fid_ring_t *r, const uint8_t *mac, uint16_t fid );
void fr_ack_all( const fid_ring_t *r );
void ack_fid( const uint8_t *mac, uint16_t fid );
uint16_t fid_of( const uint8_t *p, uint16_t len );
void env_peer_ready( const uint8_t *mac );
extern rns_stream_decoder_t g_dec;
int32_t fp_frame_cb( uint8_t *payload, uint16_t len, void *user );
void fp_node_start( const halow_ack_config_t *cfg );
int32_t fp_feed( const uint8_t *data, uint16_t len, uint16_t *consumed );
void fp_idle( void );
uint16_t rns_pkt_build( uint8_t *out, uint8_t dest_seed, uint8_t payload_seed,
                          uint16_t payload_len, uint8_t packet_type, uint8_t dest_type );
uint16_t rns_lr_build( uint8_t *out, uint8_t seed, uint32_t mtu );
uint16_t slip_encode( uint8_t *out, const uint8_t *pkt, uint16_t len );
typedef struct {
    uint8_t buf[SLIDEC_MAX_FRAMES][SLIDEC_MAX_LEN];
    uint16_t len[SLIDEC_MAX_FRAMES];
    int n;
    int in_frame;
    int esc;
    uint16_t pos;
} slipdec_t;

void slipdec_init( slipdec_t *d );
void slipdec_feed( slipdec_t *d, const uint8_t *data, uint16_t len );

/* debug counters exported by halow_pkg_handler.c */
extern volatile uint32_t g_dbg_rns_rx_calls;
extern volatile uint32_t g_dbg_rns_rx_parse_fail;
extern volatile uint32_t g_dbg_rns_rx_valid;
extern volatile uint32_t g_dbg_rns_rx_reg_ok;
extern volatile uint32_t g_dbg_rns_rx_reg_fail;
extern volatile uint32_t g_dbg_rns_tx_parse_fail;

#endif /* TEST_HELPERS_H */
