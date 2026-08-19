#ifndef __RNS_STREAM_H__
#define __RNS_STREAM_H__

#include "rns/defines.h"
#include <stdint.h>

/* on_frame returns 0 on success, <0 (e.g. HALOW_ACK_TX_THROTTLE) to signal
 * backpressure; rns_stream_decoder_process stops and propagates it to the caller
 * so the TCP recv loop can throttle. */
typedef int32_t (*rns_stream_frame_cb_t)( uint8_t *payload, uint16_t payload_len, void *user );

typedef enum {
    RNS_STREAM_STATE_WAIT_FRAME_START = 0,
    RNS_STREAM_STATE_READ_FRAME,
    RNS_STREAM_STATE_READ_ESCAPED_BYTE
} rns_stream_state_t;

typedef struct {
    rns_stream_frame_cb_t on_frame;
    rns_stream_state_t state;
    uint16_t frame_len;
    bool     held;       /* frame_buffer holds a complete frame the TX path
                          * rejected with THROTTLE; retry it before consuming */
    uint8_t frame_buffer[RNS_STREAM_MAX_FRAME_SIZE];
} rns_stream_decoder_t;

void rns_stream_decoder_init( rns_stream_decoder_t *decoder, rns_stream_frame_cb_t on_frame );
void rns_stream_decoder_reset( rns_stream_decoder_t *decoder );
int32_t rns_stream_decoder_retry_held( rns_stream_decoder_t *decoder, void *user );
/* Returns 0 normally, or HALOW_ACK_TX_THROTTLE if a decoded frame was rejected
 * by the TX path -- in which case processing stops (the frame is HELD inside
 * the decoder, *consumed reports how many input bytes were taken) and the
 * caller must re-feed the unconsumed tail later. A frame accepted from TCP is
 * never silently dropped here. */
int32_t rns_stream_decoder_process( rns_stream_decoder_t *decoder, const uint8_t *data, uint16_t data_len, void *user, uint16_t *consumed );

int32_t rns_stream_encode_alloc(
    const uint8_t *payload,
    uint32_t payload_len,
    uint8_t **out_frame,
    uint32_t *out_frame_len
);

#endif // __RNS_STREAM_H__
