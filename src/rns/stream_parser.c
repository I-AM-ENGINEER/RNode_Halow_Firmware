#include "rns/stream_parser.h"
#define LOG_LOCAL_LEVEL RNS_STREAM_PARSER_LOG_LEVEL
#include "lib/logc/log.h"
#include "halow_ack.h"      /* HALOW_ACK_TX_THROTTLE: the only hold-worthy status */
#include <string.h>
#include <stdlib.h>

#define RNS_STREAM_FLAG      0x7Eu
#define RNS_STREAM_ESC       0x7Du
#define RNS_STREAM_ESC_MASK  0x20u

static int32_t rns_stream_emit_frame( rns_stream_decoder_t *decoder, void *user ){
    if( decoder == NULL || decoder->on_frame == NULL ){
        return 0;
    }

    if( decoder->frame_len == 0u ){
        log_trace("frame format error: empty frame");
        return 0;
    }

    log_trace("frame received: payload_len=%u", (unsigned int)decoder->frame_len);
    return decoder->on_frame(decoder->frame_buffer, decoder->frame_len, user);
}

void rns_stream_decoder_init( rns_stream_decoder_t *decoder, rns_stream_frame_cb_t on_frame ){
    if( decoder == NULL ){
        return;
    }

    memset(decoder, 0, sizeof(*decoder));
    decoder->on_frame = on_frame;
}

void rns_stream_decoder_reset( rns_stream_decoder_t *decoder ){
    if( decoder == NULL ){
        return;
    }

    decoder->state = RNS_STREAM_STATE_WAIT_FRAME_START;
    decoder->frame_len = 0u;
    decoder->held = false;
}

int32_t rns_stream_decoder_retry_held( rns_stream_decoder_t *decoder, void *user ){
    if( decoder == NULL || !decoder->held ){
        return 0;
    }
    int32_t r = rns_stream_emit_frame(decoder, user);
    if( r == HALOW_ACK_TX_THROTTLE ){
        return r;
    }
    decoder->held = false;
    decoder->state = RNS_STREAM_STATE_READ_FRAME;
    decoder->frame_len = 0u;
    return r;
}

int32_t rns_stream_decoder_process( rns_stream_decoder_t *decoder, const uint8_t *data, uint16_t data_len, void *user, uint16_t *consumed ){
    uint16_t i;

    if( decoder == NULL || data == NULL || data_len == 0u ){
        if( consumed != NULL ) *consumed = 0u;
        return 0;
    }

    /* A HELD frame retries FIRST, before any new byte is consumed. */
    if( decoder->held ){
        int32_t r = rns_stream_emit_frame(decoder, user);
        if( r == HALOW_ACK_TX_THROTTLE ){
            if( consumed != NULL ) *consumed = 0u;
            return r;
        }
        decoder->held = false;
        decoder->state = RNS_STREAM_STATE_READ_FRAME;
        decoder->frame_len = 0u;
    }

    for( i = 0; i < data_len; i++ ){
        uint8_t byte = data[i];

        /* Fast path: a mid-frame run of plain bytes is copied without the
         * per-byte state checks (this loop is the TX-pipeline hotspot).
         * Falls through to the generic logic on FLAG/ESC/end-of-input;
         * overflow resyncs exactly like the generic path. */
        if( decoder->state == RNS_STREAM_STATE_READ_FRAME &&
            byte != RNS_STREAM_FLAG && byte != RNS_STREAM_ESC ){
            const uint8_t *src = &data[i];
            const uint8_t *end = &data[data_len];
            uint8_t *dstp      = &decoder->frame_buffer[decoder->frame_len];
            uint8_t *dst_end   = &decoder->frame_buffer[sizeof(decoder->frame_buffer)];

            while( src < end ){
                uint8_t b = *src;
                if( b == RNS_STREAM_FLAG || b == RNS_STREAM_ESC ) break;
                if( dstp >= dst_end ){
                    log_trace(
                        "format error: frame overflow, max=%u",
                        (unsigned int)sizeof(decoder->frame_buffer)
                    );
                    decoder->state = RNS_STREAM_STATE_WAIT_FRAME_START;
                    decoder->frame_len = 0u;
                    break;
                }
                *dstp++ = b;
                src++;
            }
            if( decoder->state == RNS_STREAM_STATE_READ_FRAME ){
                decoder->frame_len = (uint16_t)(dstp - decoder->frame_buffer);
            }
            i = (uint16_t)(src - data);
            if( i >= data_len ) break;
            byte = *src;
        }

        if( byte == RNS_STREAM_FLAG ){
            if( decoder->state == RNS_STREAM_STATE_READ_ESCAPED_BYTE ){
                log_trace(
                    "format error: frame ended after escape byte, buffered_len=%u",
                    (unsigned int)decoder->frame_len
                );
            }

            if(
                (decoder->state == RNS_STREAM_STATE_READ_FRAME ||
                 decoder->state == RNS_STREAM_STATE_READ_ESCAPED_BYTE) &&
                decoder->frame_len > 0u
            ){
                int32_t r = rns_stream_emit_frame(decoder, user);
                if( r == HALOW_ACK_TX_THROTTLE ){
                    /* CONTRACT: the frame is NOT dropped -- it stays complete
                     * in frame_buffer (held) and the input stops right after
                     * this FLAG; *consumed reports the taken bytes and the
                     * caller must re-feed the tail. */
                    decoder->held = true;
                    if( consumed != NULL ) *consumed = (uint16_t)(i + 1u);
                    return r;
                }
            }

            decoder->state = RNS_STREAM_STATE_READ_FRAME;
            decoder->frame_len = 0u;
            continue;
        }

        if( decoder->state == RNS_STREAM_STATE_WAIT_FRAME_START ){
            continue;
        }

        if( decoder->state == RNS_STREAM_STATE_READ_ESCAPED_BYTE ){
            byte = (uint8_t)(byte ^ RNS_STREAM_ESC_MASK);
            decoder->state = RNS_STREAM_STATE_READ_FRAME;
        }else if( byte == RNS_STREAM_ESC ){
            decoder->state = RNS_STREAM_STATE_READ_ESCAPED_BYTE;
            continue;
        }

        if( decoder->frame_len >= sizeof(decoder->frame_buffer) ){
            log_trace(
                "format error: frame overflow, max=%u",
                (unsigned int)sizeof(decoder->frame_buffer)
            );
            decoder->state = RNS_STREAM_STATE_WAIT_FRAME_START;
            decoder->frame_len = 0u;
            continue;
        }

        decoder->frame_buffer[decoder->frame_len++] = byte;
    }
    if( consumed != NULL ) *consumed = data_len;
    return 0;
}

/* Escaped size of payload (one tight scan, no writes). */
uint32_t rns_stream_escape_size( const uint8_t *payload, uint32_t payload_len ){
    uint32_t i;
    uint32_t n = payload_len;

    for( i = 0; i < payload_len; i++ ){
        uint8_t b = payload[i];
        if( b == RNS_STREAM_FLAG || b == RNS_STREAM_ESC ) n++;
    }
    return n;
}

/* Escape payload into dst; dst MUST have rns_stream_escape_size() bytes. */
void rns_stream_escape_write( uint8_t *dst, const uint8_t *payload, uint32_t payload_len ){
    uint32_t i;
    uint32_t o = 0u;

    for( i = 0; i < payload_len; i++ ){
        uint8_t b = payload[i];
        if( b == RNS_STREAM_FLAG || b == RNS_STREAM_ESC ){
            dst[o++] = RNS_STREAM_ESC;
            dst[o++] = (uint8_t)(b ^ RNS_STREAM_ESC_MASK);
        }else{
            dst[o++] = b;
        }
    }
}

/* SLIP-frame payload into dst: FLAG + escaped payload + FLAG. Returns the
 * total frame length; when dst is NULL or dst_cap is too small, nothing is
 * written and the REQUIRED length is returned. Exactly two scans. */
uint32_t rns_stream_encode_frame( uint8_t *dst, uint32_t dst_cap,
                                  const uint8_t *payload, uint32_t payload_len )
{
    uint32_t esc = rns_stream_escape_size(payload, payload_len);
    uint32_t n = esc + 2u;

    if( dst == NULL || dst_cap < n ) return n;
    dst[0] = RNS_STREAM_FLAG;
    rns_stream_escape_write(dst + 1u, payload, payload_len);
    dst[n - 1u] = RNS_STREAM_FLAG;
    return n;
}

int32_t rns_stream_encode_alloc(
    const uint8_t *payload,
    uint32_t payload_len,
    uint8_t **out_frame,
    uint32_t *out_frame_len
)
{
    uint32_t encoded_frame_len;
    uint8_t *encoded_frame;

    if( payload == NULL || out_frame == NULL || out_frame_len == NULL || payload_len == 0u ){
        log_trace(
            "encode error: invalid args, payload=%p len=%u out_frame=%p out_len=%p",
            payload,
            (unsigned int)payload_len,
            out_frame,
            out_frame_len
        );
        return -1;
    }

    encoded_frame_len = rns_stream_escape_size(payload, payload_len) + 2u;
    encoded_frame = malloc(encoded_frame_len);
    if( encoded_frame == NULL ){
        log_trace("encode error: malloc failed, frame_len=%u", (unsigned int)encoded_frame_len);
        return -2;
    }
    encoded_frame[0] = RNS_STREAM_FLAG;
    rns_stream_escape_write( encoded_frame + 1u, payload, payload_len );
    encoded_frame[encoded_frame_len - 1u] = RNS_STREAM_FLAG;

    *out_frame = encoded_frame;
    *out_frame_len = encoded_frame_len;

    return 0;
}
