#include "rns/stream_parser.h"
#define LOG_LOCAL_LEVEL RNS_STREAM_PARSER_LOG_LEVEL
#include "lib/logc/log.h"
#include <string.h>
#include <stdlib.h>

#define RNS_STREAM_FLAG      0x7Eu
#define RNS_STREAM_ESC       0x7Du
#define RNS_STREAM_ESC_MASK  0x20u

static void rns_stream_emit_frame( rns_stream_decoder_t *decoder, void *user ){
    if( decoder == NULL || decoder->on_frame == NULL ){
        return;
    }

    if( decoder->frame_len == 0u ){
        log_trace("frame format error: empty frame");
        return;
    }

    log_trace("frame received: payload_len=%u", (unsigned int)decoder->frame_len);
    decoder->on_frame(decoder->frame_buffer, decoder->frame_len, user);
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
}

void rns_stream_decoder_process( rns_stream_decoder_t *decoder, const uint8_t *data, uint16_t data_len, void *user ){
    uint16_t i;

    if( decoder == NULL || data == NULL || data_len == 0u ){
        return;
    }

    for( i = 0; i < data_len; i++ ){
        uint8_t byte = data[i];

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
                rns_stream_emit_frame(decoder, user);
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
}

static uint32_t rns_stream_get_escaped_size( const uint8_t *data, uint32_t data_len ){
    uint32_t i;
    uint32_t escaped_len = 0u;

    for( i = 0; i < data_len; i++ ){
        escaped_len++;
        if( data[i] == RNS_STREAM_FLAG || data[i] == RNS_STREAM_ESC ){
            escaped_len++;
        }
    }

    return escaped_len;
}

static uint32_t rns_stream_write_escaped_bytes( uint8_t *dst, const uint8_t *src, uint32_t src_len ){
    uint32_t i;
    uint32_t dst_len = 0u;

    for( i = 0; i < src_len; i++ ){
        if( src[i] == RNS_STREAM_FLAG || src[i] == RNS_STREAM_ESC ){
            dst[dst_len++] = RNS_STREAM_ESC;
            dst[dst_len++] = (uint8_t)(src[i] ^ RNS_STREAM_ESC_MASK);
        }else{
            dst[dst_len++] = src[i];
        }
    }

    return dst_len;
}

int32_t rns_stream_encode_alloc(
    const uint8_t *payload,
    uint32_t payload_len,
    uint8_t **out_frame,
    uint32_t *out_frame_len
){
    uint32_t encoded_frame_len;
    uint8_t *encoded_frame;
    uint32_t offset = 0u;

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

    encoded_frame_len = 2u + rns_stream_get_escaped_size(payload, payload_len);

    encoded_frame = malloc(encoded_frame_len);
    if( encoded_frame == NULL ){
        log_trace("encode error: malloc failed, frame_len=%u", (unsigned int)encoded_frame_len);
        return -2;
    }

    encoded_frame[offset++] = RNS_STREAM_FLAG;
    offset += rns_stream_write_escaped_bytes(encoded_frame + offset, payload, payload_len);
    encoded_frame[offset++] = RNS_STREAM_FLAG;

    *out_frame = encoded_frame;
    *out_frame_len = offset;

    return 0;
}
