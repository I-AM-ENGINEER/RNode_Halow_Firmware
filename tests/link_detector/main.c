#define LOG_LOCAL_LEVEL LOG_TRACE
#include "lib/logc/log.h"
#include "rns/stream_parser.h"
#include "rns/link_parser.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdbool.h>

#define LINK_MTU_LIMIT   (1024U)
#define TCP_TRACE_RAW    0

static rns_stream_decoder_t *g_dec_a = NULL;
static rns_stream_decoder_t *g_dec_b = NULL;

static int g_fd_a = -1;
static int g_fd_b = -1;
static bool g_stop = false;

static inline int tcp_listen( const char *host, const char *port ){
    struct addrinfo hints = {0};
    struct addrinfo *res = NULL;
    struct addrinfo *it = NULL;
    int fd = -1;
    int yes = 1;

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    if( getaddrinfo(host, port, &hints, &res) != 0 ){
        return -1;
    }

    for( it = res; it; it = it->ai_next ){
        fd = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
        if( fd < 0 ){
            continue;
        }

        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

        if( bind(fd, it->ai_addr, it->ai_addrlen) == 0 && listen(fd, 1) == 0 ){
            break;
        }

        close(fd);
        fd = -1;
    }

    freeaddrinfo(res);
    return fd;
}

static void trace_tcp_raw( const char *tag, const uint8_t *buf, uint32_t len ){
#if TCP_TRACE_RAW
    uint32_t i;
    char line[16 * 3 + 1];
    uint32_t pos;

    if( buf == NULL || len == 0U ){
        return;
    }

    log_trace("[%s] raw tcp len=%u", tag, (unsigned)len);

    for( i = 0U; i < len; i += 16U ){
        uint32_t j;
        uint32_t chunk = len - i;

        if( chunk > 16U ){
            chunk = 16U;
        }

        pos = 0U;
        for( j = 0U; j < chunk; j++ ){
            pos += (uint32_t)snprintf(&line[pos], sizeof(line) - pos, "%02X ", buf[i + j]);
        }

        if( pos > 0U ){
            line[pos - 1U] = '\0';
        }else{
            line[0] = '\0';
        }

        log_trace("[%s] raw %04u: %s", tag, (unsigned)i, line);
    }
#else
    (void)tag;
    (void)buf;
    (void)len;
#endif
}

static void log_link_event( const char *dir, const rns_link_packet_info_t *pkt ){
    if( pkt->packet_type == RNS_PACKET_TYPE_LINKREQUEST ){
        log_trace("[%s] LINK OPEN id=%02X%02X%02X%02X...",
            dir,
            pkt->link_id[0], pkt->link_id[1], pkt->link_id[2], pkt->link_id[3]
        );
        return;
    }

    if( pkt->destination_type != RNS_DESTINATION_TYPE_LINK ){
        return;
    }

    switch( pkt->context ){
        case RNS_CONTEXT_LRPROOF:
            log_trace("[%s] LINK PROOF id=%02X%02X%02X%02X...",
                dir,
                pkt->link_id[0], pkt->link_id[1], pkt->link_id[2], pkt->link_id[3]
            );
            break;

        case RNS_CONTEXT_LRRTT:
            log_trace("[%s] LINK ACTIVE id=%02X%02X%02X%02X...",
                dir,
                pkt->link_id[0], pkt->link_id[1], pkt->link_id[2], pkt->link_id[3]
            );
            break;

        case RNS_CONTEXT_LINKIDENTIFY:
            log_trace("[%s] LINK IDENTIFY id=%02X%02X%02X%02X...",
                dir,
                pkt->link_id[0], pkt->link_id[1], pkt->link_id[2], pkt->link_id[3]
            );
            break;

        case RNS_CONTEXT_KEEPALIVE:
            log_trace("[%s] LINK KEEPALIVE id=%02X%02X%02X%02X...",
                dir,
                pkt->link_id[0], pkt->link_id[1], pkt->link_id[2], pkt->link_id[3]
            );
            break;

        case RNS_CONTEXT_LINKCLOSE:
            log_trace("[%s] LINK CLOSE id=%02X%02X%02X%02X...",
                dir,
                pkt->link_id[0], pkt->link_id[1], pkt->link_id[2], pkt->link_id[3]
            );
            break;

        default:
            log_trace("[%s] LINK DATA ctx=0x%02X id=%02X%02X%02X%02X...",
                dir,
                (unsigned)pkt->context,
                pkt->link_id[0], pkt->link_id[1], pkt->link_id[2], pkt->link_id[3]
            );
            break;
    }
}

static inline bool send_all( int fd, const uint8_t *buf, uint32_t len ){
    uint32_t off = 0;

    while( off < len ){
        ssize_t wr = send(fd, buf + off, (size_t)(len - off), 0);
        if( wr <= 0 ){
            log_trace("send fail fd=%d", fd);
            return false;
        }

        off += (uint32_t)wr;
    }

    return true;
}

static inline size_t link_payload_offset( uint16_t packet_len, const rns_link_packet_info_t *pkt ){
    return (size_t)packet_len - (size_t)pkt->payload_len;
}

static inline uint32_t link_request_get_mtu( const uint8_t *packet, uint16_t packet_len, const rns_link_packet_info_t *pkt ){
    const size_t off = link_payload_offset(packet_len, pkt) + 64U;
    const uint32_t signalling =
        ((uint32_t)packet[off + 0] << 16U) |
        ((uint32_t)packet[off + 1] << 8U)  |
        ((uint32_t)packet[off + 2] << 0U);

    return signalling & 0x1FFFFFU;
}

static inline uint8_t link_request_get_mode( const uint8_t *packet, uint16_t packet_len, const rns_link_packet_info_t *pkt ){
    const size_t off = link_payload_offset(packet_len, pkt) + 64U;
    return (uint8_t)((packet[off + 0] >> 5U) & 0x07U);
}

static inline void link_request_set_signalling(
    uint8_t *packet,
    uint16_t packet_len,
    const rns_link_packet_info_t *pkt,
    uint8_t mode,
    uint32_t mtu
){
    const size_t off = link_payload_offset(packet_len, pkt) + 64U;
    const uint32_t signalling = (mtu & 0x1FFFFFU) | (((uint32_t)(mode & 0x07U)) << 21U);

    packet[off + 0] = (uint8_t)((signalling >> 16U) & 0xFFU);
    packet[off + 1] = (uint8_t)((signalling >> 8U) & 0xFFU);
    packet[off + 2] = (uint8_t)((signalling >> 0U) & 0xFFU);
}

static inline void maybe_clamp_link_mtu( uint8_t *packet, uint16_t packet_len, const char *dir ){
    rns_link_packet_info_t pkt;
    uint32_t mtu;
    uint8_t mode;

    if( rns_link_parser_parse(packet, packet_len, &pkt) != RNS_RET_OK ){
        return;
    }

    if( pkt.packet_type != RNS_PACKET_TYPE_LINKREQUEST ){
        return;
    }

    if( pkt.payload_len < 67U ){
        return;
    }

    mtu = link_request_get_mtu(packet, packet_len, &pkt);
    mode = link_request_get_mode(packet, packet_len, &pkt);

    if( mtu > LINK_MTU_LIMIT ){
        log_trace("[%s] clamp LINKREQUEST mtu %u -> %u",
            dir,
            (unsigned)mtu,
            (unsigned)LINK_MTU_LIMIT
        );

        link_request_set_signalling(packet, packet_len, &pkt, mode, LINK_MTU_LIMIT);
    }
}

static void forward_packet( int dst_fd, const char *dir, const uint8_t *payload, uint16_t payload_len ){
    uint8_t packet[RNS_STREAM_MAX_FRAME_SIZE];
    uint8_t *frame = NULL;
    uint32_t frame_len = 0;
    rns_link_packet_info_t pkt;

    if( payload_len > sizeof(packet) ){
        log_trace("[%s] packet too large: %u", dir, (unsigned)payload_len);
        g_stop = true;
        return;
    }

    memcpy(packet, payload, payload_len);

    maybe_clamp_link_mtu(packet, payload_len, dir);

    if( rns_link_parser_parse(packet, payload_len, &pkt) == RNS_RET_OK ){
        log_link_event(dir, &pkt);
    }

    if( rns_stream_encode_alloc(packet, payload_len, &frame, &frame_len) < 0 ){
        log_trace("[%s] encode failed", dir);
        g_stop = true;
        return;
    }

    if( frame == NULL || frame_len == 0U ){
        log_trace("[%s] encode returned empty frame", dir);
        free(frame);
        g_stop = true;
        return;
    }

    if( !send_all(dst_fd, frame, frame_len) ){
        free(frame);
        g_stop = true;
        return;
    }

    free(frame);
}

static void on_frame_a( const uint8_t *payload, uint16_t payload_len ){
    forward_packet(g_fd_b, "A->B", payload, payload_len);
}

static void on_frame_b( const uint8_t *payload, uint16_t payload_len ){
    forward_packet(g_fd_a, "B->A", payload, payload_len);
}

static inline int forward_once( int src_fd, rns_stream_decoder_t *decoder, const char *tag ){
    uint8_t buf[2048];
    ssize_t rd;

    rd = recv(src_fd, buf, sizeof(buf), 0);
    if( rd <= 0 ){
        return -1;
    }

    trace_tcp_raw(tag, buf, (uint32_t)rd);

    if( decoder != NULL ){
        rns_stream_decoder_process(decoder, buf, (uint16_t)rd);
    }

    return g_stop ? -1 : 0;
}

int main( int argc, char **args ){
    int listen_a_fd;
    int listen_b_fd;
    struct pollfd pfds[2];
    rns_stream_decoder_t dec_a;
    rns_stream_decoder_t dec_b;

    if( argc < 5 ){
        fprintf(stderr, "usage: %s <host_a> <port_a> <host_b> <port_b>\n", args[0]);
        return 1;
    }

    listen_a_fd = tcp_listen(args[1], args[2]);
    listen_b_fd = tcp_listen(args[3], args[4]);

    if( listen_a_fd < 0 || listen_b_fd < 0 ){
        fprintf(stderr, "listen fail\n");
        return 1;
    }

    log_debug("listen A %s:%s", args[1], args[2]);
    log_debug("listen B %s:%s", args[3], args[4]);

    g_fd_a = accept(listen_a_fd, NULL, NULL);
    if( g_fd_a < 0 ){
        fprintf(stderr, "accept A fail\n");
        close(listen_a_fd);
        close(listen_b_fd);
        return 1;
    }

    log_debug("client A connected");

    g_fd_b = accept(listen_b_fd, NULL, NULL);
    if( g_fd_b < 0 ){
        fprintf(stderr, "accept B fail\n");
        close(g_fd_a);
        close(listen_a_fd);
        close(listen_b_fd);
        return 1;
    }

    log_debug("client B connected");

    rns_stream_decoder_init(&dec_a, on_frame_a);
    rns_stream_decoder_init(&dec_b, on_frame_b);

    g_dec_a = &dec_a;
    g_dec_b = &dec_b;

    pfds[0].fd = g_fd_a;
    pfds[0].events = POLLIN;
    pfds[1].fd = g_fd_b;
    pfds[1].events = POLLIN;

    while( !g_stop ){
        if( poll(pfds, 2, -1) <= 0 ){
            continue;
        }

        if( pfds[0].revents & POLLIN ){
            if( forward_once(g_fd_a, g_dec_a, "A->B raw") < 0 ){
                break;
            }
        }

        if( pfds[1].revents & POLLIN ){
            if( forward_once(g_fd_b, g_dec_b, "B->A raw") < 0 ){
                break;
            }
        }

        if( pfds[0].revents & (POLLERR | POLLHUP | POLLNVAL) ){
            break;
        }

        if( pfds[1].revents & (POLLERR | POLLHUP | POLLNVAL) ){
            break;
        }
    }

    close(g_fd_a);
    close(g_fd_b);
    close(listen_a_fd);
    close(listen_b_fd);
    return 0;
}
