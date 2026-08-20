#include "sys_config.h"
#define LOG_LOCAL_LEVEL LOG_LEVEL_HALOW_PKG_HANDLER
#include "basic_include.h"
#include "lib/logc/log.h"
#include "halow_pkg_handler.h"
#include "halow_ack.h"
#include "rns/link_db.h"
#include "rns/link_parser.h"
#include "rns/link_utils.h"
#include "rns/stream_parser.h"
#include "utils.h"
#include "halow.h"
#include "configdb.h"
#include "tcp_server.h"

#define RNS_MTU_LIMIT_KEY   CONFIGDB_ADD_MODULE("rns") ".mtu"
#define RNS_MTU_LIMIT_DEF   (500U)
#define RNS_MTU_CACHE_MS    5000u

volatile uint32_t g_dbg_rns_rx_calls;
volatile uint32_t g_dbg_rns_rx_parse_fail;
volatile uint32_t g_dbg_rns_rx_valid;
volatile uint32_t g_dbg_rns_rx_reg_ok;
volatile uint32_t g_dbg_rns_rx_reg_fail;
volatile uint32_t g_dbg_rns_tx_parse_fail;

/* ================= RNS MTU limit (configdb, cached) ================= */

static int16_t g_rns_mtu_cache;
static uint64_t g_rns_mtu_cache_jiff;
static bool g_rns_mtu_cache_valid;

int16_t rns_mtu_limit_get( void ){
    if( !g_rns_mtu_cache_valid ||
        (os_jiffies() - g_rns_mtu_cache_jiff) >= os_msecs_to_jiffies(RNS_MTU_CACHE_MS) ){
        int16_t val = RNS_MTU_LIMIT_DEF;
        configdb_get_i16(RNS_MTU_LIMIT_KEY, &val);
        g_rns_mtu_cache = val;
        g_rns_mtu_cache_jiff = os_jiffies();
        g_rns_mtu_cache_valid = true;
    }
    return g_rns_mtu_cache;
}

void rns_mtu_limit_set( int16_t mtu ){
    configdb_set_i16(RNS_MTU_LIMIT_KEY, &mtu);
    g_rns_mtu_cache = mtu;
    g_rns_mtu_cache_jiff = os_jiffies();
    g_rns_mtu_cache_valid = true;
}

/* ================= RF -> TCP ================= */

static uint32_t link_mtu_limit( void ){
    uint32_t hw = halow_get_mtu(halow_cfg_mcs_get_cached());
    uint32_t rl = (uint32_t)rns_mtu_limit_get();
    return (rl < hw) ? rl : hw;
}

static uint32_t link_effective_mtu( uint32_t advertised ){
    uint32_t lim = link_mtu_limit();
    return (advertised == 0u || advertised > lim) ? lim : advertised;
}

static bool peer_mac_known( const uint8_t mac[6] ){
    for( uint32_t i = 0; i < 6; i++ )
        if( mac[i] != RNS_LINK_MAC_UNKNOWN_BYTE ) return true;
    return false;
}

static void deliver_rns_frame( const uint8_t *pkg, uint16_t len,
                               const uint8_t *src_mac, bool unicast_to_me ){
    rns_link_packet_info_t packet_info;
    uint8_t *allocated_rx = NULL;
    uint32_t allocated_len = 0u;

    int32_t res = rns_link_parser_parse(pkg, len, &packet_info);
    if( res != RNS_RET_OK ){
        g_dbg_rns_rx_parse_fail++;
        log_warn("rx rns package parse error=%d len=%u", (int)res, (unsigned int)len);
        return;
    }

    if( packet_info.valid ){
        bool is_linkrequest = (packet_info.packet_type == RNS_PACKET_TYPE_LINKREQUEST);
        uint32_t rx_mtu = 0;
        if( is_linkrequest ){
            (void)rns_link_utils_get_mtu(pkg, len, &packet_info, &rx_mtu);
            rx_mtu = link_effective_mtu(rx_mtu);
        }
        g_dbg_rns_rx_valid++;
        int32_t rr = rns_link_db_package_register(&packet_info, RNS_PACKET_DIRECTION_RX,
                                                  src_mac, rx_mtu, is_linkrequest,
                                                  unicast_to_me);
        if( rr == RNS_RET_OK ) g_dbg_rns_rx_reg_ok++;
        else                   g_dbg_rns_rx_reg_fail++;
    }

    res = rns_stream_encode_alloc(pkg, len, &allocated_rx, &allocated_len);
    if( res != 0 || allocated_rx == NULL || allocated_len == 0u ){
        log_warn("rx rns tcp encoding fail res=%d in_len=%u out_len=%u",
                 (int)res, (unsigned int)len, (unsigned int)allocated_len);
        return;
    }
    res = tcp_server_send(allocated_rx, allocated_len);
    if( res != 0 ){
        extern halow_tx_dbg_t g_tx_dbg;
        g_tx_dbg.rf_tcp_dropped++;
        log_warn("rf->tcp ring full res=%d, drop len=%u", (int)res, (unsigned int)allocated_len);
    }
    free(allocated_rx);
}

static bool bundle_walk_valid( const uint8_t *pkg, uint16_t len,
                               uint16_t hdr_len, uint8_t nsub ){
    uint32_t off = hdr_len;
    for( uint32_t i = 0u; i < nsub; i++ ){
        if( off + 2u > len ) return false;
        uint16_t slen = (uint16_t)((uint16_t)pkg[off] | ((uint16_t)pkg[off + 1] << 8));
        off += 2u;
        if( (uint32_t)off + slen > len ) return false;
        off += slen;
    }
    return off == len;
}

static void bundle_split_deliver( const uint8_t *pkg, uint16_t len, uint16_t hdr_len,
                                  uint8_t nsub, const uint8_t src_mac[6], bool unicast_to_me ){
    uint32_t o = hdr_len;
    for( uint32_t i = 0u; i < nsub; i++ ){
        uint16_t slen = (uint16_t)((uint16_t)pkg[o] | ((uint16_t)pkg[o + 1] << 8));
        o += 2u;
        deliver_rns_frame(&pkg[o], slen, src_mac, unicast_to_me);
        o += slen;
    }
}

static bool is_env_bundle( const uint8_t *pkg, uint16_t len ){
    return ( len >= (uint16_t)(HALOW_ENV_BUNDLE_HDR + 2u) &&
             pkg[0] == HALOW_ENV_MAGIC0 && pkg[1] == HALOW_ENV_MAGIC1 &&
             halow_env_type(pkg) == HALOW_ENV_TYPE_BUNDLE &&
             halow_env_ver(pkg) == HALOW_ENV_VER );
}

static bool is_legacy_bundle( const uint8_t *pkg, uint16_t len ){
    return ( len >= 4u &&
             pkg[0] == HALOW_ACK_AGG_MAGIC0 && pkg[1] == HALOW_ACK_AGG_MAGIC1 &&
             pkg[2] >= 2u );
}

void halow_pkg_handler_rf_to_tcp( uint8_t* pkg, uint16_t len,
                                  const uint8_t *src_mac, const uint8_t *dst_mac,
                                  int8_t evm ){
    const uint8_t *inner;
    uint16_t inner_len;

    if( !halow_ack_on_rx(pkg, len, src_mac, dst_mac, evm, &inner, &inner_len) ) return;
    pkg = (uint8_t *)inner;
    len = inner_len;
    g_dbg_rns_rx_calls++;

    bool unicast_to_me = ( dst_mac != NULL && memcmp(dst_mac, mac_broadcast, 6) != 0 );

    if( is_env_bundle(pkg, len) ){
        if( !bundle_walk_valid(pkg, len, HALOW_ENV_BUNDLE_HDR, pkg[5]) ){
            halow_ack_env_malformed();
            return;
        }
        bundle_split_deliver(pkg, len, HALOW_ENV_BUNDLE_HDR, pkg[5],
                             src_mac, unicast_to_me);
        return;
    }

    if( is_legacy_bundle(pkg, len) &&
        bundle_walk_valid(pkg, len, 3u, pkg[2]) ){
        bundle_split_deliver(pkg, len, 3u, pkg[2], src_mac, unicast_to_me);
        return;
    }

    deliver_rns_frame(pkg, len, src_mac, unicast_to_me);
}

/* ================= TCP -> RF ================= */

static void tx_linkrequest_mtu_clamp( uint8_t *pkg, uint16_t len,
                                      rns_link_packet_info_t *info ){
    uint32_t original_mtu = 0;
    uint32_t mtu_limit = link_mtu_limit();

    rns_link_utils_clamp_mtu(pkg, len, info, mtu_limit, &original_mtu);
    log_info("cap link MTU from %db to %db", (int)original_mtu, (int)mtu_limit);

    uint32_t stored_mtu = link_effective_mtu(original_mtu);
    rns_link_db_package_register(info, RNS_PACKET_DIRECTION_TX,
                                 NULL, stored_mtu, true, false);
}

int32_t halow_pkg_handler_tcp_to_rf( uint8_t* pkg, uint16_t len ){
    rns_link_packet_info_t packet_info;

    int32_t res = rns_link_parser_parse(pkg, len, &packet_info);
    if( res != RNS_RET_OK ){
        g_dbg_rns_tx_parse_fail++;
        log_warn("tx rns package parse error=%d", res);
        return 0;
    }

    log_trace("receive pkg type=%d", (int)packet_info.packet_type);

    if( packet_info.valid && packet_info.packet_type == RNS_PACKET_TYPE_LINKREQUEST ){
        tx_linkrequest_mtu_clamp(pkg, len, &packet_info);
    }else if( packet_info.valid ){
        rns_link_db_package_register(&packet_info, RNS_PACKET_DIRECTION_TX,
                                     NULL, 0, false, false);
    }

    rns_link_db_link_t link;
    const uint8_t *dest = ( packet_info.valid &&
                            rns_link_db_link_snapshot_by_id(packet_info.link_id, &link) &&
                            peer_mac_known(link.remote_mac) )
                          ? link.remote_mac : mac_broadcast;

    return halow_ack_tx(pkg, len, dest);
}

void halow_pkg_handler_init( void ){
    rns_link_db_init();
    halow_ack_init();
}
