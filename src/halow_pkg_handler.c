#include "sys_config.h"
#define LOG_LOCAL_LEVEL LOG_LEVEL_HALOW_PKG_HANDLER
#include "lib/logc/log.h"
#include "halow_pkg_handler.h"
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

/* Debug counters for the RX registration chain (exposed via
 * /api/get_reticulum_links) to locate where a received frame fails to become a
 * registered link: parse -> valid -> register. */
volatile uint32_t g_dbg_rns_rx_calls;
volatile uint32_t g_dbg_rns_rx_parse_fail;
volatile uint32_t g_dbg_rns_rx_valid;
volatile uint32_t g_dbg_rns_rx_reg_ok;
volatile uint32_t g_dbg_rns_rx_reg_fail;

/* A peer MAC is "unknown" until learned from a received frame (addr2). The link
 * db stores it as the RNS_LINK_MAC_UNKNOWN_BYTE (0xFF) sentinel on link
 * creation; TX falls back to broadcast while still unknown. */
static bool halow_peer_mac_known( const uint8_t mac[6] ){
    uint32_t i;
    for( i = 0; i < 6; i++ ){
        if( mac[i] != RNS_LINK_MAC_UNKNOWN_BYTE ){
            return true;
        }
    }
    return false;
}

void halow_pkg_handler_rf_to_tcp( uint8_t* pkg, uint16_t len, const uint8_t *src_mac ){
    int32_t res;
    rns_link_packet_info_t packet_info;
    uint8_t *allocated_rx = NULL;
    uint32_t allocated_len = 0u;

    g_dbg_rns_rx_calls++;
    res = rns_link_parser_parse(pkg, len, &packet_info);
    if( res != RNS_RET_OK ){
        g_dbg_rns_rx_parse_fail++;
        log_warn("rx rns package parse error=%d len=%u", (int)res, (unsigned int)len);
        return;
    }

    /* Register the Reticulum link (creating/updating it) and learn the peer's
     * MAC from addr2. remote_mac is later used by the TX path to address the
     * neighbour directly instead of broadcasting. */
    if( packet_info.valid ){
        int32_t rr;
        uint32_t rx_mtu = 0;
        bool have_mtu = (packet_info.packet_type == RNS_PACKET_TYPE_LINKREQUEST &&
                         rns_link_utils_get_mtu(pkg, len, &packet_info, &rx_mtu) == RNS_RET_OK);

        g_dbg_rns_rx_valid++;
        rr = rns_link_db_package_register(&packet_info, RNS_PACKET_DIRECTION_RX,
                                          src_mac, rx_mtu, have_mtu);
        if( rr == RNS_RET_OK ){
            g_dbg_rns_rx_reg_ok++;
        }else{
            g_dbg_rns_rx_reg_fail++;
        }
    }

    res = rns_stream_encode_alloc(pkg, len, &allocated_rx, &allocated_len);
    if( res != 0 || allocated_rx == NULL || allocated_len == 0u ){
        log_warn(
            "rx rns tcp encoding fail res=%d in_len=%u out=%p out_len=%u",
            (int)res,
            (unsigned int)len,
            allocated_rx,
            (unsigned int)allocated_len
        );
        return;
    }

    log_trace(
        "rf->tcp encoded in_len=%u out_len=%u",
        (unsigned int)len,
        (unsigned int)allocated_len,
        allocated_rx
    );

    /* Non-blocking enqueue: tcp_server_send returns <0 when the TX ring is full
     * (see tcp_server.c). This runs on the LMAC RX context which must not stall
     * — dropping here is correct; TCP reliability / host retransmit covers the
     * loss. */
    res = tcp_server_send(allocated_rx, allocated_len);
    if( res != 0 ){
        log_warn("rf->tcp ring full res=%d, drop len=%u", (int)res, (unsigned int)allocated_len);
    }
    free(allocated_rx);
}

void halow_pkg_handler_tcp_to_rf( uint8_t* pkg, uint16_t len ){
    int32_t res;
    rns_link_packet_info_t packet_info;

    res = rns_link_parser_parse(pkg, len, &packet_info);
    if(res != RNS_RET_OK){
        log_warn("tx rns package parse error=%d", res);
        return;
    }

    log_trace("receive pkg type=%d", (int)packet_info.packet_type);

    if( packet_info.valid && packet_info.packet_type == RNS_PACKET_TYPE_LINKREQUEST ){
        uint32_t original_mtu = 0;
        uint32_t hw_mtu;
        uint32_t mtu_limit;
        uint32_t stored_mtu;
        halow_config_t cfg;
        int16_t rns_mtu_limit;

        halow_config_load(&cfg);
        hw_mtu = halow_get_mtu(cfg.mcs);
        rns_mtu_limit = rns_mtu_limit_get();

        if ((uint32_t)rns_mtu_limit < hw_mtu) {
            mtu_limit = (uint32_t)rns_mtu_limit;
        } else {
            mtu_limit = hw_mtu;
        }

        rns_link_utils_clamp_mtu(pkg, len, &packet_info, mtu_limit, &original_mtu);
        log_info("cap link MTU from %db to %db", (int)original_mtu, (int)mtu_limit);

        stored_mtu = (original_mtu <= mtu_limit) ? original_mtu : mtu_limit;

        rns_link_db_package_register(&packet_info, RNS_PACKET_DIRECTION_TX,
                                     NULL, stored_mtu, true);
    }else if( packet_info.valid ){
        rns_link_db_package_register(&packet_info, RNS_PACKET_DIRECTION_TX,
                                     NULL, 0, false);
    }

    /* Address the frame to the neighbour's MAC when the Reticulum link has a
     * known peer (learned on RX from addr2). halow_send_frame carries the
     * destination in addr3 with addr1=broadcast, so this stays ACK-free
     * (broadcast-addressed at the PHY, no MAC-level ACK) while letting the
     * receiver accept the frame via its addr3 filter (addr3 == own MAC).
     * No known peer -> broadcast. */
    rns_link_db_link_t link;
    if( packet_info.valid &&
        rns_link_db_link_snapshot_by_id(packet_info.link_id, &link) &&
        halow_peer_mac_known(link.remote_mac) ){
        (void)halow_tx(pkg, len, link.remote_mac, HALOW_MCS_DEFAULT);
    }else{
        (void)halow_tx(pkg, len, mac_broadcast, HALOW_MCS_DEFAULT);
    }
}

void halow_pkg_handler_init( void ){
    rns_link_db_init();
}

int16_t rns_mtu_limit_get( void ){
    int16_t val = RNS_MTU_LIMIT_DEF;
    configdb_get_i16(RNS_MTU_LIMIT_KEY, &val);
    return val;
}

void rns_mtu_limit_set( int16_t mtu ){
    configdb_set_i16(RNS_MTU_LIMIT_KEY, &mtu);
}
