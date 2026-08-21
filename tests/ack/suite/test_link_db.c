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

void t_cov_linkdb_fill_close_hijack( void ){
    halow_ack_config_t cfg;
    rns_link_db_link_t link;
    rns_link_packet_info_t info;
    static uint8_t pkt[300];
    static uint8_t big[300];
    uint8_t data[64];
    uint16_t plen;
    uint8_t count0;

    cfg_base(&cfg);
    fp_node_start(&cfg);

    count0 = rns_link_db_link_count_get();

    /* 1) LINKCLOSE removes an existing link; with no link it is a no-op */
    plen = rns_pkt_build(pkt, 0xE1, 0xE1, 100, RNS_PACKET_TYPE_DATA,
                         RNS_DESTINATION_TYPE_LINK);
    CHECK( rns_link_parser_parse(pkt, plen, &info) == RNS_RET_OK );
    CHECK( rns_link_db_package_register(&info, RNS_PACKET_DIRECTION_TX,
                                        NULL, 0, false, false) == RNS_RET_OK );
    CHECK( rns_link_db_link_count_get() == (uint8_t)(count0 + 1) );
    pkt[18] = (uint8_t)RNS_CONTEXT_LINKCLOSE;
    CHECK( rns_link_parser_parse(pkt, plen, &info) == RNS_RET_OK );
    CHECK( rns_link_db_package_register(&info, RNS_PACKET_DIRECTION_TX,
                                        NULL, 0, false, false) == RNS_RET_OK );
    CHECK( rns_link_db_link_count_get() == count0 );
    CHECK( rns_link_db_package_register(&info, RNS_PACKET_DIRECTION_TX,
                                        NULL, 0, false, false) == RNS_RET_OK );
    CHECK( rns_link_db_link_count_get() == count0 );

    /* 2) the peer's TX MAC can't be hijacked by a broadcast-dest replay */
    plen = rns_pkt_build(pkt, 0xE2, 0xE2, 100, RNS_PACKET_TYPE_DATA,
                         RNS_DESTINATION_TYPE_LINK);
    CHECK( rns_link_parser_parse(pkt, plen, &info) == RNS_RET_OK );
    CHECK( rns_link_db_package_register(&info, RNS_PACKET_DIRECTION_RX,
                                        PEER_A, 0, false, true) == RNS_RET_OK );
    CHECK( rns_link_db_link_snapshot_by_id(info.link_id, &link) );
    CHECK( memcmp(link.remote_mac, PEER_A, 6) == 0 );
    CHECK( rns_link_db_package_register(&info, RNS_PACKET_DIRECTION_RX,
                                        PEER_B, 0, false, false) == RNS_RET_OK );
    CHECK( rns_link_db_link_snapshot_by_id(info.link_id, &link) );
    CHECK( memcmp(link.remote_mac, PEER_A, 6) == 0 );

    /* unicast-to-me RX may re-learn the MAC (legitimate peer MAC change) */
    CHECK( rns_link_db_package_register(&info, RNS_PACKET_DIRECTION_RX,
                                        PEER_B, 0, false, true) == RNS_RET_OK );
    CHECK( rns_link_db_link_snapshot_by_id(info.link_id, &link) );
    CHECK( memcmp(link.remote_mac, PEER_B, 6) == 0 );

    /* 3) snapshot_by_index walks live links */
    CHECK( rns_link_db_link_snapshot_by_index(0, &link) );
    CHECK( !rns_link_db_link_snapshot_by_index(200, &link) );
    CHECK( !rns_link_db_link_snapshot_by_index(0, NULL) );
    CHECK( !rns_link_db_link_snapshot_by_id(NULL, &link) );

    /* 4) fill the DB to 255 links: RX registrations start failing */
    {
        extern volatile uint32_t g_dbg_rns_rx_reg_fail;
        uint32_t f0 = g_dbg_rns_rx_reg_fail;
        int guard = 0;
        while( rns_link_db_link_count_get() < 255u ){
            uint8_t seed = (uint8_t)(0xF0 + (guard % 16));
            uint16_t l = rns_pkt_build(big, seed, seed, 100,
                                       RNS_PACKET_TYPE_DATA,
                                       RNS_DESTINATION_TYPE_LINK);
            big[2] ^= (uint8_t)guard;        /* unique dest hash per link */
            big[3] ^= (uint8_t)(guard >> 8);
            CHECK( rns_link_parser_parse(big, l, &info) == RNS_RET_OK );
            CHECK( rns_link_db_package_register(&info, RNS_PACKET_DIRECTION_RX,
                                                PEER_C, 0, false, true) == RNS_RET_OK );
            CHECK( ++guard < 300 );
        }
        fill_payload(data, sizeof(data), 0x99);
        halow_pkg_handler_rf_to_tcp(data, sizeof(data), PEER_C, MAC_ME, EVM_M10);
        plen = rns_pkt_build(pkt, 0xF1, 0xF1, 100, RNS_PACKET_TYPE_DATA,
                             RNS_DESTINATION_TYPE_LINK);
        halow_pkg_handler_rf_to_tcp(pkt, plen, PEER_C, MAC_ME, EVM_M10);
        CHECK( g_dbg_rns_rx_reg_fail > f0 );
    }

    /* sweep runs over the full table without touching fresh links */
    rns_link_db_sweep_expired();
    CHECK( rns_link_db_link_count_get() == 255 );
}

