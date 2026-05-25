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

typedef struct {
    bool none           :1;
    bool resource       :1;
    bool resource_adv   :1;
    bool resource_req   :1;
    bool resource_hmu   :1;
    bool resource_prf   :1;
    bool resource_icl   :1;
    bool resource_rcl   :1;
    bool cache_request  :1;
    bool request        :1;
    bool response       :1;
    bool path_response  :1;
    bool command        :1;
    bool command_status :1;
    bool channel        :1;
    bool keepalive      :1;
    bool linkidentify   :1;
    bool linkclose      :1;
    bool linkproof      :1;
    bool lrrtt          :1;
    bool lrproof        :1;
    bool unknown        :1;
} halow_ack_link_context_t;

typedef struct {
    halow_ack_link_context_t contexts_en;
    uint8_t batch_size;
    uint8_t retries_count;
} halow_ack_config_t;

static inline bool rns_link_ack_cfg_should_ack( const halow_ack_link_context_t *cfg, rns_context_t context ){
    if( cfg == NULL ){
        return false;
    }

    switch( context ){
        case RNS_CONTEXT_NONE:           return cfg->none;
        case RNS_CONTEXT_RESOURCE:       return cfg->resource;
        case RNS_CONTEXT_RESOURCE_ADV:   return cfg->resource_adv;
        case RNS_CONTEXT_RESOURCE_REQ:   return cfg->resource_req;
        case RNS_CONTEXT_RESOURCE_HMU:   return cfg->resource_hmu;
        case RNS_CONTEXT_RESOURCE_PRF:   return cfg->resource_prf;
        case RNS_CONTEXT_RESOURCE_ICL:   return cfg->resource_icl;
        case RNS_CONTEXT_RESOURCE_RCL:   return cfg->resource_rcl;
        case RNS_CONTEXT_CACHE_REQUEST:  return cfg->cache_request;
        case RNS_CONTEXT_REQUEST:        return cfg->request;
        case RNS_CONTEXT_RESPONSE:       return cfg->response;
        case RNS_CONTEXT_PATH_RESPONSE:  return cfg->path_response;
        case RNS_CONTEXT_COMMAND:        return cfg->command;
        case RNS_CONTEXT_COMMAND_STATUS: return cfg->command_status;
        case RNS_CONTEXT_CHANNEL:        return cfg->channel;
        case RNS_CONTEXT_KEEPALIVE:      return cfg->keepalive;
        case RNS_CONTEXT_LINKIDENTIFY:   return cfg->linkidentify;
        case RNS_CONTEXT_LINKCLOSE:      return cfg->linkclose;
        case RNS_CONTEXT_LINKPROOF:      return cfg->linkproof;
        case RNS_CONTEXT_LRRTT:          return cfg->lrrtt;
        case RNS_CONTEXT_LRPROOF:        return cfg->lrproof;
        default:                         return false;
    }
}

typedef struct __attribute__((packed)) {
    union {
        struct __attribute__((packed)) {
            uint8_t data      : 1;
            uint8_t ack_only  : 1;
            uint8_t retry     : 1;
            uint8_t need_ack  : 1;
            uint8_t _reserved : 2;
            uint8_t version   : 2;
        };
        uint8_t flags;
    };

    uint8_t seq;
    uint8_t ack;
    uint8_t ack_bits;
} halow_hdr_t;

struct link_user_ctx {
    const rns_link_db_link_t* link;
    uint8_t remote_mac[6];
};

void halow_pkg_handler_rf_to_tcp( uint8_t* pkg, uint16_t len ){
    int32_t res;
    rns_link_packet_info_t packet_info;
    uint8_t *allocated_rx = NULL;
    uint32_t allocated_len = 0u;

    res = rns_link_parser_parse(pkg, len, &packet_info);
    if( res != RNS_RET_OK ){
        log_warn("rx rns package parse error=%d len=%u", (int)res, (unsigned int)len);
        return;
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

    tcp_server_send(allocated_rx, allocated_len);
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
        uint32_t original_mtu;
        uint32_t hw_mtu;
        uint32_t effective_mtu;
        halow_config_t cfg;
        int16_t rns_mtu_limit;

        halow_config_load(&cfg);
        hw_mtu = halow_get_mtu(cfg.mcs);
        rns_mtu_limit = rns_mtu_limit_get();

        if ((uint32_t)rns_mtu_limit < hw_mtu) {
            effective_mtu = (uint32_t)rns_mtu_limit;
        } else {
            effective_mtu = hw_mtu;
        }

        rns_link_utils_clamp_mtu(pkg, len, &packet_info, effective_mtu, &original_mtu);
        log_info("cap link MTU from %db to %db", (int)original_mtu, (int)effective_mtu);
    }

    //link_db
    halow_tx(pkg, len, mac_broadcast, HALOW_MCS_DEFAULT);
    //
    
    //if(pkg)
}

void halow_pkg_handler_init( void ){

}

int16_t rns_mtu_limit_get( void ){
    int16_t val = RNS_MTU_LIMIT_DEF;
    configdb_get_i16(RNS_MTU_LIMIT_KEY, &val);
    return val;
}

void rns_mtu_limit_set( int16_t mtu ){
    configdb_set_i16(RNS_MTU_LIMIT_KEY, &mtu);
}
