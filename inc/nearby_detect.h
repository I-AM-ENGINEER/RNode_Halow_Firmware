#ifndef __NEARBY_DETECT_H__
#define __NEARBY_DETECT_H__

#include <stdint.h>

#ifndef NEARBY_MODEM_MAX_COUNT
#define NEARBY_MODEM_MAX_COUNT   (60)
#endif

typedef struct {
    uint8_t mac[6];
    uint8_t mcs;
    int8_t last_rssi;
    int32_t lastrx_timestamp_s;
    int32_t rx_bytes;
    int32_t rx_packets;
    void *user;
} nearby_modem_t;

typedef struct {
    uint8_t mac[6];
    uint8_t len;
    uint8_t mcs;
    int8_t rssi;
    uint32_t timestamp_s;
} nearby_modem_package_info_t;

typedef struct {
    nearby_modem_t modems[NEARBY_MODEM_MAX_COUNT];
    uint8_t modems_count;
} nearby_modem_db_t;

void nearby_modem_package_register( const nearby_modem_package_info_t *pkg );
nearby_modem_t* nearby_modem_get_by_index( uint32_t index );
uint8_t nearby_modem_count_get( void );
void nearby_modem_print_table( void );

#endif
