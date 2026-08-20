#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <time.h>

#include <csi_core.h>   /* __disable_irq inline */
#include "osal/csky/defs.h"   /* disable_irq macro */
#include "nearby_detect.h"

static nearby_modem_db_t g_nearby_db;

static nearby_modem_t* nearby_modem_find_by_mac( const uint8_t mac[6] ){
    uint32_t i;

    for(i = 0; i < g_nearby_db.modems_count; i++){
        if( memcmp(g_nearby_db.modems[i].mac, mac, 6) == 0 ){
            return &g_nearby_db.modems[i];
        }
    }

    return NULL;
}

static uint32_t nearby_modem_find_oldest_index( void ){
    uint32_t i;
    uint32_t oldest_index = 0;

    for( i = 1; i < g_nearby_db.modems_count; i++ ){
        if( g_nearby_db.modems[i].lastrx_timestamp_s < g_nearby_db.modems[oldest_index].lastrx_timestamp_s ){
            oldest_index = i;
        }
    }

    return oldest_index;
}

void nearby_modem_package_register( const nearby_modem_package_info_t *pkg ){
    /* RX task mutates vs httpd readers: run the whole update under irq-off. */
    nearby_modem_t *modem;
    uint32_t index;

    if( pkg == NULL ){
        return;
    }
    uint32_t irqf = disable_irq();

    modem = nearby_modem_find_by_mac(pkg->mac);
    if( modem != NULL ){
        modem->mcs = pkg->mcs;
        modem->last_rssi = pkg->rssi;
        modem->last_snr = pkg->snr;
        modem->lastrx_timestamp_s = (int32_t)pkg->timestamp_s;
        modem->rx_bytes += (int32_t)pkg->len;
        modem->rx_packets += 1;
        enable_irq(irqf);
        return;
    }

    if( g_nearby_db.modems_count < NEARBY_MODEM_MAX_COUNT ){
        index = g_nearby_db.modems_count;
        g_nearby_db.modems_count++;
    }else{
        index = nearby_modem_find_oldest_index();
    }

    memset(&g_nearby_db.modems[index], 0, sizeof(g_nearby_db.modems[index]));

    memcpy(g_nearby_db.modems[index].mac, pkg->mac, 6);
    g_nearby_db.modems[index].mcs = pkg->mcs;
    g_nearby_db.modems[index].last_rssi = pkg->rssi;
    g_nearby_db.modems[index].last_snr = pkg->snr;
    g_nearby_db.modems[index].lastrx_timestamp_s = (int32_t)pkg->timestamp_s;
    g_nearby_db.modems[index].rx_bytes = (int32_t)pkg->len;
    g_nearby_db.modems[index].rx_packets = 1;
    g_nearby_db.modems[index].user = NULL;
    enable_irq(irqf);
}

nearby_modem_t* nearby_modem_get_by_index( uint32_t index ){
    if( index >= g_nearby_db.modems_count ){
        return NULL;
    }

    return &g_nearby_db.modems[index];
}

uint8_t nearby_modem_count_get( void ){
    return g_nearby_db.modems_count;
}

void nearby_modem_print_table( void ){
    uint32_t i;
    nearby_modem_t *m;

    printf("Nearby modems: %u\r\n", (unsigned)g_nearby_db.modems_count);
    printf(" #  MAC                MCS RSSI  LAST_RX_S    RX_BYTES   RX_PACKETS   USER\r\n");

    for( i = 0; i < g_nearby_db.modems_count; i++ ){
        m = &g_nearby_db.modems[i];

        printf(
            "%2u  %02X:%02X:%02X:%02X:%02X:%02X  %3u %4d  %10ld  %9ld  %11ld  %p\r\n",
            (unsigned)i,
            m->mac[0], m->mac[1], m->mac[2], m->mac[3], m->mac[4], m->mac[5],
            (unsigned)m->mcs,
            (int)m->last_rssi,
            (long)m->lastrx_timestamp_s,
            (long)m->rx_bytes,
            (long)m->rx_packets,
            m->user
        );
    }
}

int8_t nearby_modem_best_recent_rssi( uint32_t age_s ){
    int8_t best = -128;
    int32_t now = (int32_t)time(NULL);
    uint32_t irqf = disable_irq();
    for( uint32_t i = 0; i < g_nearby_db.modems_count; i++ ){
        nearby_modem_t *m = &g_nearby_db.modems[i];
        if( (now - m->lastrx_timestamp_s) <= (int32_t)age_s ){
            if( m->last_rssi > best ){
                best = m->last_rssi;
            }
        }
    }
    enable_irq(irqf);
    return best;
}
