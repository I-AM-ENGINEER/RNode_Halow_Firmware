#ifndef __HALOW_LBT_H_
#define __HALOW_LBT_H_

#include <stdint.h>

typedef struct {
    uint8_t  lbt_enabled;
    uint16_t noise_short_window_samples;
    uint16_t noise_long_window_samples;
    uint8_t  noise_long_low_percent;
    int8_t   noise_relative_offset_dbm;
    int8_t   noise_absolute_busy_dbm;
    uint16_t tx_skip_check_time_us;
    uint16_t tx_max_continuous_time_ms;
    uint16_t backoff_random_min_us;
    uint16_t backoff_random_max_us;
    uint8_t  util_enabled;
    uint8_t  util_max_percent;
    uint32_t util_refill_window_ms;
    uint16_t util_bucket_capacity_ms;
} halow_lbt_config_t;

// Call on tx complete for reset timer
void halow_lbt_wait_tx_allowed(void);
void halow_lbt_set_tx_as_active(void);
void halow_lbt_set_tx_as_deactive(void);
float halow_lbt_ch_util_get(void);
float halow_lbt_airtime_get(void);
int8_t halow_lbt_background_short_dbm_get( void );
int8_t halow_lbt_background_long_dbm_get( void );
void halow_lbt_config_save( const halow_lbt_config_t *cfg );
void halow_lbt_config_apply( const halow_lbt_config_t *cfg );
void halow_lbt_config_load( halow_lbt_config_t *cfg );
int32_t halow_lbt_init(void);

#endif
