#ifndef __HALOW_LBT_H_
#define __HALOW_LBT_H_

#include <stdint.h>

typedef struct {
    // LBT control
    uint8_t  lbt_enabled;                 // 0 = disabled, 1 = enabled

    // Noise sampling
    uint16_t noise_short_window_samples;  // Short-term window size (samples)
    uint16_t noise_long_window_samples;   // Long-term window size (samples)
    uint8_t  noise_long_low_percent;      // Lowest X% of long-term samples used as background reference

    // Noise thresholds
    int8_t   noise_relative_offset_dbm;   // Allowed margin above background reference
    int8_t   noise_absolute_busy_dbm;     // Absolute busy threshold (noise >= value -> busy)

    // TX timing limits
    uint16_t tx_skip_check_time_us;       // Skip noise check if last TX was within this time
    uint16_t tx_max_continuous_time_ms;   // Maximum continuous TX duration

    // Random backoff
    uint16_t backoff_random_min_us;       // Minimum random delay before re-check
    uint16_t backoff_random_max_us;       // Maximum random delay before re-check

    // Channel utilization limiter (token bucket)
    uint8_t  util_enabled;                // 0 = disabled, 1 = enabled
    uint8_t  util_max_percent;            // Maximum average channel utilization (%)
    uint32_t util_refill_window_ms;       // Averaging window (defines refill rate)
    uint16_t util_bucket_capacity_ms;     // Maximum accumulated TX airtime (burst size)
} halow_lbt_config_t;

// Call on tx complete for reset timer
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
