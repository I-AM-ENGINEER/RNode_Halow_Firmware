#ifndef __HALOW_CCA_H_
#define __HALOW_CCA_H_

#include <stdint.h>

typedef struct {
    uint8_t  cca_enabled;
    uint16_t cca_force_tx_pct;
    uint16_t duty_limit_pct;
    uint16_t cw_min;
    uint16_t cw_max;
    uint8_t  cca_threshold_dynamic;
    uint8_t  cca_sensitivity;
} halow_cca_config_t;

void halow_cca_config_set_default(halow_cca_config_t *cfg);
void halow_cca_config_sanitize(halow_cca_config_t *cfg);
void halow_cca_config_load(halow_cca_config_t *cfg);
void halow_cca_config_save(const halow_cca_config_t *cfg);
void halow_cca_config_apply(const halow_cca_config_t *cfg);
void halow_cca_init(void);

#endif
