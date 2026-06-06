#include "sys_config.h"

#include <stdbool.h>
#include <string.h>

#include "halow_cca.h"
#include "configdb.h"
#include "lib/lmac/mars_lmac_tx.h"

#define HALOW_CCA_CONFIG_PREFIX             CONFIGDB_ADD_MODULE("hcca")
#define HALOW_CCA_CONFIG_ADD_CONFIG(name)   HALOW_CCA_CONFIG_PREFIX "." name

#define HALOW_CCA_CONFIG_ENABLED_NAME           HALOW_CCA_CONFIG_ADD_CONFIG("en")
#define HALOW_CCA_CONFIG_FORCE_TX_PCT_NAME      HALOW_CCA_CONFIG_ADD_CONFIG("ftpct")
#define HALOW_CCA_CONFIG_DUTY_LIMIT_PCT_NAME    HALOW_CCA_CONFIG_ADD_CONFIG("dlpct")
#define HALOW_CCA_CONFIG_CW_MIN_NAME            HALOW_CCA_CONFIG_ADD_CONFIG("cwmin")
#define HALOW_CCA_CONFIG_CW_MAX_NAME            HALOW_CCA_CONFIG_ADD_CONFIG("cwmax")
#define HALOW_CCA_CONFIG_THRESHOLD_DYNAMIC_NAME HALOW_CCA_CONFIG_ADD_CONFIG("thdyn")
#define HALOW_CCA_CONFIG_SENSITIVITY_NAME       HALOW_CCA_CONFIG_ADD_CONFIG("sens")

void halow_cca_config_set_default(halow_cca_config_t *cfg) {
    if (cfg == NULL) return;
    memset(cfg, 0, sizeof(*cfg));
    cfg->cca_enabled          = HALOW_LBT_CCA_ENABLED_DEF ? 1u : 0u;
    cfg->cca_force_tx_pct     = HALOW_LBT_CCA_FORCE_TX_PCT_DEF;
    cfg->duty_limit_pct       = HALOW_LBT_DUTY_LIMIT_PCT_DEF;
    cfg->cw_min               = HALOW_LBT_CW_MIN_DEF;
    cfg->cw_max               = HALOW_LBT_CW_MAX_DEF;
    cfg->cca_threshold_dynamic = HALOW_LBT_CCA_THRESHOLD_DYNAMIC_DEF;
    cfg->cca_sensitivity       = HALOW_LBT_CCA_SENSITIVITY_DEF;
}

void halow_cca_config_sanitize(halow_cca_config_t *cfg) {
    if (cfg == NULL) return;
    if (cfg->cca_force_tx_pct == 0)    cfg->cca_force_tx_pct = 1;
    if (cfg->cca_force_tx_pct > 1000)  cfg->cca_force_tx_pct = 1000;
    if (cfg->duty_limit_pct > 1000)   cfg->duty_limit_pct = 1000;
    if (cfg->cca_sensitivity > 10)   cfg->cca_sensitivity = 10;
    if (cfg->cw_min == 0)            cfg->cw_min = 31;
    if (cfg->cw_max == 0)            cfg->cw_max = 1023;
    if (cfg->cw_min > 2047)          cfg->cw_min = 2047;
    if (cfg->cw_max > 2047)          cfg->cw_max = 2047;
    if (cfg->cw_max < cfg->cw_min)   cfg->cw_max = cfg->cw_min;
}

void halow_cca_config_load(halow_cca_config_t *cfg) {
    if (cfg == NULL) return;
    halow_cca_config_set_default(cfg);
    configdb_get_i8 (HALOW_CCA_CONFIG_ENABLED_NAME,           (int8_t *)&cfg->cca_enabled);
    configdb_get_i16(HALOW_CCA_CONFIG_FORCE_TX_PCT_NAME,      (int16_t *)&cfg->cca_force_tx_pct);
    configdb_get_i16(HALOW_CCA_CONFIG_DUTY_LIMIT_PCT_NAME,    (int16_t *)&cfg->duty_limit_pct);
    configdb_get_i16(HALOW_CCA_CONFIG_CW_MIN_NAME,            (int16_t *)&cfg->cw_min);
    configdb_get_i16(HALOW_CCA_CONFIG_CW_MAX_NAME,            (int16_t *)&cfg->cw_max);
    configdb_get_i8 (HALOW_CCA_CONFIG_THRESHOLD_DYNAMIC_NAME, (int8_t *)&cfg->cca_threshold_dynamic);
    configdb_get_i8 (HALOW_CCA_CONFIG_SENSITIVITY_NAME,       (int8_t *)&cfg->cca_sensitivity);
    halow_cca_config_sanitize(cfg);
}

void halow_cca_config_save(const halow_cca_config_t *cfg) {
    if (cfg == NULL) return;
    halow_cca_config_sanitize((halow_cca_config_t *)cfg);
    configdb_set_i8 (HALOW_CCA_CONFIG_ENABLED_NAME,           (const int8_t *)&cfg->cca_enabled);
    configdb_set_i16(HALOW_CCA_CONFIG_FORCE_TX_PCT_NAME,      (const int16_t *)&cfg->cca_force_tx_pct);
    configdb_set_i16(HALOW_CCA_CONFIG_DUTY_LIMIT_PCT_NAME,    (const int16_t *)&cfg->duty_limit_pct);
    configdb_set_i16(HALOW_CCA_CONFIG_CW_MIN_NAME,            (const int16_t *)&cfg->cw_min);
    configdb_set_i16(HALOW_CCA_CONFIG_CW_MAX_NAME,            (const int16_t *)&cfg->cw_max);
    configdb_set_i8 (HALOW_CCA_CONFIG_THRESHOLD_DYNAMIC_NAME, (const int8_t *)&cfg->cca_threshold_dynamic);
    configdb_set_i8 (HALOW_CCA_CONFIG_SENSITIVITY_NAME,       (const int8_t *)&cfg->cca_sensitivity);
}

void halow_cca_config_apply(const halow_cca_config_t *cfg) {
    if (cfg == NULL) return;
    lmac_custom_cfg.cca_enabled          = cfg->cca_enabled;
    lmac_custom_cfg.cca_force_tx_pct     = cfg->cca_force_tx_pct;
    lmac_custom_cfg.duty_limit_pct       = cfg->duty_limit_pct;
    lmac_custom_cfg.cw_min               = cfg->cw_min;
    lmac_custom_cfg.cw_max               = cfg->cw_max;
    lmac_custom_cfg.cca_threshold_dynamic = cfg->cca_threshold_dynamic;
    lmac_custom_cfg.cca_sensitivity       = cfg->cca_sensitivity;
}

void halow_cca_init(void) {
    halow_cca_config_t cfg;
    halow_cca_config_set_default(&cfg);
    halow_cca_config_load(&cfg);
    halow_cca_config_apply(&cfg);
    halow_cca_config_save(&cfg);
}
