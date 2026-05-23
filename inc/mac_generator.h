#ifndef __MAC_GENERATOR_H__
#define __MAC_GENERATOR_H__

#include <stdint.h>

typedef struct {
    uint16_t rotation_minutes;
    uint8_t  broadcast_mac;
} mac_generator_config_t;

void get_mac(uint8_t mac[6]);

void mac_generator_init(void);
void mac_generator_config_load(mac_generator_config_t *cfg);
void mac_generator_config_save(const mac_generator_config_t *cfg);
void mac_generator_config_apply(const mac_generator_config_t *cfg);
void mac_generator_get(uint8_t mac[6]);

#endif
