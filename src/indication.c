#include "basic_include.h"
#include "indication.h"
#include "pinout.h"

static struct os_work led_rx_wk;

static int32 sys_blink_work(struct os_work *work) {
    gpio_set_val(INDICATION_LED_RSSI3_PIN, 1);
    return 0;
}

void indication_init(void){
    OS_WORK_INIT(&led_rx_wk, sys_blink_work,0);
    gpio_set_dir(BUTTON_PAIR_PIN, GPIO_DIR_INPUT);
    gpio_set_mode(BUTTON_PAIR_PIN, GPIO_PULL_UP, GPIO_PULL_LEVEL_10K);

    gpio_set_dir(INDICATION_LED_CONNECT_PIN, GPIO_DIR_OUTPUT);
    //gpio_set_dir(INDICATION_LED_RSSI1_PIN, GPIO_DIR_OUTPUT);
    //gpio_set_dir(INDICATION_LED_RSSI2_PIN, GPIO_DIR_OUTPUT);
    //gpio_set_dir(INDICATION_LED_RSSI3_PIN, GPIO_DIR_OUTPUT);
    gpio_set_val(INDICATION_LED_CONNECT_PIN, 1);
    gpio_set_val(INDICATION_LED_RSSI1_PIN, 1);
    gpio_set_val(INDICATION_LED_RSSI2_PIN, 1);
    gpio_set_val(INDICATION_LED_RSSI3_PIN, 1);
}

bool button_get(void){
    return gpio_get_val(BUTTON_PAIR_PIN) == 0;
}

void indication_led_main_set(bool state){
    gpio_set_val(INDICATION_LED_CONNECT_PIN, !state);
}

void indication_led_rx(void){
    gpio_set_val(INDICATION_LED_RSSI3_PIN, 0);
    os_run_work_delay(&led_rx_wk, 50);
}

void indication_led_tx_set(bool state){
    gpio_set_val(INDICATION_LED_RSSI2_PIN, !state);
}
