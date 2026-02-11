// Copyright (c) 2024 Cesanta Software Limited
// All rights reserved

#define LED_1 PIN('A', 0)
#define LED_2 PIN('A', 1)
#define UART_DEBUG NULL

#define BIT(x) (1UL << (x))
#define CLRSET(reg, clear, set) ((reg) = ((reg) & ~(clear)) | (set))
#define PIN(bank, num) ((((bank) - 'A') << 8) | (num))
#define PINNO(pin) (pin & 255)
#define PINBANK(pin) (pin >> 8)

// No-op HAL API implementation for a device with GPIO and UART
#define hal_init()
#define hal_ram_free() 0
#define hal_ram_used() 0
#define hal_gpio_output(pin)
#define hal_gpio_toggle(pin)
#define hal_gpio_read(pin) 0
#define hal_gpio_write(pin, val)
#define hal_uart_init(uart, baud) 
#define hal_uart_read_ready(uart) 0
#define hal_uart_write_byte(uart, ch)
#define hal_uart_write_buf(uart, buf, len)
