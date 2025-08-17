/*
 * STM32F4 Platform Definitions
 * ArmAsm-CryptoEngine - STM32F4 Cortex-M4 Platform Support
 * 
 * Platform-specific definitions, hardware abstraction, and timing functions
 */

#ifndef PLATFORM_STM32F4_H
#define PLATFORM_STM32F4_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* STM32F4 specific includes */
#ifdef STM32F4
#include "stm32f4xx.h"
#else
/* Minimal definitions for compilation without CMSIS */
#define __IO volatile
typedef struct {
    __IO uint32_t DHCSR;
    __IO uint32_t DCRSR;
    __IO uint32_t DCRDR;
    __IO uint32_t DEMCR;
} CoreDebug_Type;

typedef struct {
    __IO uint32_t CTRL;
    __IO uint32_t CYCCNT;
    __IO uint32_t CPICNT;
    __IO uint32_t EXCCNT;
    __IO uint32_t SLEEPCNT;
    __IO uint32_t LSUCNT;
    __IO uint32_t FOLDCNT;
    __IO uint32_t PCSR;
} DWT_Type;

#define CoreDebug ((CoreDebug_Type *)0xE000EDF0UL)
#define DWT       ((DWT_Type *)0xE0001000UL)
#endif

/* Platform identification */
#define PLATFORM_NAME "STM32F4"
#define PLATFORM_CORTEX_M4 1

/* Clock configuration */
#define PLATFORM_MAX_CLOCK_HZ 168000000UL
#define PLATFORM_DEFAULT_CLOCK_HZ 168000000UL

/* Memory configuration */
#define PLATFORM_FLASH_BASE 0x08000000UL
#define PLATFORM_SRAM_BASE  0x20000000UL
#define PLATFORM_SRAM_SIZE  (128 * 1024)  /* 128KB SRAM */

/* Cache and memory barriers */
#define PLATFORM_HAS_CACHE 0
#define PLATFORM_MEMORY_BARRIER() __asm__ __volatile__("dmb" ::: "memory")
#define PLATFORM_INSTRUCTION_BARRIER() __asm__ __volatile__("isb" ::: "memory")

/* DWT (Data Watchpoint and Trace) for cycle counting */
#define DWT_CTRL_CYCCNTENA_Pos 0U
#define DWT_CTRL_CYCCNTENA_Msk (1UL << DWT_CTRL_CYCCNTENA_Pos)
#define DEMCR_TRCENA_Pos 24U
#define DEMCR_TRCENA_Msk (1UL << DEMCR_TRCENA_Pos)

/* Platform-specific types */
typedef uint32_t platform_cycles_t;
typedef uint32_t platform_time_ms_t;

/* Error codes */
typedef enum {
    PLATFORM_SUCCESS = 0,
    PLATFORM_ERROR_INVALID_PARAM = -1,
    PLATFORM_ERROR_NOT_SUPPORTED = -2,
    PLATFORM_ERROR_HARDWARE = -3,
    PLATFORM_ERROR_TIMEOUT = -4
} platform_result_t;

/* UART configuration for examples */
typedef struct {
    void* uart_base;        /* UART peripheral base address */
    uint32_t baudrate;      /* Baud rate */
    uint8_t data_bits;      /* Data bits (7, 8, 9) */
    uint8_t stop_bits;      /* Stop bits (1, 2) */
    uint8_t parity;         /* Parity (0=none, 1=odd, 2=even) */
    uint8_t flow_control;   /* Flow control (0=none, 1=RTS/CTS) */
} platform_uart_config_t;

/* GPIO configuration */
typedef struct {
    void* gpio_base;        /* GPIO port base address */
    uint16_t pin_mask;      /* Pin mask */
    uint8_t mode;           /* Mode (input, output, alternate, analog) */
    uint8_t pull;           /* Pull-up/down configuration */
    uint8_t speed;          /* Output speed */
    uint8_t alternate;      /* Alternate function number */
} platform_gpio_config_t;

/* SPI configuration for SD card */
typedef struct {
    void* spi_base;         /* SPI peripheral base address */
    uint32_t clock_rate;    /* SPI clock rate */
    uint8_t mode;           /* SPI mode (0-3) */
    uint8_t data_size;      /* Data size (8, 16 bits) */
    uint8_t bit_order;      /* Bit order (MSB/LSB first) */
    uint8_t cs_pin;         /* Chip select pin number */
} platform_spi_config_t;

/*
 * Platform initialization and configuration
 */

/* Initialize platform (clocks, peripherals, etc.) */
platform_result_t platform_init(void);

/* Get system clock frequency */
uint32_t platform_get_clock_freq(void);

/* Configure system clock */
platform_result_t platform_set_clock_freq(uint32_t freq_hz);

/*
 * Timing and cycle counting
 */

/* Initialize cycle counter */
platform_result_t platform_cycles_init(void);

/* Get current cycle count */
platform_cycles_t platform_cycles_get(void);

/* Calculate cycles elapsed between two readings */
platform_cycles_t platform_cycles_elapsed(platform_cycles_t start, platform_cycles_t end);

/* Convert cycles to microseconds */
uint32_t platform_cycles_to_us(platform_cycles_t cycles);

/* Convert cycles to nanoseconds */
uint64_t platform_cycles_to_ns(platform_cycles_t cycles);

/* Delay functions */
void platform_delay_ms(uint32_t ms);
void platform_delay_us(uint32_t us);

/*
 * Memory management and cache
 */

/* Flush data cache (no-op on Cortex-M4) */
void platform_dcache_flush(void);

/* Invalidate instruction cache (no-op on Cortex-M4) */  
void platform_icache_invalidate(void);

/* Memory copy with cache coherency */
void platform_memcpy_coherent(void* dst, const void* src, size_t len);

/*
 * UART functions for CLI example
 */

/* Initialize UART */
platform_result_t platform_uart_init(const platform_uart_config_t* config);

/* Send data via UART */
platform_result_t platform_uart_send(const uint8_t* data, size_t len);

/* Receive data via UART */
platform_result_t platform_uart_receive(uint8_t* data, size_t len, uint32_t timeout_ms);

/* Check if data is available */
int platform_uart_data_available(void);

/*
 * GPIO functions
 */

/* Configure GPIO pins */
platform_result_t platform_gpio_config(const platform_gpio_config_t* config);

/* Set GPIO pin state */
void platform_gpio_set(void* gpio_base, uint16_t pin_mask);

/* Clear GPIO pin state */
void platform_gpio_clear(void* gpio_base, uint16_t pin_mask);

/* Toggle GPIO pin state */
void platform_gpio_toggle(void* gpio_base, uint16_t pin_mask);

/* Read GPIO pin state */
uint16_t platform_gpio_read(void* gpio_base, uint16_t pin_mask);

/*
 * SPI functions for SD card
 */

/* Initialize SPI */
platform_result_t platform_spi_init(const platform_spi_config_t* config);

/* Transfer data via SPI */
platform_result_t platform_spi_transfer(const uint8_t* tx_data, uint8_t* rx_data, size_t len);

/* Set chip select state */
void platform_spi_cs_set(uint8_t cs_pin, int state);

/*
 * Random number generation
 */

/* Initialize hardware RNG (if available) */
platform_result_t platform_rng_init(void);

/* Get random bytes */
platform_result_t platform_rng_get_bytes(uint8_t* buffer, size_t len);

/*
 * Secure memory functions
 */

/* Check if address is in secure memory region */
int platform_is_secure_memory(const void* addr, size_t len);

/* Lock memory region (if supported) */
platform_result_t platform_memory_lock(void* addr, size_t len);

/*
 * Power management
 */

/* Enter low power mode */
void platform_enter_sleep(void);

/* Enter deep sleep mode */
void platform_enter_deep_sleep(void);

/* Wake up from sleep */
void platform_wakeup(void);

/*
 * Debug and diagnostics
 */

/* Print debug message (if debug UART configured) */
void platform_debug_printf(const char* format, ...);

/* Get platform information string */
const char* platform_get_info_string(void);

/* Get unique device ID */
void platform_get_unique_id(uint8_t* id, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* PLATFORM_STM32F4_H */
