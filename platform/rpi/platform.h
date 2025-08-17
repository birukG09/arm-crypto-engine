/*
 * Raspberry Pi Platform Definitions  
 * ArmAsm-CryptoEngine - Raspberry Pi Cortex-A53 Platform Support
 * 
 * Platform-specific definitions for Raspberry Pi with ARMv8-A and NEON
 */

#ifndef PLATFORM_RPI_H
#define PLATFORM_RPI_H

#include <stdint.h>
#include <stddef.h>
#include <sys/time.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Platform identification */
#define PLATFORM_NAME "Raspberry Pi"
#define PLATFORM_CORTEX_A53 1
#define PLATFORM_HAS_NEON 1

/* Clock configuration */
#define PLATFORM_MAX_CLOCK_HZ 1200000000UL  /* 1.2 GHz */
#define PLATFORM_DEFAULT_CLOCK_HZ 1000000000UL  /* 1.0 GHz */

/* Memory configuration */
#define PLATFORM_MEMORY_ALIGNMENT 64        /* Cache line size */
#define PLATFORM_HAS_CACHE 1

/* Cache and memory barriers */
#define PLATFORM_MEMORY_BARRIER() __asm__ __volatile__("dmb sy" ::: "memory")
#define PLATFORM_INSTRUCTION_BARRIER() __asm__ __volatile__("isb" ::: "memory")
#define PLATFORM_DATA_SYNC_BARRIER() __asm__ __volatile__("dsb sy" ::: "memory")

/* Performance monitoring unit */
#define PLATFORM_HAS_PMU 1

/* Platform-specific types */
typedef uint64_t platform_cycles_t;
typedef uint32_t platform_time_ms_t;

/* Error codes */
typedef enum {
    PLATFORM_SUCCESS = 0,
    PLATFORM_ERROR_INVALID_PARAM = -1,
    PLATFORM_ERROR_NOT_SUPPORTED = -2,
    PLATFORM_ERROR_HARDWARE = -3,
    PLATFORM_ERROR_TIMEOUT = -4,
    PLATFORM_ERROR_PERMISSION = -5
} platform_result_t;

/* GPIO configuration */
typedef struct {
    int pin_number;         /* GPIO pin number */
    int direction;          /* 0=input, 1=output */
    int pull_mode;          /* 0=none, 1=pullup, 2=pulldown */
    int initial_value;      /* Initial output value */
} platform_gpio_config_t;

/* SPI configuration */
typedef struct {
    int spi_device;         /* SPI device number (0, 1) */
    uint32_t max_speed;     /* Maximum SPI speed in Hz */
    uint8_t mode;           /* SPI mode (0-3) */
    uint8_t bits_per_word;  /* Bits per word (8, 16) */
} platform_spi_config_t;

/* UART configuration */
typedef struct {
    const char* device;     /* Device path (e.g., "/dev/serial0") */
    uint32_t baudrate;      /* Baud rate */
    uint8_t data_bits;      /* Data bits */
    uint8_t stop_bits;      /* Stop bits */
    uint8_t parity;         /* Parity */
} platform_uart_config_t;

/*
 * Platform initialization and configuration
 */

/* Initialize platform */
platform_result_t platform_init(void);

/* Cleanup platform resources */
void platform_cleanup(void);

/* Get system information */
const char* platform_get_info_string(void);

/* Get CPU frequency */
uint32_t platform_get_clock_freq(void);

/*
 * High-resolution timing and cycle counting
 */

/* Initialize performance monitoring */
platform_result_t platform_cycles_init(void);

/* Get current cycle count */
platform_cycles_t platform_cycles_get(void);

/* Calculate cycles elapsed */
platform_cycles_t platform_cycles_elapsed(platform_cycles_t start, platform_cycles_t end);

/* Convert cycles to time units */
uint32_t platform_cycles_to_us(platform_cycles_t cycles);
uint64_t platform_cycles_to_ns(platform_cycles_t cycles);

/* High-resolution sleep */
void platform_delay_ms(uint32_t ms);
void platform_delay_us(uint32_t us);
void platform_delay_ns(uint64_t ns);

/*
 * Memory management and cache operations
 */

/* Cache operations */
void platform_dcache_flush(void);
void platform_dcache_invalidate(void);
void platform_icache_invalidate(void);

/* Cache-coherent memory operations */
void* platform_alloc_coherent(size_t size);
void platform_free_coherent(void* ptr, size_t size);
void platform_memcpy_coherent(void* dst, const void* src, size_t len);

/* Memory alignment */
void* platform_aligned_alloc(size_t alignment, size_t size);
void platform_aligned_free(void* ptr);

/*
 * GPIO functions
 */

/* Initialize GPIO subsystem */
platform_result_t platform_gpio_init(void);

/* Configure GPIO pin */
platform_result_t platform_gpio_config(const platform_gpio_config_t* config);

/* GPIO operations */
void platform_gpio_set(int pin);
void platform_gpio_clear(int pin);
void platform_gpio_toggle(int pin);
int platform_gpio_read(int pin);

/* Cleanup GPIO */
void platform_gpio_cleanup(void);

/*
 * SPI functions for SD card
 */

/* Initialize SPI */
platform_result_t platform_spi_init(const platform_spi_config_t* config);

/* SPI transfer */
platform_result_t platform_spi_transfer(const uint8_t* tx_data, uint8_t* rx_data, size_t len);

/* SPI cleanup */
void platform_spi_cleanup(void);

/*
 * UART functions
 */

/* Initialize UART */
platform_result_t platform_uart_init(const platform_uart_config_t* config);

/* UART operations */
platform_result_t platform_uart_send(const uint8_t* data, size_t len);
platform_result_t platform_uart_receive(uint8_t* data, size_t len, uint32_t timeout_ms);
int platform_uart_data_available(void);

/* UART cleanup */
void platform_uart_cleanup(void);

/*
 * Random number generation
 */

/* Initialize hardware RNG */
platform_result_t platform_rng_init(void);

/* Get random bytes */
platform_result_t platform_rng_get_bytes(uint8_t* buffer, size_t len);

/* Cleanup RNG */
void platform_rng_cleanup(void);

/*
 * File system operations for SD card encryption
 */

/* Check if file exists */
int platform_file_exists(const char* path);

/* Get file size */
platform_result_t platform_file_get_size(const char* path, size_t* size);

/* Read file */
platform_result_t platform_file_read(const char* path, uint8_t* buffer, size_t size);

/* Write file */
platform_result_t platform_file_write(const char* path, const uint8_t* buffer, size_t size);

/* Delete file */
platform_result_t platform_file_delete(const char* path);

/*
 * System information and capabilities
 */

/* Check if NEON is available */
int platform_has_neon(void);

/* Check if crypto extensions are available */
int platform_has_crypto_ext(void);

/* Get CPU core count */
int platform_get_cpu_count(void);

/* Get unique device ID */
void platform_get_unique_id(uint8_t* id, size_t len);

/*
 * Performance monitoring
 */

/* Enable/disable PMU access from user space */
platform_result_t platform_pmu_enable(void);
void platform_pmu_disable(void);

/* PMU event counting */
platform_result_t platform_pmu_start_counter(int event_type);
uint64_t platform_pmu_read_counter(int counter_id);
void platform_pmu_stop_counter(int counter_id);

/* Common PMU events */
#define PLATFORM_PMU_CPU_CYCLES        0x11
#define PLATFORM_PMU_INST_RETIRED      0x08
#define PLATFORM_PMU_CACHE_REFILLS     0x03
#define PLATFORM_PMU_CACHE_ACCESS      0x04
#define PLATFORM_PMU_BRANCH_MISS       0x10

/*
 * Debug and logging
 */

/* Debug output */
void platform_debug_printf(const char* format, ...);

/* Logging levels */
typedef enum {
    PLATFORM_LOG_ERROR = 0,
    PLATFORM_LOG_WARN = 1,
    PLATFORM_LOG_INFO = 2,
    PLATFORM_LOG_DEBUG = 3
} platform_log_level_t;

/* Set logging level */
void platform_set_log_level(platform_log_level_t level);

/* Log message */
void platform_log(platform_log_level_t level, const char* format, ...);

/*
 * Power and thermal management
 */

/* Get CPU temperature */
platform_result_t platform_get_temperature(float* temp_celsius);

/* Get CPU frequency */
platform_result_t platform_get_cpu_freq(uint32_t* freq_hz);

/* Thermal throttling status */
int platform_is_thermal_throttled(void);

/*
 * Security features
 */

/* Check if running with appropriate privileges */
int platform_check_privileges(void);

/* Lock memory pages (prevent swapping) */
platform_result_t platform_memory_lock(void* addr, size_t len);

/* Unlock memory pages */
platform_result_t platform_memory_unlock(void* addr, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* PLATFORM_RPI_H */
