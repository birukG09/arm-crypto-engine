/*
 * Raspberry Pi Platform Implementation
 * ArmAsm-CryptoEngine - Raspberry Pi Cortex-A53 Platform Support Implementation
 */

#include "platform.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <linux/spi/spidev.h>
#include <termios.h>
#include <errno.h>
#include <stdarg.h>
#include <pthread.h>

/* BCM2835/BCM2837 register base addresses */
#define BCM2835_PERI_BASE   0x3F000000
#define GPIO_BASE           (BCM2835_PERI_BASE + 0x200000)
#define SPI0_BASE           (BCM2835_PERI_BASE + 0x204000)

/* GPIO register offsets */
#define GPFSEL0             0x00
#define GPFSEL1             0x04
#define GPFSEL2             0x08
#define GPSET0              0x1C
#define GPSET1              0x20
#define GPCLR0              0x28
#define GPCLR1              0x2C
#define GPLEV0              0x34
#define GPLEV1              0x38
#define GPPUD               0x94
#define GPPUDCLK0           0x98
#define GPPUDCLK1           0x9C

/* Static variables */
static uint32_t g_system_clock_hz = PLATFORM_DEFAULT_CLOCK_HZ;
static volatile uint32_t* g_gpio_map = NULL;
static int g_mem_fd = -1;
static int g_cycles_initialized = 0;
static platform_log_level_t g_log_level = PLATFORM_LOG_INFO;
static pthread_mutex_t g_platform_mutex = PTHREAD_MUTEX_INITIALIZER;

/* PMU access */
static int g_pmu_enabled = 0;
static uint64_t g_pmu_counters[6] = {0};

/*
 * Low-level memory mapping
 */
static int map_peripheral(void** map, off_t addr, size_t len)
{
    if (g_mem_fd == -1) {
        g_mem_fd = open("/dev/mem", O_RDWR | O_SYNC);
        if (g_mem_fd == -1) {
            return PLATFORM_ERROR_PERMISSION;
        }
    }
    
    *map = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, g_mem_fd, addr);
    if (*map == MAP_FAILED) {
        return PLATFORM_ERROR_HARDWARE;
    }
    
    return PLATFORM_SUCCESS;
}

/*
 * Platform initialization
 */
platform_result_t platform_init(void)
{
    pthread_mutex_lock(&g_platform_mutex);
    
    /* Map GPIO registers */
    int result = map_peripheral((void**)&g_gpio_map, GPIO_BASE, 4096);
    if (result != PLATFORM_SUCCESS) {
        pthread_mutex_unlock(&g_platform_mutex);
        return result;
    }
    
    /* Initialize performance monitoring */
    platform_cycles_init();
    
    /* Initialize RNG */
    platform_rng_init();
    
    pthread_mutex_unlock(&g_platform_mutex);
    return PLATFORM_SUCCESS;
}

/*
 * Platform cleanup
 */
void platform_cleanup(void)
{
    pthread_mutex_lock(&g_platform_mutex);
    
    if (g_gpio_map) {
        munmap((void*)g_gpio_map, 4096);
        g_gpio_map = NULL;
    }
    
    if (g_mem_fd != -1) {
        close(g_mem_fd);
        g_mem_fd = -1;
    }
    
    platform_pmu_disable();
    platform_rng_cleanup();
    
    pthread_mutex_unlock(&g_platform_mutex);
}

/*
 * Get system information
 */
const char* platform_get_info_string(void)
{
    static char info[256];
    FILE* fp = fopen("/proc/cpuinfo", "r");
    char line[256];
    char model[128] = "Unknown";
    
    if (fp) {
        while (fgets(line, sizeof(line), fp)) {
            if (strncmp(line, "Model", 5) == 0) {
                char* colon = strchr(line, ':');
                if (colon) {
                    strncpy(model, colon + 2, sizeof(model) - 1);
                    char* newline = strchr(model, '\n');
                    if (newline) *newline = '\0';
                }
                break;
            }
        }
        fclose(fp);
    }
    
    snprintf(info, sizeof(info), 
             "%s, Cortex-A53 @ %lu MHz, NEON: %s, Crypto Ext: %s",
             model,
             g_system_clock_hz / 1000000,
             platform_has_neon() ? "Yes" : "No",
             platform_has_crypto_ext() ? "Yes" : "No");
    return info;
}

/*
 * Get CPU frequency
 */
uint32_t platform_get_clock_freq(void)
{
    FILE* fp = fopen("/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq", "r");
    if (fp) {
        uint32_t freq_khz;
        if (fscanf(fp, "%u", &freq_khz) == 1) {
            g_system_clock_hz = freq_khz * 1000;
        }
        fclose(fp);
    }
    return g_system_clock_hz;
}

/*
 * Performance monitoring and cycle counting
 */
platform_result_t platform_cycles_init(void)
{
    /* Enable user-space access to performance counters */
    FILE* fp = fopen("/proc/sys/kernel/perf_event_paranoid", "w");
    if (fp) {
        fprintf(fp, "-1");
        fclose(fp);
    }
    
    g_cycles_initialized = 1;
    return PLATFORM_SUCCESS;
}

platform_cycles_t platform_cycles_get(void)
{
    uint64_t cycles;
    
    /* Read cycle counter using inline assembly */
    __asm__ volatile("mrs %0, cntvct_el0" : "=r" (cycles));
    
    return cycles;
}

platform_cycles_t platform_cycles_elapsed(platform_cycles_t start, platform_cycles_t end)
{
    if (end >= start) {
        return end - start;
    } else {
        /* Handle counter overflow */
        return (UINT64_MAX - start) + end + 1;
    }
}

uint32_t platform_cycles_to_us(platform_cycles_t cycles)
{
    return (uint32_t)((cycles * 1000000ULL) / g_system_clock_hz);
}

uint64_t platform_cycles_to_ns(platform_cycles_t cycles)
{
    return (cycles * 1000000000ULL) / g_system_clock_hz;
}

void platform_delay_ms(uint32_t ms)
{
    struct timespec ts = {
        .tv_sec = ms / 1000,
        .tv_nsec = (ms % 1000) * 1000000
    };
    nanosleep(&ts, NULL);
}

void platform_delay_us(uint32_t us)
{
    struct timespec ts = {
        .tv_sec = us / 1000000,
        .tv_nsec = (us % 1000000) * 1000
    };
    nanosleep(&ts, NULL);
}

void platform_delay_ns(uint64_t ns)
{
    struct timespec ts = {
        .tv_sec = ns / 1000000000ULL,
        .tv_nsec = ns % 1000000000ULL
    };
    nanosleep(&ts, NULL);
}

/*
 * Cache operations
 */
void platform_dcache_flush(void)
{
    __asm__ volatile("dc civac, %0" :: "r" (0) : "memory");
    PLATFORM_DATA_SYNC_BARRIER();
}

void platform_dcache_invalidate(void)
{
    __asm__ volatile("dc ivac, %0" :: "r" (0) : "memory");
    PLATFORM_DATA_SYNC_BARRIER();
}

void platform_icache_invalidate(void)
{
    __asm__ volatile("ic iallu" ::: "memory");
    PLATFORM_INSTRUCTION_BARRIER();
}

void* platform_alloc_coherent(size_t size)
{
    return aligned_alloc(PLATFORM_MEMORY_ALIGNMENT, size);
}

void platform_free_coherent(void* ptr, size_t size)
{
    (void)size;
    free(ptr);
}

void platform_memcpy_coherent(void* dst, const void* src, size_t len)
{
    memcpy(dst, src, len);
    platform_dcache_flush();
}

void* platform_aligned_alloc(size_t alignment, size_t size)
{
    return aligned_alloc(alignment, size);
}

void platform_aligned_free(void* ptr)
{
    free(ptr);
}

/*
 * GPIO functions
 */
platform_result_t platform_gpio_init(void)
{
    return (g_gpio_map != NULL) ? PLATFORM_SUCCESS : PLATFORM_ERROR_HARDWARE;
}

platform_result_t platform_gpio_config(const platform_gpio_config_t* config)
{
    if (!config || !g_gpio_map || config->pin_number < 0 || config->pin_number > 53) {
        return PLATFORM_ERROR_INVALID_PARAM;
    }
    
    pthread_mutex_lock(&g_platform_mutex);
    
    int pin = config->pin_number;
    int reg_index = pin / 10;
    int reg_offset = (pin % 10) * 3;
    
    /* Set GPIO function (input/output) */
    uint32_t fsel = g_gpio_map[reg_index];
    fsel &= ~(7 << reg_offset);
    if (config->direction) {
        fsel |= (1 << reg_offset);  /* Output */
    }
    g_gpio_map[reg_index] = fsel;
    
    /* Configure pull-up/pull-down */
    if (config->pull_mode != 0) {
        g_gpio_map[GPPUD / 4] = config->pull_mode;
        platform_delay_us(10);
        
        if (pin < 32) {
            g_gpio_map[GPPUDCLK0 / 4] = 1 << pin;
        } else {
            g_gpio_map[GPPUDCLK1 / 4] = 1 << (pin - 32);
        }
        
        platform_delay_us(10);
        
        g_gpio_map[GPPUD / 4] = 0;
        g_gpio_map[GPPUDCLK0 / 4] = 0;
        g_gpio_map[GPPUDCLK1 / 4] = 0;
    }
    
    /* Set initial value if output */
    if (config->direction && config->initial_value) {
        platform_gpio_set(pin);
    }
    
    pthread_mutex_unlock(&g_platform_mutex);
    return PLATFORM_SUCCESS;
}

void platform_gpio_set(int pin)
{
    if (!g_gpio_map || pin < 0 || pin > 53) return;
    
    if (pin < 32) {
        g_gpio_map[GPSET0 / 4] = 1 << pin;
    } else {
        g_gpio_map[GPSET1 / 4] = 1 << (pin - 32);
    }
}

void platform_gpio_clear(int pin)
{
    if (!g_gpio_map || pin < 0 || pin > 53) return;
    
    if (pin < 32) {
        g_gpio_map[GPCLR0 / 4] = 1 << pin;
    } else {
        g_gpio_map[GPCLR1 / 4] = 1 << (pin - 32);
    }
}

void platform_gpio_toggle(int pin)
{
    if (platform_gpio_read(pin)) {
        platform_gpio_clear(pin);
    } else {
        platform_gpio_set(pin);
    }
}

int platform_gpio_read(int pin)
{
    if (!g_gpio_map || pin < 0 || pin > 53) return 0;
    
    if (pin < 32) {
        return (g_gpio_map[GPLEV0 / 4] & (1 << pin)) ? 1 : 0;
    } else {
        return (g_gpio_map[GPLEV1 / 4] & (1 << (pin - 32))) ? 1 : 0;
    }
}

void platform_gpio_cleanup(void)
{
    /* GPIO cleanup handled in platform_cleanup() */
}

/*
 * SPI functions
 */
static int g_spi_fd = -1;

platform_result_t platform_spi_init(const platform_spi_config_t* config)
{
    if (!config) {
        return PLATFORM_ERROR_INVALID_PARAM;
    }
    
    char device_path[32];
    snprintf(device_path, sizeof(device_path), "/dev/spidev0.%d", config->spi_device);
    
    g_spi_fd = open(device_path, O_RDWR);
    if (g_spi_fd < 0) {
        return PLATFORM_ERROR_HARDWARE;
    }
    
    /* Configure SPI parameters */
    if (ioctl(g_spi_fd, SPI_IOC_WR_MODE, &config->mode) < 0 ||
        ioctl(g_spi_fd, SPI_IOC_WR_BITS_PER_WORD, &config->bits_per_word) < 0 ||
        ioctl(g_spi_fd, SPI_IOC_WR_MAX_SPEED_HZ, &config->max_speed) < 0) {
        close(g_spi_fd);
        g_spi_fd = -1;
        return PLATFORM_ERROR_HARDWARE;
    }
    
    return PLATFORM_SUCCESS;
}

platform_result_t platform_spi_transfer(const uint8_t* tx_data, uint8_t* rx_data, size_t len)
{
    if (g_spi_fd < 0 || len == 0) {
        return PLATFORM_ERROR_INVALID_PARAM;
    }
    
    struct spi_ioc_transfer transfer = {
        .tx_buf = (uintptr_t)tx_data,
        .rx_buf = (uintptr_t)rx_data,
        .len = len,
        .speed_hz = 0,  /* Use default */
        .delay_usecs = 0,
        .bits_per_word = 8,
    };
    
    if (ioctl(g_spi_fd, SPI_IOC_MESSAGE(1), &transfer) < 0) {
        return PLATFORM_ERROR_HARDWARE;
    }
    
    return PLATFORM_SUCCESS;
}

void platform_spi_cleanup(void)
{
    if (g_spi_fd >= 0) {
        close(g_spi_fd);
        g_spi_fd = -1;
    }
}

/*
 * UART functions
 */
static int g_uart_fd = -1;

platform_result_t platform_uart_init(const platform_uart_config_t* config)
{
    if (!config || !config->device) {
        return PLATFORM_ERROR_INVALID_PARAM;
    }
    
    g_uart_fd = open(config->device, O_RDWR | O_NOCTTY);
    if (g_uart_fd < 0) {
        return PLATFORM_ERROR_HARDWARE;
    }
    
    struct termios tty;
    if (tcgetattr(g_uart_fd, &tty) != 0) {
        close(g_uart_fd);
        g_uart_fd = -1;
        return PLATFORM_ERROR_HARDWARE;
    }
    
    /* Configure UART settings */
    cfsetospeed(&tty, B115200);  /* Default baud rate */
    cfsetispeed(&tty, B115200);
    
    tty.c_cflag &= ~PARENB;     /* No parity */
    tty.c_cflag &= ~CSTOPB;     /* One stop bit */
    tty.c_cflag &= ~CSIZE;
    tty.c_cflag |= CS8;         /* 8 data bits */
    tty.c_cflag &= ~CRTSCTS;    /* No hardware flow control */
    tty.c_cflag |= CREAD | CLOCAL;
    
    tty.c_lflag &= ~ICANON;     /* Non-canonical mode */
    tty.c_lflag &= ~ECHO;       /* No echo */
    tty.c_lflag &= ~ISIG;       /* No signal handling */
    
    tty.c_iflag &= ~(IXON | IXOFF | IXANY);  /* No software flow control */
    tty.c_iflag &= ~(IGNBRK | BRKINT | PARMRK | ISTRIP | INLCR | IGNCR | ICRNL);
    
    tty.c_oflag &= ~OPOST;      /* No output processing */
    
    if (tcsetattr(g_uart_fd, TCSANOW, &tty) != 0) {
        close(g_uart_fd);
        g_uart_fd = -1;
        return PLATFORM_ERROR_HARDWARE;
    }
    
    return PLATFORM_SUCCESS;
}

platform_result_t platform_uart_send(const uint8_t* data, size_t len)
{
    if (g_uart_fd < 0 || !data || len == 0) {
        return PLATFORM_ERROR_INVALID_PARAM;
    }
    
    ssize_t written = write(g_uart_fd, data, len);
    return (written == (ssize_t)len) ? PLATFORM_SUCCESS : PLATFORM_ERROR_HARDWARE;
}

platform_result_t platform_uart_receive(uint8_t* data, size_t len, uint32_t timeout_ms)
{
    if (g_uart_fd < 0 || !data || len == 0) {
        return PLATFORM_ERROR_INVALID_PARAM;
    }
    
    fd_set read_fds;
    struct timeval timeout = {
        .tv_sec = timeout_ms / 1000,
        .tv_usec = (timeout_ms % 1000) * 1000
    };
    
    FD_ZERO(&read_fds);
    FD_SET(g_uart_fd, &read_fds);
    
    if (select(g_uart_fd + 1, &read_fds, NULL, NULL, &timeout) <= 0) {
        return PLATFORM_ERROR_TIMEOUT;
    }
    
    ssize_t bytes_read = read(g_uart_fd, data, len);
    return (bytes_read > 0) ? PLATFORM_SUCCESS : PLATFORM_ERROR_HARDWARE;
}

int platform_uart_data_available(void)
{
    if (g_uart_fd < 0) return 0;
    
    fd_set read_fds;
    struct timeval timeout = {0, 0};
    
    FD_ZERO(&read_fds);
    FD_SET(g_uart_fd, &read_fds);
    
    return select(g_uart_fd + 1, &read_fds, NULL, NULL, &timeout) > 0;
}

void platform_uart_cleanup(void)
{
    if (g_uart_fd >= 0) {
        close(g_uart_fd);
        g_uart_fd = -1;
    }
}

/*
 * Random number generation
 */
static int g_urandom_fd = -1;

platform_result_t platform_rng_init(void)
{
    g_urandom_fd = open("/dev/urandom", O_RDONLY);
    return (g_urandom_fd >= 0) ? PLATFORM_SUCCESS : PLATFORM_ERROR_HARDWARE;
}

platform_result_t platform_rng_get_bytes(uint8_t* buffer, size_t len)
{
    if (!buffer || len == 0 || g_urandom_fd < 0) {
        return PLATFORM_ERROR_INVALID_PARAM;
    }
    
    ssize_t bytes_read = read(g_urandom_fd, buffer, len);
    return (bytes_read == (ssize_t)len) ? PLATFORM_SUCCESS : PLATFORM_ERROR_HARDWARE;
}

void platform_rng_cleanup(void)
{
    if (g_urandom_fd >= 0) {
        close(g_urandom_fd);
        g_urandom_fd = -1;
    }
}

/*
 * File system operations
 */
int platform_file_exists(const char* path)
{
    return access(path, F_OK) == 0;
}

platform_result_t platform_file_get_size(const char* path, size_t* size)
{
    if (!path || !size) {
        return PLATFORM_ERROR_INVALID_PARAM;
    }
    
    FILE* fp = fopen(path, "rb");
    if (!fp) {
        return PLATFORM_ERROR_HARDWARE;
    }
    
    fseek(fp, 0, SEEK_END);
    *size = ftell(fp);
    fclose(fp);
    
    return PLATFORM_SUCCESS;
}

platform_result_t platform_file_read(const char* path, uint8_t* buffer, size_t size)
{
    if (!path || !buffer || size == 0) {
        return PLATFORM_ERROR_INVALID_PARAM;
    }
    
    FILE* fp = fopen(path, "rb");
    if (!fp) {
        return PLATFORM_ERROR_HARDWARE;
    }
    
    size_t read_bytes = fread(buffer, 1, size, fp);
    fclose(fp);
    
    return (read_bytes == size) ? PLATFORM_SUCCESS : PLATFORM_ERROR_HARDWARE;
}

platform_result_t platform_file_write(const char* path, const uint8_t* buffer, size_t size)
{
    if (!path || !buffer || size == 0) {
        return PLATFORM_ERROR_INVALID_PARAM;
    }
    
    FILE* fp = fopen(path, "wb");
    if (!fp) {
        return PLATFORM_ERROR_HARDWARE;
    }
    
    size_t written_bytes = fwrite(buffer, 1, size, fp);
    fclose(fp);
    
    return (written_bytes == size) ? PLATFORM_SUCCESS : PLATFORM_ERROR_HARDWARE;
}

platform_result_t platform_file_delete(const char* path)
{
    if (!path) {
        return PLATFORM_ERROR_INVALID_PARAM;
    }
    
    return (unlink(path) == 0) ? PLATFORM_SUCCESS : PLATFORM_ERROR_HARDWARE;
}

/*
 * System capabilities
 */
int platform_has_neon(void)
{
    FILE* fp = fopen("/proc/cpuinfo", "r");
    if (!fp) return 0;
    
    char line[256];
    int has_neon = 0;
    
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "neon")) {
            has_neon = 1;
            break;
        }
    }
    
    fclose(fp);
    return has_neon;
}

int platform_has_crypto_ext(void)
{
    FILE* fp = fopen("/proc/cpuinfo", "r");
    if (!fp) return 0;
    
    char line[256];
    int has_crypto = 0;
    
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "aes") || strstr(line, "sha")) {
            has_crypto = 1;
            break;
        }
    }
    
    fclose(fp);
    return has_crypto;
}

int platform_get_cpu_count(void)
{
    return sysconf(_SC_NPROCESSORS_ONLN);
}

void platform_get_unique_id(uint8_t* id, size_t len)
{
    if (!id || len == 0) return;
    
    /* Try to read from CPU serial */
    FILE* fp = fopen("/proc/cpuinfo", "r");
    if (fp) {
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            if (strncmp(line, "Serial", 6) == 0) {
                char* colon = strchr(line, ':');
                if (colon) {
                    unsigned long long serial = strtoull(colon + 1, NULL, 16);
                    size_t copy_len = (len < 8) ? len : 8;
                    memcpy(id, &serial, copy_len);
                    
                    if (len > 8) {
                        memset(&id[8], 0, len - 8);
                    }
                    fclose(fp);
                    return;
                }
            }
        }
        fclose(fp);
    }
    
    /* Fallback: use machine ID */
    fp = fopen("/etc/machine-id", "r");
    if (fp) {
        char machine_id[64];
        if (fgets(machine_id, sizeof(machine_id), fp)) {
            size_t id_len = strlen(machine_id);
            if (id_len > len) id_len = len;
            memcpy(id, machine_id, id_len);
        }
        fclose(fp);
    } else {
        /* Ultimate fallback */
        memset(id, 0xAB, len);
    }
}

/*
 * Performance monitoring
 */
platform_result_t platform_pmu_enable(void)
{
    /* This requires kernel support and appropriate permissions */
    g_pmu_enabled = 1;
    return PLATFORM_SUCCESS;
}

void platform_pmu_disable(void)
{
    g_pmu_enabled = 0;
}

platform_result_t platform_pmu_start_counter(int event_type)
{
    if (!g_pmu_enabled) {
        return PLATFORM_ERROR_NOT_SUPPORTED;
    }
    
    /* Implementation would configure PMU registers */
    /* This is a simplified placeholder */
    (void)event_type;
    return PLATFORM_SUCCESS;
}

uint64_t platform_pmu_read_counter(int counter_id)
{
    if (!g_pmu_enabled || counter_id < 0 || counter_id >= 6) {
        return 0;
    }
    
    return g_pmu_counters[counter_id];
}

void platform_pmu_stop_counter(int counter_id)
{
    if (g_pmu_enabled && counter_id >= 0 && counter_id < 6) {
        g_pmu_counters[counter_id] = 0;
    }
}

/*
 * Debug and logging
 */
void platform_debug_printf(const char* format, ...)
{
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
    fflush(stdout);
}

void platform_set_log_level(platform_log_level_t level)
{
    g_log_level = level;
}

void platform_log(platform_log_level_t level, const char* format, ...)
{
    if (level > g_log_level) return;
    
    const char* level_str[] = {"ERROR", "WARN", "INFO", "DEBUG"};
    
    printf("[%s] ", level_str[level]);
    
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
    
    printf("\n");
    fflush(stdout);
}

/*
 * Power and thermal management
 */
platform_result_t platform_get_temperature(float* temp_celsius)
{
    if (!temp_celsius) {
        return PLATFORM_ERROR_INVALID_PARAM;
    }
    
    FILE* fp = fopen("/sys/class/thermal/thermal_zone0/temp", "r");
    if (!fp) {
        return PLATFORM_ERROR_HARDWARE;
    }
    
    int temp_millidegrees;
    if (fscanf(fp, "%d", &temp_millidegrees) == 1) {
        *temp_celsius = temp_millidegrees / 1000.0f;
        fclose(fp);
        return PLATFORM_SUCCESS;
    }
    
    fclose(fp);
    return PLATFORM_ERROR_HARDWARE;
}

platform_result_t platform_get_cpu_freq(uint32_t* freq_hz)
{
    if (!freq_hz) {
        return PLATFORM_ERROR_INVALID_PARAM;
    }
    
    *freq_hz = platform_get_clock_freq();
    return PLATFORM_SUCCESS;
}

int platform_is_thermal_throttled(void)
{
    FILE* fp = fopen("/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq", "r");
    if (!fp) return 0;
    
    uint32_t cur_freq, max_freq;
    fscanf(fp, "%u", &cur_freq);
    fclose(fp);
    
    fp = fopen("/sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq", "r");
    if (!fp) return 0;
    
    fscanf(fp, "%u", &max_freq);
    fclose(fp);
    
    return (cur_freq < max_freq * 0.9);
}

/*
 * Security functions
 */
int platform_check_privileges(void)
{
    return (geteuid() == 0);
}

platform_result_t platform_memory_lock(void* addr, size_t len)
{
    return (mlock(addr, len) == 0) ? PLATFORM_SUCCESS : PLATFORM_ERROR_PERMISSION;
}

platform_result_t platform_memory_unlock(void* addr, size_t len)
{
    return (munlock(addr, len) == 0) ? PLATFORM_SUCCESS : PLATFORM_ERROR_PERMISSION;
}
