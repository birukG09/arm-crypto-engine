/*
 * STM32F4 Platform Implementation
 * ArmAsm-CryptoEngine - STM32F4 Cortex-M4 Platform Support Implementation
 */

#include "platform.h"
#include <string.h>
#include <stdarg.h>
#include <stdio.h>

/* Static variables */
static uint32_t g_system_clock_hz = PLATFORM_DEFAULT_CLOCK_HZ;
static int g_cycles_initialized = 0;
static platform_uart_config_t g_debug_uart_config = {0};

/*
 * Platform initialization
 */
platform_result_t platform_init(void)
{
    /* Enable floating point unit */
    #if defined(__FPU_PRESENT) && (__FPU_PRESENT == 1U)
    SCB->CPACR |= ((3UL << 10*2)|(3UL << 11*2));  /* set CP10 and CP11 Full Access */
    #endif
    
    /* Configure system clock to maximum frequency */
    platform_set_clock_freq(PLATFORM_MAX_CLOCK_HZ);
    
    /* Initialize cycle counter */
    platform_cycles_init();
    
    /* Enable all GPIO clocks for examples */
    #ifdef STM32F4
    RCC->AHB1ENR |= RCC_AHB1ENR_GPIOAEN | RCC_AHB1ENR_GPIOBEN | 
                    RCC_AHB1ENR_GPIOCEN | RCC_AHB1ENR_GPIODEN |
                    RCC_AHB1ENR_GPIOEEN | RCC_AHB1ENR_GPIOFEN |
                    RCC_AHB1ENR_GPIOGEN | RCC_AHB1ENR_GPIOHEN;
    #endif
    
    return PLATFORM_SUCCESS;
}

/*
 * Get system clock frequency
 */
uint32_t platform_get_clock_freq(void)
{
    return g_system_clock_hz;
}

/*
 * Configure system clock
 */
platform_result_t platform_set_clock_freq(uint32_t freq_hz)
{
    if (freq_hz > PLATFORM_MAX_CLOCK_HZ) {
        return PLATFORM_ERROR_INVALID_PARAM;
    }
    
    #ifdef STM32F4
    /* Configure PLL for maximum performance */
    /* This is a simplified clock configuration */
    /* Production code would use proper clock configuration */
    
    /* Enable HSE */
    RCC->CR |= RCC_CR_HSEON;
    while (!(RCC->CR & RCC_CR_HSERDY));
    
    /* Configure PLL */
    RCC->PLLCFGR = (8 << RCC_PLLCFGR_PLLQ_Pos) |   /* PLLQ = 8 */
                   (336 << RCC_PLLCFGR_PLLN_Pos) |  /* PLLN = 336 */
                   (4 << RCC_PLLCFGR_PLLM_Pos) |    /* PLLM = 4 */
                   RCC_PLLCFGR_PLLSRC_HSE;           /* HSE as source */
    
    /* Enable PLL */
    RCC->CR |= RCC_CR_PLLON;
    while (!(RCC->CR & RCC_CR_PLLRDY));
    
    /* Configure flash latency */
    FLASH->ACR = FLASH_ACR_LATENCY_5WS | FLASH_ACR_ICEN | FLASH_ACR_DCEN | FLASH_ACR_PRFTEN;
    
    /* Configure system clock */
    RCC->CFGR |= RCC_CFGR_SW_PLL;
    while ((RCC->CFGR & RCC_CFGR_SWS) != RCC_CFGR_SWS_PLL);
    
    #endif
    
    g_system_clock_hz = freq_hz;
    return PLATFORM_SUCCESS;
}

/*
 * Initialize cycle counter
 */
platform_result_t platform_cycles_init(void)
{
    /* Enable trace and debug block */
    CoreDebug->DEMCR |= DEMCR_TRCENA_Msk;
    
    /* Reset cycle counter */
    DWT->CYCCNT = 0;
    
    /* Enable cycle counter */
    DWT->CTRL |= DWT_CTRL_CYCCNTENA_Msk;
    
    g_cycles_initialized = 1;
    return PLATFORM_SUCCESS;
}

/*
 * Get current cycle count
 */
platform_cycles_t platform_cycles_get(void)
{
    if (!g_cycles_initialized) {
        platform_cycles_init();
    }
    
    return DWT->CYCCNT;
}

/*
 * Calculate cycles elapsed
 */
platform_cycles_t platform_cycles_elapsed(platform_cycles_t start, platform_cycles_t end)
{
    /* Handle counter overflow */
    if (end >= start) {
        return end - start;
    } else {
        return (0xFFFFFFFFUL - start) + end + 1;
    }
}

/*
 * Convert cycles to microseconds
 */
uint32_t platform_cycles_to_us(platform_cycles_t cycles)
{
    return (uint32_t)((uint64_t)cycles * 1000000ULL / g_system_clock_hz);
}

/*
 * Convert cycles to nanoseconds
 */
uint64_t platform_cycles_to_ns(platform_cycles_t cycles)
{
    return (uint64_t)cycles * 1000000000ULL / g_system_clock_hz;
}

/*
 * Delay functions
 */
void platform_delay_ms(uint32_t ms)
{
    uint32_t start = platform_cycles_get();
    uint32_t cycles_per_ms = g_system_clock_hz / 1000;
    uint32_t target_cycles = ms * cycles_per_ms;
    
    while (platform_cycles_elapsed(start, platform_cycles_get()) < target_cycles) {
        __NOP();
    }
}

void platform_delay_us(uint32_t us)
{
    uint32_t start = platform_cycles_get();
    uint32_t cycles_per_us = g_system_clock_hz / 1000000;
    uint32_t target_cycles = us * cycles_per_us;
    
    while (platform_cycles_elapsed(start, platform_cycles_get()) < target_cycles) {
        __NOP();
    }
}

/*
 * Memory functions (no-op on Cortex-M4)
 */
void platform_dcache_flush(void)
{
    /* Cortex-M4 has no data cache */
    __DSB();  /* Data synchronization barrier */
}

void platform_icache_invalidate(void)
{
    /* Cortex-M4 has no instruction cache */
    __ISB();  /* Instruction synchronization barrier */
}

void platform_memcpy_coherent(void* dst, const void* src, size_t len)
{
    memcpy(dst, src, len);
    platform_dcache_flush();
}

/*
 * UART functions (simplified implementation)
 */
platform_result_t platform_uart_init(const platform_uart_config_t* config)
{
    if (!config) {
        return PLATFORM_ERROR_INVALID_PARAM;
    }
    
    /* Store configuration for debug output */
    g_debug_uart_config = *config;
    
    #ifdef STM32F4
    /* Enable USART2 clock (commonly used for debug) */
    RCC->APB1ENR |= RCC_APB1ENR_USART2EN;
    
    /* Configure GPIO for UART (PA2/PA3 for USART2) */
    GPIOA->MODER |= (2 << (2*2)) | (2 << (3*2));  /* Alternate function */
    GPIOA->AFR[0] |= (7 << (2*4)) | (7 << (3*4));  /* AF7 for USART2 */
    
    /* Configure UART */
    USART2->BRR = g_system_clock_hz / config->baudrate;
    USART2->CR1 = USART_CR1_UE | USART_CR1_TE | USART_CR1_RE;
    #endif
    
    return PLATFORM_SUCCESS;
}

platform_result_t platform_uart_send(const uint8_t* data, size_t len)
{
    if (!data || len == 0) {
        return PLATFORM_ERROR_INVALID_PARAM;
    }
    
    #ifdef STM32F4
    for (size_t i = 0; i < len; i++) {
        while (!(USART2->SR & USART_SR_TXE));
        USART2->DR = data[i];
    }
    while (!(USART2->SR & USART_SR_TC));
    #endif
    
    return PLATFORM_SUCCESS;
}

platform_result_t platform_uart_receive(uint8_t* data, size_t len, uint32_t timeout_ms)
{
    if (!data || len == 0) {
        return PLATFORM_ERROR_INVALID_PARAM;
    }
    
    uint32_t start_time = platform_cycles_get();
    uint32_t timeout_cycles = timeout_ms * (g_system_clock_hz / 1000);
    
    #ifdef STM32F4
    for (size_t i = 0; i < len; i++) {
        while (!(USART2->SR & USART_SR_RXNE)) {
            if (platform_cycles_elapsed(start_time, platform_cycles_get()) > timeout_cycles) {
                return PLATFORM_ERROR_TIMEOUT;
            }
        }
        data[i] = USART2->DR;
    }
    #endif
    
    return PLATFORM_SUCCESS;
}

int platform_uart_data_available(void)
{
    #ifdef STM32F4
    return (USART2->SR & USART_SR_RXNE) ? 1 : 0;
    #else
    return 0;
    #endif
}

/*
 * GPIO functions
 */
platform_result_t platform_gpio_config(const platform_gpio_config_t* config)
{
    if (!config || !config->gpio_base) {
        return PLATFORM_ERROR_INVALID_PARAM;
    }
    
    #ifdef STM32F4
    GPIO_TypeDef* gpio = (GPIO_TypeDef*)config->gpio_base;
    
    for (int pin = 0; pin < 16; pin++) {
        if (config->pin_mask & (1 << pin)) {
            /* Configure mode */
            gpio->MODER = (gpio->MODER & ~(3 << (pin * 2))) | 
                         (config->mode << (pin * 2));
            
            /* Configure pull-up/pull-down */
            gpio->PUPDR = (gpio->PUPDR & ~(3 << (pin * 2))) |
                         (config->pull << (pin * 2));
            
            /* Configure speed */
            gpio->OSPEEDR = (gpio->OSPEEDR & ~(3 << (pin * 2))) |
                           (config->speed << (pin * 2));
            
            /* Configure alternate function */
            if (config->mode == 2) {  /* Alternate function mode */
                if (pin < 8) {
                    gpio->AFR[0] = (gpio->AFR[0] & ~(15 << (pin * 4))) |
                                  (config->alternate << (pin * 4));
                } else {
                    gpio->AFR[1] = (gpio->AFR[1] & ~(15 << ((pin - 8) * 4))) |
                                  (config->alternate << ((pin - 8) * 4));
                }
            }
        }
    }
    #endif
    
    return PLATFORM_SUCCESS;
}

void platform_gpio_set(void* gpio_base, uint16_t pin_mask)
{
    #ifdef STM32F4
    GPIO_TypeDef* gpio = (GPIO_TypeDef*)gpio_base;
    if (gpio) {
        gpio->BSRR = pin_mask;
    }
    #endif
}

void platform_gpio_clear(void* gpio_base, uint16_t pin_mask)
{
    #ifdef STM32F4
    GPIO_TypeDef* gpio = (GPIO_TypeDef*)gpio_base;
    if (gpio) {
        gpio->BSRR = (uint32_t)pin_mask << 16;
    }
    #endif
}

void platform_gpio_toggle(void* gpio_base, uint16_t pin_mask)
{
    #ifdef STM32F4
    GPIO_TypeDef* gpio = (GPIO_TypeDef*)gpio_base;
    if (gpio) {
        gpio->ODR ^= pin_mask;
    }
    #endif
}

uint16_t platform_gpio_read(void* gpio_base, uint16_t pin_mask)
{
    #ifdef STM32F4
    GPIO_TypeDef* gpio = (GPIO_TypeDef*)gpio_base;
    if (gpio) {
        return gpio->IDR & pin_mask;
    }
    #endif
    return 0;
}

/*
 * SPI functions (simplified)
 */
platform_result_t platform_spi_init(const platform_spi_config_t* config)
{
    if (!config) {
        return PLATFORM_ERROR_INVALID_PARAM;
    }
    
    #ifdef STM32F4
    /* Enable SPI1 clock */
    RCC->APB2ENR |= RCC_APB2ENR_SPI1EN;
    
    /* Configure SPI */
    SPI1->CR1 = SPI_CR1_MSTR | SPI_CR1_BR_1 | SPI_CR1_BR_0;  /* Master mode, prescaler /8 */
    SPI1->CR1 |= SPI_CR1_SPE;  /* Enable SPI */
    #endif
    
    return PLATFORM_SUCCESS;
}

platform_result_t platform_spi_transfer(const uint8_t* tx_data, uint8_t* rx_data, size_t len)
{
    if (len == 0) {
        return PLATFORM_ERROR_INVALID_PARAM;
    }
    
    #ifdef STM32F4
    for (size_t i = 0; i < len; i++) {
        /* Send data */
        SPI1->DR = tx_data ? tx_data[i] : 0xFF;
        
        /* Wait for transmission complete */
        while (!(SPI1->SR & SPI_SR_TXE));
        while (!(SPI1->SR & SPI_SR_RXNE));
        
        /* Read received data */
        if (rx_data) {
            rx_data[i] = SPI1->DR;
        } else {
            (void)SPI1->DR;  /* Dummy read */
        }
    }
    #endif
    
    return PLATFORM_SUCCESS;
}

void platform_spi_cs_set(uint8_t cs_pin, int state)
{
    /* GPIO control for chip select - implementation depends on board */
    #ifdef STM32F4
    if (state) {
        GPIOA->BSRR = 1 << cs_pin;
    } else {
        GPIOA->BSRR = (1 << cs_pin) << 16;
    }
    #endif
}

/*
 * RNG functions
 */
platform_result_t platform_rng_init(void)
{
    #ifdef STM32F4
    /* Enable RNG clock */
    RCC->AHB2ENR |= RCC_AHB2ENR_RNGEN;
    
    /* Enable RNG */
    RNG->CR = RNG_CR_RNGEN;
    #endif
    
    return PLATFORM_SUCCESS;
}

platform_result_t platform_rng_get_bytes(uint8_t* buffer, size_t len)
{
    if (!buffer || len == 0) {
        return PLATFORM_ERROR_INVALID_PARAM;
    }
    
    #ifdef STM32F4
    for (size_t i = 0; i < len; i += 4) {
        /* Wait for random data ready */
        while (!(RNG->SR & RNG_SR_DRDY));
        
        uint32_t random = RNG->DR;
        
        /* Copy bytes */
        for (int j = 0; j < 4 && (i + j) < len; j++) {
            buffer[i + j] = (random >> (j * 8)) & 0xFF;
        }
    }
    #else
    /* Fallback: use simple PRNG (not cryptographically secure) */
    static uint32_t seed = 0x12345678;
    for (size_t i = 0; i < len; i++) {
        seed = seed * 1103515245 + 12345;
        buffer[i] = (seed >> 16) & 0xFF;
    }
    #endif
    
    return PLATFORM_SUCCESS;
}

/*
 * Memory security functions
 */
int platform_is_secure_memory(const void* addr, size_t len)
{
    uintptr_t start = (uintptr_t)addr;
    uintptr_t end = start + len;
    
    /* Check if address range is in SRAM */
    return (start >= PLATFORM_SRAM_BASE && 
            end <= (PLATFORM_SRAM_BASE + PLATFORM_SRAM_SIZE));
}

platform_result_t platform_memory_lock(void* addr, size_t len)
{
    /* STM32F4 doesn't have hardware memory protection */
    /* This would be implemented using MPU if available */
    (void)addr;
    (void)len;
    return PLATFORM_ERROR_NOT_SUPPORTED;
}

/*
 * Power management
 */
void platform_enter_sleep(void)
{
    __WFI();  /* Wait for interrupt */
}

void platform_enter_deep_sleep(void)
{
    #ifdef STM32F4
    /* Configure for stop mode */
    PWR->CR |= PWR_CR_LPDS;
    SCB->SCR |= SCB_SCR_SLEEPDEEP_Msk;
    __WFI();
    #endif
}

void platform_wakeup(void)
{
    #ifdef STM32F4
    /* Reconfigure system clock after wakeup */
    platform_set_clock_freq(g_system_clock_hz);
    #endif
}

/*
 * Debug functions
 */
void platform_debug_printf(const char* format, ...)
{
    char buffer[256];
    va_list args;
    
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);
    
    platform_uart_send((const uint8_t*)buffer, strlen(buffer));
}

const char* platform_get_info_string(void)
{
    static char info[128];
    snprintf(info, sizeof(info), 
             "STM32F4 Cortex-M4 @ %lu MHz, SRAM: %d KB",
             g_system_clock_hz / 1000000,
             PLATFORM_SRAM_SIZE / 1024);
    return info;
}

void platform_get_unique_id(uint8_t* id, size_t len)
{
    if (!id || len == 0) {
        return;
    }
    
    #ifdef STM32F4
    /* STM32F4 has 96-bit unique ID at 0x1FFF7A10 */
    const uint8_t* uid = (const uint8_t*)0x1FFF7A10;
    size_t copy_len = (len < 12) ? len : 12;
    memcpy(id, uid, copy_len);
    
    /* Pad with zeros if requested length is larger */
    if (len > 12) {
        memset(&id[12], 0, len - 12);
    }
    #else
    /* Fallback: generate pseudo-unique ID */
    for (size_t i = 0; i < len; i++) {
        id[i] = (uint8_t)(0xAB + i);
    }
    #endif
}
