/*
 * Secure Bootloader Implementation
 * ArmAsm-CryptoEngine - Secure Boot Demo
 * 
 * Demonstrates secure boot process with application verification
 * using HMAC-SHA256 signatures
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "app_verify.h"
#include "armcrypto/sha256.h"
#include "armcrypto/ct.h"
#include "platform.h"

/* Bootloader configuration */
#define BOOTLOADER_VERSION "1.0.0"
#define APPLICATION_FLASH_ADDR 0x08008000  /* App starts at 32KB offset */
#define APPLICATION_MAX_SIZE (1024 * 1024 - 32 * 1024)  /* 1MB - 32KB for bootloader */
#define RECOVERY_TIMEOUT_MS 5000  /* 5 seconds */
#define UART_RECOVERY_BAUDRATE 115200

/* Boot modes */
typedef enum {
    BOOT_MODE_NORMAL = 0,
    BOOT_MODE_RECOVERY = 1,
    BOOT_MODE_FLASH_UPDATE = 2
} boot_mode_t;

/* Global bootloader state */
static boot_mode_t g_boot_mode = BOOT_MODE_NORMAL;
static int g_recovery_active = 0;

/* HMAC key for application verification (normally stored in secure location) */
static const uint8_t bootloader_hmac_key[32] = {
    0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00
};

/*
 * Print bootloader banner
 */
static void print_banner(void)
{
    printf("\n");
    printf("========================================\n");
    printf("  ArmAsm-CryptoEngine Secure Bootloader\n");
    printf("  Version: %s\n", BOOTLOADER_VERSION);
    printf("========================================\n");
    printf("Platform: %s\n", platform_get_info_string());
    printf("Boot Mode: ");
    
    switch (g_boot_mode) {
        case BOOT_MODE_NORMAL:
            printf("Normal Boot\n");
            break;
        case BOOT_MODE_RECOVERY:
            printf("Recovery Mode\n");
            break;
        case BOOT_MODE_FLASH_UPDATE:
            printf("Flash Update Mode\n");
            break;
    }
    
    printf("\n");
}

/*
 * Check for recovery mode entry
 */
static boot_mode_t check_boot_mode(void)
{
    /* Check for GPIO button press or other recovery trigger */
#ifdef STM32F4
    /* Example: Check if user button is pressed */
    platform_gpio_config_t gpio_config = {
        .gpio_base = (void*)0x40020000,  /* GPIOA */
        .pin_mask = 1 << 0,              /* PA0 - User button */
        .mode = 0,                       /* Input */
        .pull = 2,                       /* Pull-down */
        .speed = 0,
        .alternate = 0
    };
    
    platform_gpio_config(&gpio_config);
    
    /* Check button state */
    if (platform_gpio_read((void*)0x40020000, 1 << 0)) {
        return BOOT_MODE_RECOVERY;
    }
#endif
    
    /* Check for recovery flag in backup registers or EEPROM */
    /* This is platform-specific implementation */
    
    return BOOT_MODE_NORMAL;
}

/*
 * Verify and boot application
 */
static int boot_application(void)
{
    printf("Verifying application at 0x%08X...\n", APPLICATION_FLASH_ADDR);
    
    app_info_t app_info;
    app_verify_result_t result = app_verify_from_flash(APPLICATION_FLASH_ADDR,
                                                      APPLICATION_MAX_SIZE,
                                                      &app_info);
    
    if (result != APP_VERIFY_SUCCESS) {
        printf("Application verification failed: %s\n", 
               app_verify_get_error_string(result));
        return -1;
    }
    
    printf("Application verification successful!\n");
    printf("  Entry Point: 0x%08X\n", app_info.entry_point);
    printf("  Load Address: 0x%08X\n", app_info.load_address);
    printf("  Size: %u bytes\n", app_info.size);
    printf("  Flags: 0x%08X\n", app_info.flags);
    
    /* Check if application needs to be loaded to RAM */
    if (app_info.load_address != APPLICATION_FLASH_ADDR + sizeof(app_header_t)) {
        printf("Loading application to RAM...\n");
        
        /* Copy application from flash to RAM */
        const uint8_t* flash_app = (const uint8_t*)(APPLICATION_FLASH_ADDR + sizeof(app_header_t));
        uint8_t* ram_app = (uint8_t*)app_info.load_address;
        
        /* Verify target memory is valid */
        if (!app_verify_is_valid_load_region(app_info.load_address, app_info.size)) {
            printf("Error: Invalid load address\n");
            return -1;
        }
        
        /* Copy application data */
        memcpy(ram_app, flash_app, app_info.size);
        
        /* Flush caches to ensure coherency */
        platform_dcache_flush();
        platform_icache_invalidate();
    }
    
    printf("Jumping to application at 0x%08X...\n", app_info.entry_point);
    printf("========================================\n\n");
    
    /* Cleanup bootloader resources */
    app_verify_cleanup();
    
#ifdef PLATFORM_RPI
    platform_cleanup();
#endif
    
    /* Jump to application */
    void (*app_entry)(void) = (void (*)(void))(app_info.entry_point);
    app_entry();
    
    /* Should not return */
    return 0;
}

/*
 * Recovery mode CLI
 */
static void recovery_mode_cli(void)
{
    char command[256];
    
    printf("Entering recovery mode...\n");
    printf("Available commands:\n");
    printf("  boot     - Attempt to boot application\n");
    printf("  verify   - Verify application without booting\n");
    printf("  info     - Show application information\n");
    printf("  flash    - Enter flash update mode\n");
    printf("  reset    - Reset system\n");
    printf("  help     - Show this help\n\n");
    
    g_recovery_active = 1;
    
    while (g_recovery_active) {
        printf("recovery> ");
        fflush(stdout);
        
        /* Read command from UART */
        if (fgets(command, sizeof(command), stdin) != NULL) {
            /* Remove newline */
            char* newline = strchr(command, '\n');
            if (newline) *newline = 0;
            
            if (strcmp(command, "boot") == 0) {
                if (boot_application() == 0) {
                    /* Application started successfully */
                    g_recovery_active = 0;
                } else {
                    printf("Boot failed\n");
                }
            } else if (strcmp(command, "verify") == 0) {
                app_info_t app_info;
                app_verify_result_t result = app_verify_from_flash(APPLICATION_FLASH_ADDR,
                                                                  APPLICATION_MAX_SIZE,
                                                                  &app_info);
                
                if (result == APP_VERIFY_SUCCESS) {
                    printf("Application verification successful\n");
                } else {
                    printf("Application verification failed: %s\n",
                           app_verify_get_error_string(result));
                }
            } else if (strcmp(command, "info") == 0) {
                app_header_t header;
                memcpy(&header, (const void*)APPLICATION_FLASH_ADDR, sizeof(header));
                
                printf("Application Information:\n");
                printf("  Magic: %.8s\n", header.magic);
                printf("  Version: %u\n", header.version);
                printf("  Size: %u bytes\n", header.app_size);
                printf("  Entry: 0x%08X\n", header.app_entry);
                printf("  Load: 0x%08X\n", header.load_address);
                printf("  Flags: 0x%08X\n", header.flags);
                
            } else if (strcmp(command, "flash") == 0) {
                printf("Flash update mode not implemented in this demo\n");
                
            } else if (strcmp(command, "reset") == 0) {
                printf("Resetting system...\n");
#ifdef STM32F4
                NVIC_SystemReset();
#else
                exit(0);  /* For host platform */
#endif
                
            } else if (strcmp(command, "help") == 0) {
                printf("Available commands:\n");
                printf("  boot, verify, info, flash, reset, help\n");
                
            } else if (strlen(command) > 0) {
                printf("Unknown command: %s\n", command);
            }
        }
    }
}

/*
 * Check for recovery timeout
 */
static int check_recovery_timeout(void)
{
    static platform_cycles_t start_time = 0;
    
    if (start_time == 0) {
        start_time = platform_cycles_get();
        printf("Press any key within %d seconds to enter recovery mode...\n", 
               RECOVERY_TIMEOUT_MS / 1000);
        return 0;
    }
    
    platform_cycles_t current_time = platform_cycles_get();
    uint32_t elapsed_ms = platform_cycles_to_us(platform_cycles_elapsed(start_time, current_time)) / 1000;
    
    /* Check for user input */
    if (platform_uart_data_available()) {
        uint8_t dummy;
        platform_uart_receive(&dummy, 1, 0);  /* Consume the byte */
        printf("\nUser input detected, entering recovery mode...\n");
        return 1;  /* Enter recovery */
    }
    
    if (elapsed_ms >= RECOVERY_TIMEOUT_MS) {
        printf("\nTimeout expired, proceeding with normal boot...\n");
        return -1;  /* Timeout, proceed with normal boot */
    }
    
    return 0;  /* Continue waiting */
}

/*
 * Initialize bootloader hardware
 */
static int bootloader_init(void)
{
    /* Initialize platform */
    if (platform_init() != PLATFORM_SUCCESS) {
        return -1;
    }
    
    /* Initialize cycle counter for timeouts */
    platform_cycles_init();
    
    /* Initialize UART for recovery console */
    platform_uart_config_t uart_config = {
#ifdef STM32F4
        .uart_base = (void*)0x40004400,  /* USART2 */
#else
        .device = "/dev/console",
#endif
        .baudrate = UART_RECOVERY_BAUDRATE,
        .data_bits = 8,
        .stop_bits = 1,
        .parity = 0,
        .flow_control = 0
    };
    
    if (platform_uart_init(&uart_config) != PLATFORM_SUCCESS) {
        return -1;
    }
    
    /* Initialize application verification */
    if (app_verify_init(bootloader_hmac_key) != APP_VERIFY_SUCCESS) {
        return -1;
    }
    
    return 0;
}

/*
 * Main bootloader function
 */
int main(void)
{
    /* Initialize bootloader */
    if (bootloader_init() != 0) {
        /* Critical error - cannot continue */
        while (1) {
            /* Flash LED or other error indication */
#ifdef STM32F4
            platform_delay_ms(500);
#else
            printf("Bootloader initialization failed\n");
            return 1;
#endif
        }
    }
    
    /* Determine boot mode */
    g_boot_mode = check_boot_mode();
    
    /* Print banner */
    print_banner();
    
    if (g_boot_mode == BOOT_MODE_RECOVERY) {
        /* User requested recovery mode */
        recovery_mode_cli();
    } else {
        /* Normal boot - check for recovery timeout */
        int timeout_result;
        do {
            timeout_result = check_recovery_timeout();
            platform_delay_ms(100);
        } while (timeout_result == 0);
        
        if (timeout_result == 1) {
            /* User requested recovery */
            recovery_mode_cli();
        } else {
            /* Proceed with normal boot */
            if (boot_application() != 0) {
                printf("Normal boot failed, entering recovery mode...\n");
                g_boot_mode = BOOT_MODE_RECOVERY;
                recovery_mode_cli();
            }
        }
    }
    
    /* Should not reach here in normal operation */
    printf("Bootloader exiting...\n");
    return 0;
}

#ifdef STM32F4
/*
 * STM32 specific startup and interrupt handlers
 */

/* Vector table */
extern uint32_t _stack;

void Reset_Handler(void);
void NMI_Handler(void) __attribute__((weak, alias("Default_Handler")));
void HardFault_Handler(void) __attribute__((weak, alias("Default_Handler")));
void MemManage_Handler(void) __attribute__((weak, alias("Default_Handler")));
void BusFault_Handler(void) __attribute__((weak, alias("Default_Handler")));
void UsageFault_Handler(void) __attribute__((weak, alias("Default_Handler")));
void SVC_Handler(void) __attribute__((weak, alias("Default_Handler")));
void DebugMon_Handler(void) __attribute__((weak, alias("Default_Handler")));
void PendSV_Handler(void) __attribute__((weak, alias("Default_Handler")));
void SysTick_Handler(void) __attribute__((weak, alias("Default_Handler")));

/* Vector table */
__attribute__((section(".isr_vector")))
const uint32_t vector_table[] = {
    (uint32_t)&_stack,           /* Initial stack pointer */
    (uint32_t)Reset_Handler,     /* Reset handler */
    (uint32_t)NMI_Handler,       /* NMI handler */
    (uint32_t)HardFault_Handler, /* Hard fault handler */
    (uint32_t)MemManage_Handler, /* Memory management fault */
    (uint32_t)BusFault_Handler,  /* Bus fault handler */
    (uint32_t)UsageFault_Handler,/* Usage fault handler */
    0,                           /* Reserved */
    0,                           /* Reserved */
    0,                           /* Reserved */
    0,                           /* Reserved */
    (uint32_t)SVC_Handler,       /* SVC handler */
    (uint32_t)DebugMon_Handler,  /* Debug monitor handler */
    0,                           /* Reserved */
    (uint32_t)PendSV_Handler,    /* PendSV handler */
    (uint32_t)SysTick_Handler,   /* SysTick handler */
};

/* Default interrupt handler */
void Default_Handler(void)
{
    printf("Unhandled interrupt occurred\n");
    while (1);
}

/* Reset handler */
void Reset_Handler(void)
{
    /* Initialize system */
    SystemInit();
    
    /* Initialize C runtime */
    __libc_init_array();
    
    /* Call main */
    main();
    
    /* Should not return */
    while (1);
}

/* System initialization */
void SystemInit(void)
{
    /* Enable FPU if present */
#if defined(__FPU_PRESENT) && (__FPU_PRESENT == 1U)
    SCB->CPACR |= ((3UL << 10*2) | (3UL << 11*2));
#endif
    
    /* Configure vector table location */
    SCB->VTOR = 0x08000000;
}

#endif /* STM32F4 */
