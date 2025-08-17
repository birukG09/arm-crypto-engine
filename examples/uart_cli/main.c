/*
 * UART CLI Crypto Tool
 * ArmAsm-CryptoEngine - Interactive cryptographic operations over UART
 * 
 * Provides a command-line interface for AES and SHA-256 operations
 * accessible via UART for embedded systems testing and demonstrations
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "armcrypto/aes.h"
#include "armcrypto/sha256.h"
#include "armcrypto/ct.h"
#include "platform.h"
#include "commands.h"

/* CLI Configuration */
#define CLI_BUFFER_SIZE 1024
#define CLI_MAX_ARGS 16
#define CLI_PROMPT "crypto> "
#define CLI_VERSION "1.0.0"

/* Global state */
static char cli_buffer[CLI_BUFFER_SIZE];
static char* cli_args[CLI_MAX_ARGS];
static int cli_running = 1;

/*
 * Print welcome message
 */
static void print_welcome(void)
{
    printf("\n");
    printf("=====================================\n");
    printf("  ArmAsm-CryptoEngine UART CLI %s\n", CLI_VERSION);
    printf("=====================================\n");
    printf("Platform: %s\n", platform_get_info_string());
    printf("Type 'help' for available commands\n");
    printf("\n");
}

/*
 * Parse command line into arguments
 */
static int parse_command_line(char* line, char** args, int max_args)
{
    int argc = 0;
    char* token = strtok(line, " \t\r\n");
    
    while (token != NULL && argc < max_args - 1) {
        args[argc++] = token;
        token = strtok(NULL, " \t\r\n");
    }
    
    args[argc] = NULL;
    return argc;
}

/*
 * Print command prompt
 */
static void print_prompt(void)
{
    printf(CLI_PROMPT);
    fflush(stdout);
}

/*
 * Read command line from UART
 */
static int read_command_line(char* buffer, size_t buffer_size)
{
    size_t pos = 0;
    uint8_t ch;
    
    while (pos < buffer_size - 1) {
        /* Read single character with timeout */
        if (platform_uart_receive(&ch, 1, 5000) != PLATFORM_SUCCESS) {
            continue; /* Timeout, try again */
        }
        
        /* Handle special characters */
        if (ch == '\r' || ch == '\n') {
            buffer[pos] = '\0';
            printf("\n");
            return pos > 0 ? 1 : 0;
        } else if (ch == '\b' || ch == 0x7F) { /* Backspace */
            if (pos > 0) {
                pos--;
                printf("\b \b"); /* Erase character on terminal */
            }
        } else if (ch >= 32 && ch <= 126) { /* Printable characters */
            buffer[pos++] = ch;
            printf("%c", ch); /* Echo character */
        }
        /* Ignore other control characters */
    }
    
    buffer[buffer_size - 1] = '\0';
    return 1;
}

/*
 * Execute command
 */
static void execute_command(int argc, char** argv)
{
    if (argc == 0) {
        return;
    }
    
    const char* cmd = argv[0];
    
    /* Built-in commands */
    if (strcmp(cmd, "help") == 0 || strcmp(cmd, "?") == 0) {
        cmd_help(argc, argv);
    } else if (strcmp(cmd, "version") == 0) {
        cmd_version(argc, argv);
    } else if (strcmp(cmd, "status") == 0) {
        cmd_status(argc, argv);
    } else if (strcmp(cmd, "clear") == 0) {
        cmd_clear(argc, argv);
    } else if (strcmp(cmd, "exit") == 0 || strcmp(cmd, "quit") == 0) {
        cmd_exit(argc, argv);
        cli_running = 0;
    }
    
    /* AES commands */
    else if (strcmp(cmd, "aes-encrypt") == 0 || strcmp(cmd, "aes-enc") == 0) {
        cmd_aes_encrypt(argc, argv);
    } else if (strcmp(cmd, "aes-decrypt") == 0 || strcmp(cmd, "aes-dec") == 0) {
        cmd_aes_decrypt(argc, argv);
    } else if (strcmp(cmd, "aes-keygen") == 0) {
        cmd_aes_keygen(argc, argv);
    }
    
    /* SHA-256 commands */
    else if (strcmp(cmd, "sha256") == 0) {
        cmd_sha256(argc, argv);
    } else if (strcmp(cmd, "hmac") == 0) {
        cmd_hmac(argc, argv);
    }
    
    /* Utility commands */
    else if (strcmp(cmd, "hex2bin") == 0) {
        cmd_hex2bin(argc, argv);
    } else if (strcmp(cmd, "bin2hex") == 0) {
        cmd_bin2hex(argc, argv);
    } else if (strcmp(cmd, "base64-enc") == 0) {
        cmd_base64_encode(argc, argv);
    } else if (strcmp(cmd, "base64-dec") == 0) {
        cmd_base64_decode(argc, argv);
    }
    
    /* Benchmark commands */
    else if (strcmp(cmd, "bench-aes") == 0) {
        cmd_bench_aes(argc, argv);
    } else if (strcmp(cmd, "bench-sha256") == 0) {
        cmd_bench_sha256(argc, argv);
    } else if (strcmp(cmd, "bench-all") == 0) {
        cmd_bench_all(argc, argv);
    }
    
    /* Test commands */
    else if (strcmp(cmd, "test-aes") == 0) {
        cmd_test_aes(argc, argv);
    } else if (strcmp(cmd, "test-sha256") == 0) {
        cmd_test_sha256(argc, argv);
    } else if (strcmp(cmd, "test-all") == 0) {
        cmd_test_all(argc, argv);
    }
    
    /* Random number generation */
    else if (strcmp(cmd, "random") == 0 || strcmp(cmd, "rand") == 0) {
        cmd_random(argc, argv);
    }
    
    else {
        printf("Unknown command: %s\n", cmd);
        printf("Type 'help' for available commands\n");
    }
}

/*
 * Main CLI loop
 */
static void cli_loop(void)
{
    print_welcome();
    
    while (cli_running) {
        print_prompt();
        
        if (read_command_line(cli_buffer, CLI_BUFFER_SIZE)) {
            int argc = parse_command_line(cli_buffer, cli_args, CLI_MAX_ARGS);
            execute_command(argc, cli_args);
        }
    }
    
    printf("Goodbye!\n");
}

/*
 * Initialize UART CLI
 */
static int init_uart_cli(void)
{
    /* Configure UART */
    platform_uart_config_t uart_config = {
#ifdef PLATFORM_STM32F4
        .uart_base = (void*)0x40004400,  /* USART2 base address */
#else
        .device = "/dev/serial0",        /* Raspberry Pi serial device */
#endif
        .baudrate = 115200,
        .data_bits = 8,
        .stop_bits = 1,
        .parity = 0,
        .flow_control = 0
    };
    
    if (platform_uart_init(&uart_config) != PLATFORM_SUCCESS) {
        return -1;
    }
    
    /* Initialize random number generator */
    platform_rng_init();
    
    return 0;
}

/*
 * Handle system errors
 */
static void handle_error(const char* message)
{
    printf("ERROR: %s\n", message);
    printf("System will continue running...\n");
}

/*
 * Signal handler for graceful shutdown
 */
#ifndef PLATFORM_STM32F4
#include <signal.h>

static void signal_handler(int sig)
{
    (void)sig;
    cli_running = 0;
    printf("\nReceived shutdown signal, exiting...\n");
}
#endif

/*
 * Main function
 */
int main(void)
{
    /* Initialize platform */
    if (platform_init() != PLATFORM_SUCCESS) {
        handle_error("Failed to initialize platform");
        return 1;
    }
    
    /* Initialize cycle counter for benchmarking */
    if (platform_cycles_init() != PLATFORM_SUCCESS) {
        handle_error("Failed to initialize cycle counter");
        /* Continue anyway, benchmarks will be disabled */
    }
    
    /* Initialize UART CLI */
    if (init_uart_cli() != 0) {
        handle_error("Failed to initialize UART CLI");
        return 1;
    }
    
#ifndef PLATFORM_STM32F4
    /* Set up signal handlers for graceful shutdown */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
#endif
    
    /* Initialize command system */
    if (cmd_init() != 0) {
        handle_error("Failed to initialize command system");
        return 1;
    }
    
    /* Run CLI loop */
    cli_loop();
    
    /* Cleanup */
    cmd_cleanup();
    
#ifdef PLATFORM_RPI
    platform_uart_cleanup();
    platform_rng_cleanup();
    platform_cleanup();
#endif
    
    return 0;
}

#ifdef PLATFORM_STM32F4
/*
 * STM32 specific initialization and interrupt handlers
 */

/* System Clock Configuration for STM32F4 */
void SystemClock_Config(void)
{
    /* This would contain STM32-specific clock configuration */
    /* For now, rely on platform_init() to handle this */
}

/* SysTick Handler */
void SysTick_Handler(void)
{
    /* System tick handler - can be used for timeouts */
}

/* Hard Fault Handler */
void HardFault_Handler(void)
{
    printf("\nHARD FAULT DETECTED\n");
    printf("System halted. Please reset the device.\n");
    while(1);
}

/* Memory Management Fault Handler */
void MemManage_Handler(void)
{
    printf("\nMEMORY MANAGEMENT FAULT\n");
    printf("System halted. Please reset the device.\n");
    while(1);
}

/* Bus Fault Handler */
void BusFault_Handler(void)
{
    printf("\nBUS FAULT\n");
    printf("System halted. Please reset the device.\n");
    while(1);
}

/* Usage Fault Handler */
void UsageFault_Handler(void)
{
    printf("\nUSAGE FAULT\n");
    printf("System halted. Please reset the device.\n");
    while(1);
}

/* Reset handler */
void Reset_Handler(void)
{
    /* Initialize system */
    SystemClock_Config();
    
    /* Initialize static constructors */
    void __libc_init_array(void);
    __libc_init_array();
    
    /* Call main */
    main();
    
    /* Should not reach here */
    while(1);
}

#endif /* PLATFORM_STM32F4 */
