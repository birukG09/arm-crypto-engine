/*
 * UART CLI Commands Implementation
 * ArmAsm-CryptoEngine - Command handlers for UART CLI
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>

#include "commands.h"
#include "armcrypto/aes.h"
#include "armcrypto/sha256.h"
#include "armcrypto/ct.h"
#include "platform.h"

/* Command state */
static int commands_initialized = 0;

/* Helper function prototypes */
static int hex_to_bytes(const char* hex, uint8_t* bytes, size_t max_bytes);
static void bytes_to_hex(const uint8_t* bytes, size_t len, char* hex);
static void print_hex(const uint8_t* data, size_t len);
static int parse_size_t(const char* str, size_t* value);

/*
 * Initialize command system
 */
int cmd_init(void)
{
    commands_initialized = 1;
    return 0;
}

/*
 * Cleanup command system
 */
void cmd_cleanup(void)
{
    commands_initialized = 0;
}

/*
 * Help command
 */
void cmd_help(int argc, char** argv)
{
    (void)argc;
    (void)argv;
    
    printf("Available commands:\n\n");
    
    printf("General:\n");
    printf("  help, ?              - Show this help message\n");
    printf("  version              - Show version information\n");
    printf("  status               - Show system status\n");
    printf("  clear                - Clear screen\n");
    printf("  exit, quit           - Exit CLI\n\n");
    
    printf("AES Commands:\n");
    printf("  aes-encrypt <key> <mode> <data> [iv] - Encrypt data\n");
    printf("  aes-decrypt <key> <mode> <data> [iv] - Decrypt data\n");
    printf("  aes-keygen <size>    - Generate AES key (128/192/256)\n");
    printf("    modes: ecb, cbc, ctr\n");
    printf("    key/data/iv in hex format\n\n");
    
    printf("SHA-256 Commands:\n");
    printf("  sha256 <data>        - Calculate SHA-256 hash\n");
    printf("  hmac <key> <data>    - Calculate HMAC-SHA256\n");
    printf("    key/data in hex format\n\n");
    
    printf("Utility Commands:\n");
    printf("  hex2bin <hex>        - Convert hex to binary\n");
    printf("  bin2hex <text>       - Convert text to hex\n");
    printf("  base64-enc <hex>     - Base64 encode hex data\n");
    printf("  base64-dec <b64>     - Base64 decode to hex\n");
    printf("  random <bytes>       - Generate random hex data\n\n");
    
    printf("Test Commands:\n");
    printf("  test-aes             - Run AES test vectors\n");
    printf("  test-sha256          - Run SHA-256 test vectors\n");
    printf("  test-all             - Run all test vectors\n\n");
    
    printf("Benchmark Commands:\n");
    printf("  bench-aes [size]     - Benchmark AES operations\n");
    printf("  bench-sha256 [size]  - Benchmark SHA-256\n");
    printf("  bench-all            - Run all benchmarks\n\n");
    
    printf("Examples:\n");
    printf("  aes-encrypt 000102030405060708090a0b0c0d0e0f ecb 00112233445566778899aabbccddeeff\n");
    printf("  sha256 48656c6c6f20576f726c64\n");
    printf("  hmac 0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b 4869205468657265\n");
    printf("  random 16\n");
}

/*
 * Version command
 */
void cmd_version(int argc, char** argv)
{
    (void)argc;
    (void)argv;
    
    printf("ArmAsm-CryptoEngine UART CLI v1.0.0\n");
    printf("Platform: %s\n", platform_get_info_string());
    printf("CPU Frequency: %u MHz\n", platform_get_clock_freq() / 1000000);
    
#ifdef ARM_CORTEX_A53
    printf("NEON Support: %s\n", platform_has_neon() ? "Yes" : "No");
    printf("Crypto Extensions: %s\n", platform_has_crypto_ext() ? "Yes" : "No");
#endif
    
    printf("Build Date: %s %s\n", __DATE__, __TIME__);
}

/*
 * Status command
 */
void cmd_status(int argc, char** argv)
{
    (void)argc;
    (void)argv;
    
    printf("System Status:\n");
    printf("  Platform: %s\n", platform_get_info_string());
    printf("  Commands initialized: %s\n", commands_initialized ? "Yes" : "No");
    printf("  Memory usage: N/A\n"); /* Could add memory tracking */
    
#ifdef PLATFORM_RPI
    float temp;
    if (platform_get_temperature(&temp) == PLATFORM_SUCCESS) {
        printf("  CPU Temperature: %.1f°C\n", temp);
    }
    
    printf("  Thermal throttled: %s\n", platform_is_thermal_throttled() ? "Yes" : "No");
#endif
}

/*
 * Clear screen command
 */
void cmd_clear(int argc, char** argv)
{
    (void)argc;
    (void)argv;
    
    printf("\033[2J\033[H"); /* ANSI escape sequence to clear screen */
}

/*
 * Exit command
 */
void cmd_exit(int argc, char** argv)
{
    (void)argc;
    (void)argv;
    
    printf("Exiting CLI...\n");
}

/*
 * AES encrypt command
 */
void cmd_aes_encrypt(int argc, char** argv)
{
    if (argc < 4) {
        printf("Usage: aes-encrypt <key> <mode> <data> [iv]\n");
        printf("  key: hex string (32/48/64 chars for AES-128/192/256)\n");
        printf("  mode: ecb, cbc, ctr\n");
        printf("  data: hex string (must be multiple of 32 chars for ECB/CBC)\n");
        printf("  iv: hex string (32 chars, required for CBC/CTR)\n");
        return;
    }
    
    const char* key_hex = argv[1];
    const char* mode = argv[2];
    const char* data_hex = argv[3];
    const char* iv_hex = (argc >= 5) ? argv[4] : NULL;
    
    /* Parse key */
    size_t key_len = strlen(key_hex) / 2;
    if (key_len != 16 && key_len != 24 && key_len != 32) {
        printf("Error: Invalid key length. Must be 32, 48, or 64 hex characters\n");
        return;
    }
    
    uint8_t key[32];
    if (hex_to_bytes(key_hex, key, sizeof(key)) != key_len) {
        printf("Error: Invalid key format\n");
        return;
    }
    
    /* Parse data */
    size_t data_len = strlen(data_hex) / 2;
    if (data_len == 0 || data_len > 1024) {
        printf("Error: Invalid data length\n");
        return;
    }
    
    uint8_t* plaintext = malloc(data_len);
    uint8_t* ciphertext = malloc(data_len);
    
    if (!plaintext || !ciphertext) {
        printf("Error: Memory allocation failed\n");
        free(plaintext);
        free(ciphertext);
        return;
    }
    
    if (hex_to_bytes(data_hex, plaintext, data_len) != data_len) {
        printf("Error: Invalid data format\n");
        free(plaintext);
        free(ciphertext);
        return;
    }
    
    /* Parse IV if needed */
    uint8_t iv[16];
    if (strcmp(mode, "cbc") == 0 || strcmp(mode, "ctr") == 0) {
        if (!iv_hex) {
            printf("Error: IV required for %s mode\n", mode);
            free(plaintext);
            free(ciphertext);
            return;
        }
        
        if (hex_to_bytes(iv_hex, iv, sizeof(iv)) != 16) {
            printf("Error: Invalid IV format (must be 32 hex characters)\n");
            free(plaintext);
            free(ciphertext);
            return;
        }
    }
    
    /* Initialize AES */
    arm_aes_ctx ctx;
    arm_aes_init(&ctx, key, key_len * 8);
    
    /* Encrypt based on mode */
    if (strcmp(mode, "ecb") == 0) {
        if (data_len % 16 != 0) {
            printf("Error: Data length must be multiple of 16 bytes for ECB mode\n");
            goto cleanup;
        }
        
        for (size_t i = 0; i < data_len; i += 16) {
            arm_aes_ecb_encrypt(&ctx, &plaintext[i], &ciphertext[i]);
        }
        
    } else if (strcmp(mode, "cbc") == 0) {
        if (data_len % 16 != 0) {
            printf("Error: Data length must be multiple of 16 bytes for CBC mode\n");
            goto cleanup;
        }
        
        arm_aes_cbc_encrypt(&ctx, iv, plaintext, ciphertext, data_len);
        
    } else if (strcmp(mode, "ctr") == 0) {
        arm_aes_ctr_crypt(&ctx, iv, plaintext, ciphertext, data_len);
        
    } else {
        printf("Error: Unsupported mode '%s'\n", mode);
        goto cleanup;
    }
    
    /* Output result */
    printf("Encrypted: ");
    print_hex(ciphertext, data_len);
    
    if (strcmp(mode, "cbc") == 0 || strcmp(mode, "ctr") == 0) {
        printf("Final IV: ");
        print_hex(iv, 16);
    }
    
cleanup:
    arm_aes_clear(&ctx);
    arm_secure_zero(plaintext, data_len);
    arm_secure_zero(ciphertext, data_len);
    free(plaintext);
    free(ciphertext);
}

/*
 * AES decrypt command
 */
void cmd_aes_decrypt(int argc, char** argv)
{
    if (argc < 4) {
        printf("Usage: aes-decrypt <key> <mode> <data> [iv]\n");
        return;
    }
    
    const char* key_hex = argv[1];
    const char* mode = argv[2];
    const char* data_hex = argv[3];
    const char* iv_hex = (argc >= 5) ? argv[4] : NULL;
    
    /* Parse key */
    size_t key_len = strlen(key_hex) / 2;
    if (key_len != 16 && key_len != 24 && key_len != 32) {
        printf("Error: Invalid key length\n");
        return;
    }
    
    uint8_t key[32];
    if (hex_to_bytes(key_hex, key, sizeof(key)) != key_len) {
        printf("Error: Invalid key format\n");
        return;
    }
    
    /* Parse data */
    size_t data_len = strlen(data_hex) / 2;
    uint8_t* ciphertext = malloc(data_len);
    uint8_t* plaintext = malloc(data_len);
    
    if (!ciphertext || !plaintext) {
        printf("Error: Memory allocation failed\n");
        free(ciphertext);
        free(plaintext);
        return;
    }
    
    if (hex_to_bytes(data_hex, ciphertext, data_len) != data_len) {
        printf("Error: Invalid data format\n");
        free(ciphertext);
        free(plaintext);
        return;
    }
    
    /* Parse IV if needed */
    uint8_t iv[16];
    if (strcmp(mode, "cbc") == 0 || strcmp(mode, "ctr") == 0) {
        if (!iv_hex || hex_to_bytes(iv_hex, iv, sizeof(iv)) != 16) {
            printf("Error: Invalid IV format\n");
            free(ciphertext);
            free(plaintext);
            return;
        }
    }
    
    /* Initialize AES */
    arm_aes_ctx ctx;
    arm_aes_init(&ctx, key, key_len * 8);
    
    /* Decrypt based on mode */
    if (strcmp(mode, "ecb") == 0) {
        for (size_t i = 0; i < data_len; i += 16) {
            arm_aes_ecb_decrypt(&ctx, &ciphertext[i], &plaintext[i]);
        }
    } else if (strcmp(mode, "cbc") == 0) {
        arm_aes_cbc_decrypt(&ctx, iv, ciphertext, plaintext, data_len);
    } else if (strcmp(mode, "ctr") == 0) {
        arm_aes_ctr_crypt(&ctx, iv, ciphertext, plaintext, data_len);
    } else {
        printf("Error: Unsupported mode '%s'\n", mode);
        goto cleanup_decrypt;
    }
    
    /* Output result */
    printf("Decrypted: ");
    print_hex(plaintext, data_len);
    
cleanup_decrypt:
    arm_aes_clear(&ctx);
    arm_secure_zero(ciphertext, data_len);
    arm_secure_zero(plaintext, data_len);
    free(ciphertext);
    free(plaintext);
}

/*
 * AES key generation command
 */
void cmd_aes_keygen(int argc, char** argv)
{
    if (argc < 2) {
        printf("Usage: aes-keygen <size>\n");
        printf("  size: 128, 192, or 256\n");
        return;
    }
    
    size_t key_size;
    if (!parse_size_t(argv[1], &key_size)) {
        printf("Error: Invalid key size\n");
        return;
    }
    
    size_t key_bytes;
    switch (key_size) {
        case 128: key_bytes = 16; break;
        case 192: key_bytes = 24; break;
        case 256: key_bytes = 32; break;
        default:
            printf("Error: Key size must be 128, 192, or 256\n");
            return;
    }
    
    uint8_t key[32];
    if (platform_rng_get_bytes(key, key_bytes) != PLATFORM_SUCCESS) {
        printf("Error: Failed to generate random key\n");
        return;
    }
    
    printf("Generated AES-%zu key: ", key_size);
    print_hex(key, key_bytes);
    
    arm_secure_zero(key, sizeof(key));
}

/*
 * SHA-256 command
 */
void cmd_sha256(int argc, char** argv)
{
    if (argc < 2) {
        printf("Usage: sha256 <data>\n");
        printf("  data: hex string\n");
        return;
    }
    
    const char* data_hex = argv[1];
    size_t data_len = strlen(data_hex) / 2;
    
    uint8_t* data = malloc(data_len);
    if (!data) {
        printf("Error: Memory allocation failed\n");
        return;
    }
    
    if (hex_to_bytes(data_hex, data, data_len) != data_len) {
        printf("Error: Invalid data format\n");
        free(data);
        return;
    }
    
    uint8_t hash[32];
    arm_sha256_hash(data, data_len, hash);
    
    printf("SHA-256: ");
    print_hex(hash, 32);
    
    free(data);
}

/*
 * HMAC command
 */
void cmd_hmac(int argc, char** argv)
{
    if (argc < 3) {
        printf("Usage: hmac <key> <data>\n");
        printf("  key: hex string\n");
        printf("  data: hex string\n");
        return;
    }
    
    const char* key_hex = argv[1];
    const char* data_hex = argv[2];
    
    size_t key_len = strlen(key_hex) / 2;
    size_t data_len = strlen(data_hex) / 2;
    
    uint8_t* key = malloc(key_len);
    uint8_t* data = malloc(data_len);
    
    if (!key || !data) {
        printf("Error: Memory allocation failed\n");
        free(key);
        free(data);
        return;
    }
    
    if (hex_to_bytes(key_hex, key, key_len) != key_len ||
        hex_to_bytes(data_hex, data, data_len) != data_len) {
        printf("Error: Invalid hex format\n");
        free(key);
        free(data);
        return;
    }
    
    uint8_t mac[32];
    arm_hmac_sha256(key, key_len, data, data_len, mac);
    
    printf("HMAC-SHA256: ");
    print_hex(mac, 32);
    
    arm_secure_zero(key, key_len);
    free(key);
    free(data);
}

/* Helper functions continue... */

/*
 * Convert hex string to bytes
 */
static int hex_to_bytes(const char* hex, uint8_t* bytes, size_t max_bytes)
{
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0) return -1;
    
    size_t byte_len = hex_len / 2;
    if (byte_len > max_bytes) return -1;
    
    for (size_t i = 0; i < byte_len; i++) {
        char hex_byte[3] = {hex[i*2], hex[i*2+1], 0};
        char* endptr;
        unsigned long val = strtoul(hex_byte, &endptr, 16);
        
        if (*endptr != 0 || val > 255) return -1;
        bytes[i] = (uint8_t)val;
    }
    
    return byte_len;
}

/*
 * Convert bytes to hex string
 */
static void bytes_to_hex(const uint8_t* bytes, size_t len, char* hex)
{
    for (size_t i = 0; i < len; i++) {
        sprintf(&hex[i*2], "%02x", bytes[i]);
    }
    hex[len*2] = 0;
}

/*
 * Print bytes as hex
 */
static void print_hex(const uint8_t* data, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

/*
 * Parse size_t from string
 */
static int parse_size_t(const char* str, size_t* value)
{
    char* endptr;
    unsigned long val = strtoul(str, &endptr, 10);
    
    if (*endptr != 0) return 0;
    *value = (size_t)val;
    return 1;
}

/* Placeholder implementations for remaining commands */
void cmd_hex2bin(int argc, char** argv) { (void)argc; (void)argv; printf("Not implemented\n"); }
void cmd_bin2hex(int argc, char** argv) { (void)argc; (void)argv; printf("Not implemented\n"); }
void cmd_base64_encode(int argc, char** argv) { (void)argc; (void)argv; printf("Not implemented\n"); }
void cmd_base64_decode(int argc, char** argv) { (void)argc; (void)argv; printf("Not implemented\n"); }
void cmd_bench_aes(int argc, char** argv) { (void)argc; (void)argv; printf("Use bench/bench_crypto for full benchmarks\n"); }
void cmd_bench_sha256(int argc, char** argv) { (void)argc; (void)argv; printf("Use bench/bench_crypto for full benchmarks\n"); }
void cmd_bench_all(int argc, char** argv) { (void)argc; (void)argv; printf("Use bench/bench_crypto for full benchmarks\n"); }
void cmd_test_aes(int argc, char** argv) { (void)argc; (void)argv; printf("Use tests/unit/test_aes for full tests\n"); }
void cmd_test_sha256(int argc, char** argv) { (void)argc; (void)argv; printf("Use tests/unit/test_sha256 for full tests\n"); }
void cmd_test_all(int argc, char** argv) { (void)argc; (void)argv; printf("Run individual test suites\n"); }

void cmd_random(int argc, char** argv)
{
    if (argc < 2) {
        printf("Usage: random <bytes>\n");
        return;
    }
    
    size_t num_bytes;
    if (!parse_size_t(argv[1], &num_bytes) || num_bytes == 0 || num_bytes > 256) {
        printf("Error: Invalid byte count (1-256)\n");
        return;
    }
    
    uint8_t* random_data = malloc(num_bytes);
    if (!random_data) {
        printf("Error: Memory allocation failed\n");
        return;
    }
    
    if (platform_rng_get_bytes(random_data, num_bytes) != PLATFORM_SUCCESS) {
        printf("Error: Failed to generate random data\n");
        free(random_data);
        return;
    }
    
    printf("Random data: ");
    print_hex(random_data, num_bytes);
    
    arm_secure_zero(random_data, num_bytes);
    free(random_data);
}
