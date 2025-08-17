/*
 * SD Card Encryption Example
 * ArmAsm-CryptoEngine - File encryption/decryption on SD card
 * 
 * Demonstrates CTR mode encryption with HMAC authentication
 * for secure file storage on SD cards
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "armcrypto/aes.h"
#include "armcrypto/sha256.h"
#include "armcrypto/ct.h"
#include "platform.h"
#include "sd_crypto.h"

/* Configuration */
#define MAX_FILENAME_LEN 256
#define MAX_FILE_SIZE (10 * 1024 * 1024)  /* 10 MB max */
#define PROGRESS_UPDATE_KB 64              /* Update progress every 64 KB */

/* Global encryption context */
static sd_crypto_ctx g_crypto_ctx;

/*
 * Print usage information
 */
static void print_usage(const char* program_name)
{
    printf("SD Card Encryption Tool\n");
    printf("Usage: %s <command> [options]\n\n", program_name);
    
    printf("Commands:\n");
    printf("  encrypt <input_file> <output_file> <password>\n");
    printf("  decrypt <input_file> <output_file> <password>\n");
    printf("  verify <encrypted_file> <password>\n");
    printf("  keygen <key_file>\n");
    printf("  info <encrypted_file>\n\n");
    
    printf("Options:\n");
    printf("  --key-file <file>    Use key from file instead of password\n");
    printf("  --no-progress        Disable progress display\n");
    printf("  --verbose            Enable verbose output\n\n");
    
    printf("Examples:\n");
    printf("  %s encrypt document.txt document.enc mypassword\n", program_name);
    printf("  %s decrypt document.enc document.txt mypassword\n", program_name);
    printf("  %s verify document.enc mypassword\n", program_name);
    printf("  %s keygen master.key\n", program_name);
}

/*
 * Progress callback for file operations
 */
static void progress_callback(size_t bytes_processed, size_t total_bytes, void* user_data)
{
    int show_progress = *(int*)user_data;
    
    if (!show_progress) return;
    
    int percent = (int)((bytes_processed * 100) / total_bytes);
    
    printf("\rProgress: %d%% (%zu / %zu bytes)", percent, bytes_processed, total_bytes);
    fflush(stdout);
    
    if (bytes_processed >= total_bytes) {
        printf("\n");
    }
}

/*
 * Derive key from password using PBKDF2-like approach
 */
static int derive_key_from_password(const char* password, const uint8_t* salt, 
                                   size_t salt_len, uint8_t key[32])
{
    /* Simple key derivation - in production, use proper PBKDF2 */
    arm_hmac_sha256_ctx hmac_ctx;
    
    /* Initialize with password */
    arm_hmac_sha256_init(&hmac_ctx, (const uint8_t*)password, strlen(password));
    arm_hmac_sha256_update(&hmac_ctx, salt, salt_len);
    
    /* Add some iterations for key strengthening */
    for (int i = 0; i < 1000; i++) {
        uint8_t temp[32];
        arm_hmac_sha256_final(&hmac_ctx, temp);
        
        /* Re-initialize for next iteration */
        arm_hmac_sha256_clear(&hmac_ctx);
        arm_hmac_sha256_init(&hmac_ctx, temp, 32);
        arm_hmac_sha256_update(&hmac_ctx, (const uint8_t*)password, strlen(password));
        
        if (i == 999) {
            memcpy(key, temp, 32);
        }
        
        arm_secure_zero(temp, sizeof(temp));
    }
    
    arm_hmac_sha256_clear(&hmac_ctx);
    return 0;
}

/*
 * Load key from file
 */
static int load_key_from_file(const char* filename, uint8_t key[32])
{
    if (!platform_file_exists(filename)) {
        printf("Error: Key file '%s' not found\n", filename);
        return -1;
    }
    
    size_t file_size;
    if (platform_file_get_size(filename, &file_size) != PLATFORM_SUCCESS) {
        printf("Error: Cannot get key file size\n");
        return -1;
    }
    
    if (file_size != 32) {
        printf("Error: Key file must be exactly 32 bytes\n");
        return -1;
    }
    
    if (platform_file_read(filename, key, 32) != PLATFORM_SUCCESS) {
        printf("Error: Cannot read key file\n");
        return -1;
    }
    
    return 0;
}

/*
 * Save key to file
 */
static int save_key_to_file(const char* filename, const uint8_t key[32])
{
    if (platform_file_write(filename, key, 32) != PLATFORM_SUCCESS) {
        printf("Error: Cannot write key file\n");
        return -1;
    }
    
    printf("Key saved to '%s'\n", filename);
    return 0;
}

/*
 * Encrypt file command
 */
static int cmd_encrypt(const char* input_file, const char* output_file, 
                      const char* password, const char* key_file, int show_progress)
{
    uint8_t key[32];
    
    /* Get encryption key */
    if (key_file) {
        if (load_key_from_file(key_file, key) != 0) {
            return -1;
        }
    } else {
        /* Generate salt for key derivation */
        uint8_t salt[16];
        if (platform_rng_get_bytes(salt, sizeof(salt)) != PLATFORM_SUCCESS) {
            printf("Error: Failed to generate salt\n");
            return -1;
        }
        
        if (derive_key_from_password(password, salt, sizeof(salt), key) != 0) {
            printf("Error: Key derivation failed\n");
            return -1;
        }
    }
    
    /* Initialize crypto context */
    if (sd_crypto_init(&g_crypto_ctx, key) != 0) {
        printf("Error: Crypto initialization failed\n");
        arm_secure_zero(key, sizeof(key));
        return -1;
    }
    
    /* Encrypt file */
    printf("Encrypting '%s' to '%s'...\n", input_file, output_file);
    
    int result = sd_crypto_encrypt_file(&g_crypto_ctx, input_file, output_file, 
                                       progress_callback, &show_progress);
    
    if (result == 0) {
        printf("Encryption completed successfully\n");
        
        /* Verify the encrypted file */
        if (sd_crypto_verify_file(&g_crypto_ctx, output_file) == 0) {
            printf("Verification passed\n");
        } else {
            printf("Warning: Verification failed\n");
        }
    } else {
        printf("Encryption failed\n");
    }
    
    /* Cleanup */
    sd_crypto_cleanup(&g_crypto_ctx);
    arm_secure_zero(key, sizeof(key));
    
    return result;
}

/*
 * Decrypt file command
 */
static int cmd_decrypt(const char* input_file, const char* output_file,
                      const char* password, const char* key_file, int show_progress)
{
    uint8_t key[32];
    
    /* Get decryption key */
    if (key_file) {
        if (load_key_from_file(key_file, key) != 0) {
            return -1;
        }
    } else {
        /* For password-based decryption, we need to read the salt from the file */
        sd_crypto_header header;
        if (sd_crypto_read_header(input_file, &header) != 0) {
            printf("Error: Cannot read encrypted file header\n");
            return -1;
        }
        
        if (derive_key_from_password(password, header.salt, sizeof(header.salt), key) != 0) {
            printf("Error: Key derivation failed\n");
            return -1;
        }
    }
    
    /* Initialize crypto context */
    if (sd_crypto_init(&g_crypto_ctx, key) != 0) {
        printf("Error: Crypto initialization failed\n");
        arm_secure_zero(key, sizeof(key));
        return -1;
    }
    
    /* Decrypt file */
    printf("Decrypting '%s' to '%s'...\n", input_file, output_file);
    
    int result = sd_crypto_decrypt_file(&g_crypto_ctx, input_file, output_file,
                                       progress_callback, &show_progress);
    
    if (result == 0) {
        printf("Decryption completed successfully\n");
    } else {
        printf("Decryption failed\n");
    }
    
    /* Cleanup */
    sd_crypto_cleanup(&g_crypto_ctx);
    arm_secure_zero(key, sizeof(key));
    
    return result;
}

/*
 * Verify file command
 */
static int cmd_verify(const char* encrypted_file, const char* password, const char* key_file)
{
    uint8_t key[32];
    
    /* Get key for verification */
    if (key_file) {
        if (load_key_from_file(key_file, key) != 0) {
            return -1;
        }
    } else {
        sd_crypto_header header;
        if (sd_crypto_read_header(encrypted_file, &header) != 0) {
            printf("Error: Cannot read encrypted file header\n");
            return -1;
        }
        
        if (derive_key_from_password(password, header.salt, sizeof(header.salt), key) != 0) {
            printf("Error: Key derivation failed\n");
            return -1;
        }
    }
    
    /* Initialize crypto context */
    if (sd_crypto_init(&g_crypto_ctx, key) != 0) {
        printf("Error: Crypto initialization failed\n");
        arm_secure_zero(key, sizeof(key));
        return -1;
    }
    
    /* Verify file */
    printf("Verifying '%s'...\n", encrypted_file);
    
    int result = sd_crypto_verify_file(&g_crypto_ctx, encrypted_file);
    
    if (result == 0) {
        printf("Verification passed - file is authentic\n");
    } else {
        printf("Verification failed - file may be corrupted or tampered with\n");
    }
    
    /* Cleanup */
    sd_crypto_cleanup(&g_crypto_ctx);
    arm_secure_zero(key, sizeof(key));
    
    return result;
}

/*
 * Key generation command
 */
static int cmd_keygen(const char* key_file)
{
    uint8_t key[32];
    
    /* Generate random key */
    if (platform_rng_get_bytes(key, sizeof(key)) != PLATFORM_SUCCESS) {
        printf("Error: Failed to generate random key\n");
        return -1;
    }
    
    /* Save key to file */
    int result = save_key_to_file(key_file, key);
    
    /* Clear key from memory */
    arm_secure_zero(key, sizeof(key));
    
    return result;
}

/*
 * Info command
 */
static int cmd_info(const char* encrypted_file)
{
    sd_crypto_header header;
    
    if (sd_crypto_read_header(encrypted_file, &header) != 0) {
        printf("Error: Cannot read encrypted file header\n");
        return -1;
    }
    
    printf("Encrypted file information:\n");
    printf("  File: %s\n", encrypted_file);
    printf("  Version: %d\n", header.version);
    printf("  Algorithm: AES-256-CTR\n");
    printf("  Authentication: HMAC-SHA256\n");
    printf("  Original size: %llu bytes\n", (unsigned long long)header.original_size);
    printf("  Encrypted size: %llu bytes\n", (unsigned long long)header.encrypted_size);
    
    /* Show file size on disk */
    size_t file_size;
    if (platform_file_get_size(encrypted_file, &file_size) == PLATFORM_SUCCESS) {
        printf("  Total file size: %zu bytes\n", file_size);
    }
    
    printf("  Salt: ");
    for (int i = 0; i < 16; i++) {
        printf("%02x", header.salt[i]);
    }
    printf("\n");
    
    printf("  IV: ");
    for (int i = 0; i < 16; i++) {
        printf("%02x", header.iv[i]);
    }
    printf("\n");
    
    return 0;
}

/*
 * Parse command line arguments
 */
typedef struct {
    const char* command;
    const char* input_file;
    const char* output_file;
    const char* password;
    const char* key_file;
    int show_progress;
    int verbose;
} cmd_args_t;

static int parse_args(int argc, char** argv, cmd_args_t* args)
{
    memset(args, 0, sizeof(cmd_args_t));
    args->show_progress = 1;  /* Default to showing progress */
    
    if (argc < 2) {
        return -1;
    }
    
    args->command = argv[1];
    
    int arg_idx = 2;
    while (arg_idx < argc) {
        if (strcmp(argv[arg_idx], "--key-file") == 0) {
            if (arg_idx + 1 >= argc) return -1;
            args->key_file = argv[++arg_idx];
        } else if (strcmp(argv[arg_idx], "--no-progress") == 0) {
            args->show_progress = 0;
        } else if (strcmp(argv[arg_idx], "--verbose") == 0) {
            args->verbose = 1;
        } else {
            /* Positional arguments */
            if (strcmp(args->command, "encrypt") == 0 || strcmp(args->command, "decrypt") == 0) {
                if (!args->input_file) args->input_file = argv[arg_idx];
                else if (!args->output_file) args->output_file = argv[arg_idx];
                else if (!args->password && !args->key_file) args->password = argv[arg_idx];
            } else if (strcmp(args->command, "verify") == 0) {
                if (!args->input_file) args->input_file = argv[arg_idx];
                else if (!args->password && !args->key_file) args->password = argv[arg_idx];
            } else if (strcmp(args->command, "keygen") == 0) {
                if (!args->output_file) args->output_file = argv[arg_idx];
            } else if (strcmp(args->command, "info") == 0) {
                if (!args->input_file) args->input_file = argv[arg_idx];
            }
        }
        arg_idx++;
    }
    
    return 0;
}

/*
 * Main function
 */
int main(int argc, char** argv)
{
    cmd_args_t args;
    
    /* Parse command line arguments */
    if (parse_args(argc, argv, &args) != 0) {
        print_usage(argv[0]);
        return 1;
    }
    
    /* Initialize platform */
    if (platform_init() != PLATFORM_SUCCESS) {
        printf("Error: Failed to initialize platform\n");
        return 1;
    }
    
    /* Initialize random number generator */
    if (platform_rng_init() != PLATFORM_SUCCESS) {
        printf("Error: Failed to initialize RNG\n");
        return 1;
    }
    
    printf("SD Card Encryption Tool v1.0.0\n");
    printf("Platform: %s\n\n", platform_get_info_string());
    
    int result = 0;
    
    /* Execute command */
    if (strcmp(args.command, "encrypt") == 0) {
        if (!args.input_file || !args.output_file || (!args.password && !args.key_file)) {
            printf("Error: Missing arguments for encrypt command\n");
            print_usage(argv[0]);
            result = 1;
        } else {
            result = cmd_encrypt(args.input_file, args.output_file, args.password, 
                               args.key_file, args.show_progress);
        }
    } else if (strcmp(args.command, "decrypt") == 0) {
        if (!args.input_file || !args.output_file || (!args.password && !args.key_file)) {
            printf("Error: Missing arguments for decrypt command\n");
            print_usage(argv[0]);
            result = 1;
        } else {
            result = cmd_decrypt(args.input_file, args.output_file, args.password,
                               args.key_file, args.show_progress);
        }
    } else if (strcmp(args.command, "verify") == 0) {
        if (!args.input_file || (!args.password && !args.key_file)) {
            printf("Error: Missing arguments for verify command\n");
            print_usage(argv[0]);
            result = 1;
        } else {
            result = cmd_verify(args.input_file, args.password, args.key_file);
        }
    } else if (strcmp(args.command, "keygen") == 0) {
        if (!args.output_file) {
            printf("Error: Missing key file name\n");
            print_usage(argv[0]);
            result = 1;
        } else {
            result = cmd_keygen(args.output_file);
        }
    } else if (strcmp(args.command, "info") == 0) {
        if (!args.input_file) {
            printf("Error: Missing encrypted file name\n");
            print_usage(argv[0]);
            result = 1;
        } else {
            result = cmd_info(args.input_file);
        }
    } else {
        printf("Error: Unknown command '%s'\n", args.command);
        print_usage(argv[0]);
        result = 1;
    }
    
    /* Cleanup */
#ifdef PLATFORM_RPI
    platform_rng_cleanup();
    platform_cleanup();
#endif
    
    return result;
}
