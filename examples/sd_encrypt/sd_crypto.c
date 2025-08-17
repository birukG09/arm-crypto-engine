/*
 * SD Card Crypto Operations Implementation
 * ArmAsm-CryptoEngine - Secure file encryption for SD cards
 */

#include "sd_crypto.h"
#include "armcrypto/ct.h"
#include "platform.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Algorithm identifiers */
#define SD_CRYPTO_ALG_AES256_CTR_HMAC_SHA256 1

/* Buffer size for file I/O */
#define SD_CRYPTO_BUFFER_SIZE (64 * 1024)  /* 64 KB buffer */

/*
 * Initialize SD crypto context
 */
sd_crypto_result_t sd_crypto_init(sd_crypto_ctx* ctx, const uint8_t master_key[32])
{
    if (!ctx || !master_key) {
        return SD_CRYPTO_ERROR_INVALID_PARAM;
    }
    
    /* Clear context */
    memset(ctx, 0, sizeof(sd_crypto_ctx));
    
    /* Copy master key */
    memcpy(ctx->master_key, master_key, 32);
    
    /* Derive authentication key from master key */
    /* Use HMAC-SHA256 with fixed string as PRF */
    const char* auth_info = "SD_CRYPTO_AUTH_KEY";
    arm_hmac_sha256(master_key, 32, (const uint8_t*)auth_info, strlen(auth_info), ctx->auth_key);
    
    ctx->initialized = 1;
    return SD_CRYPTO_SUCCESS;
}

/*
 * Cleanup SD crypto context
 */
void sd_crypto_cleanup(sd_crypto_ctx* ctx)
{
    if (!ctx) return;
    
    if (ctx->initialized) {
        arm_aes_clear(&ctx->aes_ctx);
    }
    
    /* Securely zero all sensitive data */
    arm_secure_zero(ctx, sizeof(sd_crypto_ctx));
}

/*
 * Derive file encryption keys from master key
 */
void sd_crypto_derive_keys(const uint8_t master_key[32], const uint8_t salt[16],
                          uint8_t enc_key[32], uint8_t auth_key[32])
{
    /* Use HKDF-like key derivation */
    arm_hmac_sha256_ctx hmac_ctx;
    
    /* Derive encryption key */
    const char* enc_info = "SD_CRYPTO_ENC_KEY";
    arm_hmac_sha256_init(&hmac_ctx, master_key, 32);
    arm_hmac_sha256_update(&hmac_ctx, salt, 16);
    arm_hmac_sha256_update(&hmac_ctx, (const uint8_t*)enc_info, strlen(enc_info));
    arm_hmac_sha256_final(&hmac_ctx, enc_key);
    arm_hmac_sha256_clear(&hmac_ctx);
    
    /* Derive authentication key */
    const char* auth_info = "SD_CRYPTO_AUTH_KEY";
    arm_hmac_sha256_init(&hmac_ctx, master_key, 32);
    arm_hmac_sha256_update(&hmac_ctx, salt, 16);
    arm_hmac_sha256_update(&hmac_ctx, (const uint8_t*)auth_info, strlen(auth_info));
    arm_hmac_sha256_final(&hmac_ctx, auth_key);
    arm_hmac_sha256_clear(&hmac_ctx);
}

/*
 * Calculate file MAC
 */
void sd_crypto_calculate_mac(const uint8_t auth_key[32],
                            const sd_crypto_header* header,
                            const uint8_t* encrypted_data,
                            size_t data_size,
                            uint8_t mac[32])
{
    arm_hmac_sha256_ctx hmac_ctx;
    
    arm_hmac_sha256_init(&hmac_ctx, auth_key, 32);
    
    /* Include header in MAC (excluding reserved field) */
    arm_hmac_sha256_update(&hmac_ctx, (const uint8_t*)header, 
                          offsetof(sd_crypto_header, reserved));
    
    /* Include encrypted data */
    arm_hmac_sha256_update(&hmac_ctx, encrypted_data, data_size);
    
    arm_hmac_sha256_final(&hmac_ctx, mac);
    arm_hmac_sha256_clear(&hmac_ctx);
}

/*
 * Read header from encrypted file
 */
sd_crypto_result_t sd_crypto_read_header(const char* encrypted_file, sd_crypto_header* header)
{
    if (!encrypted_file || !header) {
        return SD_CRYPTO_ERROR_INVALID_PARAM;
    }
    
    /* Check if file exists */
    if (!platform_file_exists(encrypted_file)) {
        return SD_CRYPTO_ERROR_FILE_NOT_FOUND;
    }
    
    /* Check file size */
    size_t file_size;
    if (platform_file_get_size(encrypted_file, &file_size) != PLATFORM_SUCCESS) {
        return SD_CRYPTO_ERROR_IO_ERROR;
    }
    
    if (file_size < SD_CRYPTO_HEADER_SIZE) {
        return SD_CRYPTO_ERROR_INVALID_FORMAT;
    }
    
    /* Read header */
    uint8_t header_buffer[SD_CRYPTO_HEADER_SIZE];
    if (platform_file_read(encrypted_file, header_buffer, SD_CRYPTO_HEADER_SIZE) != PLATFORM_SUCCESS) {
        return SD_CRYPTO_ERROR_IO_ERROR;
    }
    
    /* Copy header structure */
    memcpy(header, header_buffer, sizeof(sd_crypto_header));
    
    /* Validate magic bytes */
    if (memcmp(header->magic, SD_CRYPTO_MAGIC, 8) != 0) {
        return SD_CRYPTO_ERROR_INVALID_FORMAT;
    }
    
    /* Validate version */
    if (header->version != SD_CRYPTO_VERSION) {
        return SD_CRYPTO_ERROR_INVALID_FORMAT;
    }
    
    /* Validate algorithm */
    if (header->algorithm != SD_CRYPTO_ALG_AES256_CTR_HMAC_SHA256) {
        return SD_CRYPTO_ERROR_INVALID_FORMAT;
    }
    
    return SD_CRYPTO_SUCCESS;
}

/*
 * Encrypt file to SD card
 */
sd_crypto_result_t sd_crypto_encrypt_file(sd_crypto_ctx* ctx,
                                         const char* input_file,
                                         const char* output_file,
                                         sd_crypto_progress_cb progress_cb,
                                         void* user_data)
{
    if (!ctx || !ctx->initialized || !input_file || !output_file) {
        return SD_CRYPTO_ERROR_INVALID_PARAM;
    }
    
    /* Check if input file exists */
    if (!platform_file_exists(input_file)) {
        return SD_CRYPTO_ERROR_FILE_NOT_FOUND;
    }
    
    /* Get input file size */
    size_t input_size;
    if (platform_file_get_size(input_file, &input_size) != PLATFORM_SUCCESS) {
        return SD_CRYPTO_ERROR_IO_ERROR;
    }
    
    if (input_size > 1024 * 1024 * 1024) {  /* 1 GB limit */
        return SD_CRYPTO_ERROR_FILE_TOO_LARGE;
    }
    
    /* Create file header */
    sd_crypto_header header;
    memset(&header, 0, sizeof(header));
    
    memcpy(header.magic, SD_CRYPTO_MAGIC, 8);
    header.version = SD_CRYPTO_VERSION;
    header.algorithm = SD_CRYPTO_ALG_AES256_CTR_HMAC_SHA256;
    header.original_size = input_size;
    header.encrypted_size = input_size;
    
    /* Generate random salt and IV */
    if (platform_rng_get_bytes(header.salt, SD_CRYPTO_SALT_SIZE) != PLATFORM_SUCCESS ||
        platform_rng_get_bytes(header.iv, SD_CRYPTO_IV_SIZE) != PLATFORM_SUCCESS) {
        return SD_CRYPTO_ERROR_CRYPTO_INIT;
    }
    
    /* Derive file-specific keys */
    uint8_t enc_key[32], auth_key[32];
    sd_crypto_derive_keys(ctx->master_key, header.salt, enc_key, auth_key);
    
    /* Initialize AES for encryption */
    arm_aes_init(&ctx->aes_ctx, enc_key, 256);
    
    /* Allocate I/O buffers */
    uint8_t* input_buffer = malloc(SD_CRYPTO_BUFFER_SIZE);
    uint8_t* output_buffer = malloc(SD_CRYPTO_BUFFER_SIZE);
    uint8_t* all_encrypted_data = malloc(input_size);
    
    if (!input_buffer || !output_buffer || !all_encrypted_data) {
        free(input_buffer);
        free(output_buffer);
        free(all_encrypted_data);
        arm_aes_clear(&ctx->aes_ctx);
        arm_secure_zero(enc_key, sizeof(enc_key));
        arm_secure_zero(auth_key, sizeof(auth_key));
        return SD_CRYPTO_ERROR_MEMORY_ERROR;
    }
    
    /* Read entire input file */
    if (platform_file_read(input_file, all_encrypted_data, input_size) != PLATFORM_SUCCESS) {
        free(input_buffer);
        free(output_buffer);
        free(all_encrypted_data);
        arm_aes_clear(&ctx->aes_ctx);
        arm_secure_zero(enc_key, sizeof(enc_key));
        arm_secure_zero(auth_key, sizeof(auth_key));
        return SD_CRYPTO_ERROR_IO_ERROR;
    }
    
    /* Encrypt data in-place */
    uint8_t counter[16];
    memcpy(counter, header.iv, 16);
    
    size_t bytes_processed = 0;
    size_t remaining = input_size;
    
    while (remaining > 0) {
        size_t chunk_size = (remaining < SD_CRYPTO_BUFFER_SIZE) ? remaining : SD_CRYPTO_BUFFER_SIZE;
        
        /* Encrypt chunk */
        arm_aes_ctr_crypt(&ctx->aes_ctx, counter, 
                         &all_encrypted_data[bytes_processed],
                         &all_encrypted_data[bytes_processed], 
                         chunk_size);
        
        bytes_processed += chunk_size;
        remaining -= chunk_size;
        
        /* Update progress */
        if (progress_cb) {
            progress_cb(bytes_processed, input_size, user_data);
        }
    }
    
    /* Calculate MAC over header and encrypted data */
    uint8_t mac[32];
    sd_crypto_calculate_mac(auth_key, &header, all_encrypted_data, input_size, mac);
    
    /* Write output file */
    uint8_t* output_data = malloc(SD_CRYPTO_HEADER_SIZE + input_size + SD_CRYPTO_MAC_SIZE);
    if (!output_data) {
        free(input_buffer);
        free(output_buffer);
        free(all_encrypted_data);
        arm_aes_clear(&ctx->aes_ctx);
        arm_secure_zero(enc_key, sizeof(enc_key));
        arm_secure_zero(auth_key, sizeof(auth_key));
        return SD_CRYPTO_ERROR_MEMORY_ERROR;
    }
    
    /* Assemble output file: header + encrypted_data + mac */
    memcpy(output_data, &header, SD_CRYPTO_HEADER_SIZE);
    memcpy(output_data + SD_CRYPTO_HEADER_SIZE, all_encrypted_data, input_size);
    memcpy(output_data + SD_CRYPTO_HEADER_SIZE + input_size, mac, SD_CRYPTO_MAC_SIZE);
    
    platform_result_t write_result = platform_file_write(output_file, output_data, 
                                                         SD_CRYPTO_HEADER_SIZE + input_size + SD_CRYPTO_MAC_SIZE);
    
    /* Cleanup */
    free(input_buffer);
    free(output_buffer);
    free(all_encrypted_data);
    free(output_data);
    arm_aes_clear(&ctx->aes_ctx);
    arm_secure_zero(enc_key, sizeof(enc_key));
    arm_secure_zero(auth_key, sizeof(auth_key));
    
    return (write_result == PLATFORM_SUCCESS) ? SD_CRYPTO_SUCCESS : SD_CRYPTO_ERROR_IO_ERROR;
}

/*
 * Decrypt file from SD card
 */
sd_crypto_result_t sd_crypto_decrypt_file(sd_crypto_ctx* ctx,
                                         const char* input_file,
                                         const char* output_file,
                                         sd_crypto_progress_cb progress_cb,
                                         void* user_data)
{
    if (!ctx || !ctx->initialized || !input_file || !output_file) {
        return SD_CRYPTO_ERROR_INVALID_PARAM;
    }
    
    /* Read and validate header */
    sd_crypto_header header;
    sd_crypto_result_t result = sd_crypto_read_header(input_file, &header);
    if (result != SD_CRYPTO_SUCCESS) {
        return result;
    }
    
    /* Get file size */
    size_t file_size;
    if (platform_file_get_size(input_file, &file_size) != PLATFORM_SUCCESS) {
        return SD_CRYPTO_ERROR_IO_ERROR;
    }
    
    size_t expected_size = SD_CRYPTO_HEADER_SIZE + header.encrypted_size + SD_CRYPTO_MAC_SIZE;
    if (file_size != expected_size) {
        return SD_CRYPTO_ERROR_INVALID_FORMAT;
    }
    
    /* Read entire encrypted file */
    uint8_t* file_data = malloc(file_size);
    if (!file_data) {
        return SD_CRYPTO_ERROR_MEMORY_ERROR;
    }
    
    if (platform_file_read(input_file, file_data, file_size) != PLATFORM_SUCCESS) {
        free(file_data);
        return SD_CRYPTO_ERROR_IO_ERROR;
    }
    
    /* Extract components */
    uint8_t* encrypted_data = file_data + SD_CRYPTO_HEADER_SIZE;
    uint8_t* stored_mac = file_data + SD_CRYPTO_HEADER_SIZE + header.encrypted_size;
    
    /* Derive keys */
    uint8_t enc_key[32], auth_key[32];
    sd_crypto_derive_keys(ctx->master_key, header.salt, enc_key, auth_key);
    
    /* Verify MAC */
    uint8_t calculated_mac[32];
    sd_crypto_calculate_mac(auth_key, &header, encrypted_data, header.encrypted_size, calculated_mac);
    
    if (arm_ct_memcmp(stored_mac, calculated_mac, 32) != 0) {
        free(file_data);
        arm_secure_zero(enc_key, sizeof(enc_key));
        arm_secure_zero(auth_key, sizeof(auth_key));
        return SD_CRYPTO_ERROR_AUTHENTICATION_FAILED;
    }
    
    /* Initialize AES for decryption */
    arm_aes_init(&ctx->aes_ctx, enc_key, 256);
    
    /* Decrypt data */
    uint8_t counter[16];
    memcpy(counter, header.iv, 16);
    
    size_t bytes_processed = 0;
    size_t remaining = header.encrypted_size;
    
    while (remaining > 0) {
        size_t chunk_size = (remaining < SD_CRYPTO_BUFFER_SIZE) ? remaining : SD_CRYPTO_BUFFER_SIZE;
        
        /* Decrypt chunk in-place */
        arm_aes_ctr_crypt(&ctx->aes_ctx, counter,
                         &encrypted_data[bytes_processed],
                         &encrypted_data[bytes_processed],
                         chunk_size);
        
        bytes_processed += chunk_size;
        remaining -= chunk_size;
        
        /* Update progress */
        if (progress_cb) {
            progress_cb(bytes_processed, header.encrypted_size, user_data);
        }
    }
    
    /* Write decrypted data to output file */
    platform_result_t write_result = platform_file_write(output_file, encrypted_data, header.original_size);
    
    /* Cleanup */
    free(file_data);
    arm_aes_clear(&ctx->aes_ctx);
    arm_secure_zero(enc_key, sizeof(enc_key));
    arm_secure_zero(auth_key, sizeof(auth_key));
    
    return (write_result == PLATFORM_SUCCESS) ? SD_CRYPTO_SUCCESS : SD_CRYPTO_ERROR_IO_ERROR;
}

/*
 * Verify encrypted file integrity
 */
sd_crypto_result_t sd_crypto_verify_file(sd_crypto_ctx* ctx, const char* encrypted_file)
{
    if (!ctx || !ctx->initialized || !encrypted_file) {
        return SD_CRYPTO_ERROR_INVALID_PARAM;
    }
    
    /* Read and validate header */
    sd_crypto_header header;
    sd_crypto_result_t result = sd_crypto_read_header(encrypted_file, &header);
    if (result != SD_CRYPTO_SUCCESS) {
        return result;
    }
    
    /* Get file size */
    size_t file_size;
    if (platform_file_get_size(encrypted_file, &file_size) != PLATFORM_SUCCESS) {
        return SD_CRYPTO_ERROR_IO_ERROR;
    }
    
    size_t expected_size = SD_CRYPTO_HEADER_SIZE + header.encrypted_size + SD_CRYPTO_MAC_SIZE;
    if (file_size != expected_size) {
        return SD_CRYPTO_ERROR_INVALID_FORMAT;
    }
    
    /* Read encrypted data and MAC */
    size_t data_and_mac_size = header.encrypted_size + SD_CRYPTO_MAC_SIZE;
    uint8_t* data_and_mac = malloc(data_and_mac_size);
    if (!data_and_mac) {
        return SD_CRYPTO_ERROR_MEMORY_ERROR;
    }
    
    /* Read from file starting after header */
    FILE* fp = fopen(encrypted_file, "rb");
    if (!fp) {
        free(data_and_mac);
        return SD_CRYPTO_ERROR_IO_ERROR;
    }
    
    fseek(fp, SD_CRYPTO_HEADER_SIZE, SEEK_SET);
    size_t read_bytes = fread(data_and_mac, 1, data_and_mac_size, fp);
    fclose(fp);
    
    if (read_bytes != data_and_mac_size) {
        free(data_and_mac);
        return SD_CRYPTO_ERROR_IO_ERROR;
    }
    
    /* Extract components */
    uint8_t* encrypted_data = data_and_mac;
    uint8_t* stored_mac = data_and_mac + header.encrypted_size;
    
    /* Derive authentication key */
    uint8_t enc_key[32], auth_key[32];
    sd_crypto_derive_keys(ctx->master_key, header.salt, enc_key, auth_key);
    
    /* Calculate and verify MAC */
    uint8_t calculated_mac[32];
    sd_crypto_calculate_mac(auth_key, &header, encrypted_data, header.encrypted_size, calculated_mac);
    
    int mac_valid = (arm_ct_memcmp(stored_mac, calculated_mac, 32) == 0);
    
    /* Cleanup */
    free(data_and_mac);
    arm_secure_zero(enc_key, sizeof(enc_key));
    arm_secure_zero(auth_key, sizeof(auth_key));
    
    return mac_valid ? SD_CRYPTO_SUCCESS : SD_CRYPTO_ERROR_AUTHENTICATION_FAILED;
}

/*
 * Get error string for result code
 */
const char* sd_crypto_get_error_string(sd_crypto_result_t result)
{
    switch (result) {
        case SD_CRYPTO_SUCCESS:
            return "Success";
        case SD_CRYPTO_ERROR_INVALID_PARAM:
            return "Invalid parameter";
        case SD_CRYPTO_ERROR_FILE_NOT_FOUND:
            return "File not found";
        case SD_CRYPTO_ERROR_FILE_TOO_LARGE:
            return "File too large";
        case SD_CRYPTO_ERROR_INVALID_FORMAT:
            return "Invalid file format";
        case SD_CRYPTO_ERROR_AUTHENTICATION_FAILED:
            return "Authentication failed - file may be corrupted or tampered";
        case SD_CRYPTO_ERROR_IO_ERROR:
            return "I/O error";
        case SD_CRYPTO_ERROR_MEMORY_ERROR:
            return "Memory allocation error";
        case SD_CRYPTO_ERROR_CRYPTO_INIT:
            return "Cryptographic initialization error";
        default:
            return "Unknown error";
    }
}
