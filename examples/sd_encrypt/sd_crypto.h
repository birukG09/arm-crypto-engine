/*
 * SD Card Crypto Operations Header
 * ArmAsm-CryptoEngine - Secure file encryption for SD cards
 * 
 * Provides high-level encryption/decryption operations for files
 * using AES-256-CTR mode with HMAC-SHA256 authentication
 */

#ifndef SD_CRYPTO_H
#define SD_CRYPTO_H

#include <stdint.h>
#include <stddef.h>
#include "armcrypto/aes.h"
#include "armcrypto/sha256.h"

#ifdef __cplusplus
extern "C" {
#endif

/* File format constants */
#define SD_CRYPTO_MAGIC "ARMCRYPT"
#define SD_CRYPTO_VERSION 1
#define SD_CRYPTO_HEADER_SIZE 128
#define SD_CRYPTO_MAC_SIZE 32
#define SD_CRYPTO_SALT_SIZE 16
#define SD_CRYPTO_IV_SIZE 16

/* Error codes */
typedef enum {
    SD_CRYPTO_SUCCESS = 0,
    SD_CRYPTO_ERROR_INVALID_PARAM = -1,
    SD_CRYPTO_ERROR_FILE_NOT_FOUND = -2,
    SD_CRYPTO_ERROR_FILE_TOO_LARGE = -3,
    SD_CRYPTO_ERROR_INVALID_FORMAT = -4,
    SD_CRYPTO_ERROR_AUTHENTICATION_FAILED = -5,
    SD_CRYPTO_ERROR_IO_ERROR = -6,
    SD_CRYPTO_ERROR_MEMORY_ERROR = -7,
    SD_CRYPTO_ERROR_CRYPTO_INIT = -8
} sd_crypto_result_t;

/* Encrypted file header structure */
typedef struct {
    char magic[8];              /* "ARMCRYPT" magic bytes */
    uint32_t version;           /* File format version */
    uint32_t algorithm;         /* Encryption algorithm ID */
    uint64_t original_size;     /* Original file size */
    uint64_t encrypted_size;    /* Encrypted data size */
    uint8_t salt[SD_CRYPTO_SALT_SIZE];  /* Salt for key derivation */
    uint8_t iv[SD_CRYPTO_IV_SIZE];      /* Initial counter value */
    uint8_t reserved[64];       /* Reserved for future use */
} __attribute__((packed)) sd_crypto_header;

/* SD crypto context */
typedef struct {
    arm_aes_ctx aes_ctx;        /* AES context */
    uint8_t master_key[32];     /* Master encryption key */
    uint8_t auth_key[32];       /* Authentication key */
    int initialized;            /* Initialization flag */
} sd_crypto_ctx;

/* Progress callback function type */
typedef void (*sd_crypto_progress_cb)(size_t bytes_processed, size_t total_bytes, void* user_data);

/*
 * Initialize SD crypto context
 * 
 * @param ctx Crypto context to initialize
 * @param master_key 256-bit master key
 * @return SD_CRYPTO_SUCCESS on success, error code on failure
 */
sd_crypto_result_t sd_crypto_init(sd_crypto_ctx* ctx, const uint8_t master_key[32]);

/*
 * Cleanup SD crypto context
 * 
 * @param ctx Crypto context to cleanup
 */
void sd_crypto_cleanup(sd_crypto_ctx* ctx);

/*
 * Encrypt file to SD card
 * 
 * @param ctx Crypto context
 * @param input_file Path to input file
 * @param output_file Path to output encrypted file
 * @param progress_cb Progress callback (optional)
 * @param user_data User data for progress callback
 * @return SD_CRYPTO_SUCCESS on success, error code on failure
 */
sd_crypto_result_t sd_crypto_encrypt_file(sd_crypto_ctx* ctx,
                                         const char* input_file,
                                         const char* output_file,
                                         sd_crypto_progress_cb progress_cb,
                                         void* user_data);

/*
 * Decrypt file from SD card
 * 
 * @param ctx Crypto context
 * @param input_file Path to encrypted file
 * @param output_file Path to output decrypted file
 * @param progress_cb Progress callback (optional)
 * @param user_data User data for progress callback
 * @return SD_CRYPTO_SUCCESS on success, error code on failure
 */
sd_crypto_result_t sd_crypto_decrypt_file(sd_crypto_ctx* ctx,
                                         const char* input_file,
                                         const char* output_file,
                                         sd_crypto_progress_cb progress_cb,
                                         void* user_data);

/*
 * Verify encrypted file integrity
 * 
 * @param ctx Crypto context
 * @param encrypted_file Path to encrypted file
 * @return SD_CRYPTO_SUCCESS if valid, error code if invalid/corrupted
 */
sd_crypto_result_t sd_crypto_verify_file(sd_crypto_ctx* ctx, const char* encrypted_file);

/*
 * Read header from encrypted file
 * 
 * @param encrypted_file Path to encrypted file
 * @param header Output header structure
 * @return SD_CRYPTO_SUCCESS on success, error code on failure
 */
sd_crypto_result_t sd_crypto_read_header(const char* encrypted_file, sd_crypto_header* header);

/*
 * Get error string for result code
 * 
 * @param result Error code
 * @return Human-readable error string
 */
const char* sd_crypto_get_error_string(sd_crypto_result_t result);

/*
 * Derive file encryption keys from master key
 * 
 * @param master_key Master key (32 bytes)
 * @param salt Salt for key derivation (16 bytes)
 * @param enc_key Output encryption key (32 bytes)
 * @param auth_key Output authentication key (32 bytes)
 */
void sd_crypto_derive_keys(const uint8_t master_key[32], const uint8_t salt[16],
                          uint8_t enc_key[32], uint8_t auth_key[32]);

/*
 * Calculate file MAC
 * 
 * @param auth_key Authentication key (32 bytes)
 * @param header File header
 * @param encrypted_data Encrypted data
 * @param data_size Size of encrypted data
 * @param mac Output MAC (32 bytes)
 */
void sd_crypto_calculate_mac(const uint8_t auth_key[32],
                            const sd_crypto_header* header,
                            const uint8_t* encrypted_data,
                            size_t data_size,
                            uint8_t mac[32]);

#ifdef __cplusplus
}
#endif

#endif /* SD_CRYPTO_H */
