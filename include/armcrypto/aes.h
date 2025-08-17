/*
 * AES (Advanced Encryption Standard) Interface
 * ArmAsm-CryptoEngine - ARM Assembly Cryptography Library
 * 
 * Supports AES-128, AES-192, and AES-256 with ECB, CBC, and CTR modes
 * Constant-time implementation to prevent side-channel attacks
 */

#ifndef ARMCRYPTO_AES_H
#define ARMCRYPTO_AES_H

#include <stdint.h>
#include <stddef.h>
#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* AES block size is always 16 bytes */
#define AES_BLOCK_SIZE 16

/* AES key sizes */
#define AES_KEY_SIZE_128 16
#define AES_KEY_SIZE_192 24
#define AES_KEY_SIZE_256 32

/* Maximum number of round keys (for AES-256) */
#define AES_MAX_ROUND_KEYS 15

/* AES context structure */
typedef struct {
    uint32_t round_keys[AES_MAX_ROUND_KEYS * 4];  /* Round keys */
    uint8_t nr;                                   /* Number of rounds */
    uint8_t key_size;                            /* Key size in bytes */
    uint8_t reserved[2];                         /* Padding for alignment */
} arm_aes_ctx;

/*
 * Initialize AES context with key
 * 
 * @param ctx     AES context to initialize
 * @param key     Encryption key
 * @param keybits Key size in bits (128, 192, or 256)
 */
void arm_aes_init(arm_aes_ctx* ctx, const uint8_t* key, size_t keybits);

/*
 * Clear AES context and zeroize sensitive data
 * 
 * @param ctx AES context to clear
 */
void arm_aes_clear(arm_aes_ctx* ctx);

/*
 * AES ECB mode encryption (single block)
 * 
 * @param ctx AES context
 * @param in  Input plaintext (16 bytes)
 * @param out Output ciphertext (16 bytes)
 */
void arm_aes_ecb_encrypt(const arm_aes_ctx* ctx, const uint8_t in[16], uint8_t out[16]);

/*
 * AES ECB mode decryption (single block)
 * 
 * @param ctx AES context
 * @param in  Input ciphertext (16 bytes)
 * @param out Output plaintext (16 bytes)
 */
void arm_aes_ecb_decrypt(const arm_aes_ctx* ctx, const uint8_t in[16], uint8_t out[16]);

/*
 * AES CBC mode encryption
 * 
 * @param ctx AES context
 * @param iv  Initialization vector (16 bytes, modified in-place)
 * @param in  Input plaintext
 * @param out Output ciphertext
 * @param len Data length (must be multiple of 16)
 */
void arm_aes_cbc_encrypt(const arm_aes_ctx* ctx, uint8_t* iv, 
                        const uint8_t* in, uint8_t* out, size_t len);

/*
 * AES CBC mode decryption
 * 
 * @param ctx AES context
 * @param iv  Initialization vector (16 bytes, modified in-place)
 * @param in  Input ciphertext
 * @param out Output plaintext
 * @param len Data length (must be multiple of 16)
 */
void arm_aes_cbc_decrypt(const arm_aes_ctx* ctx, uint8_t* iv,
                        const uint8_t* in, uint8_t* out, size_t len);

/*
 * AES CTR mode encryption/decryption
 * 
 * @param ctx   AES context
 * @param nonce Counter/nonce (16 bytes, modified in-place)
 * @param in    Input data
 * @param out   Output data
 * @param len   Data length (any length)
 */
void arm_aes_ctr_crypt(const arm_aes_ctx* ctx, uint8_t* nonce,
                      const uint8_t* in, uint8_t* out, size_t len);

/*
 * Internal functions (implemented in assembly)
 * These are exposed for testing but should not be used directly
 */

/* AES key schedule (expansion) */
void arm_aes_key_schedule(const uint8_t* key, uint32_t* round_keys, uint8_t keybits);

/* AES encrypt single block */
void arm_aes_encrypt_block(const uint32_t* round_keys, uint8_t nr, 
                          const uint8_t in[16], uint8_t out[16]);

/* AES decrypt single block */
void arm_aes_decrypt_block(const uint32_t* round_keys, uint8_t nr,
                          const uint8_t in[16], uint8_t out[16]);

#ifdef __cplusplus
}
#endif

#endif /* ARMCRYPTO_AES_H */
