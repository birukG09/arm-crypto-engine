/*
 * SHA-256 (Secure Hash Algorithm 256) Interface
 * ArmAsm-CryptoEngine - ARM Assembly Cryptography Library
 * 
 * Constant-time SHA-256 implementation with streaming API and HMAC support
 */

#ifndef ARMCRYPTO_SHA256_H
#define ARMCRYPTO_SHA256_H

#include <stdint.h>
#include <stddef.h>
#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* SHA-256 digest size */
#define SHA256_DIGEST_SIZE 32
#define SHA256_BLOCK_SIZE 64

/* SHA-256 context structure */
typedef struct {
    uint32_t state[8];           /* Hash state */
    uint64_t count;              /* Total bits processed */
    uint8_t buffer[SHA256_BLOCK_SIZE];  /* Input buffer */
    uint8_t buffer_len;          /* Bytes in buffer */
    uint8_t reserved[3];         /* Padding for alignment */
} arm_sha256_ctx;

/*
 * Initialize SHA-256 context
 * 
 * @param ctx SHA-256 context to initialize
 */
void arm_sha256_init(arm_sha256_ctx* ctx);

/*
 * Update SHA-256 hash with data
 * 
 * @param ctx  SHA-256 context
 * @param data Input data
 * @param len  Data length in bytes
 */
void arm_sha256_update(arm_sha256_ctx* ctx, const uint8_t* data, size_t len);

/*
 * Finalize SHA-256 hash and get digest
 * 
 * @param ctx SHA-256 context
 * @param out Output digest (32 bytes)
 */
void arm_sha256_final(arm_sha256_ctx* ctx, uint8_t out[32]);

/*
 * Clear SHA-256 context and zeroize sensitive data
 * 
 * @param ctx SHA-256 context to clear
 */
void arm_sha256_clear(arm_sha256_ctx* ctx);

/*
 * One-shot SHA-256 hash computation
 * 
 * @param data Input data
 * @param len  Data length
 * @param out  Output digest (32 bytes)
 */
void arm_sha256_hash(const uint8_t* data, size_t len, uint8_t out[32]);

/*
 * HMAC-SHA256 computation
 * 
 * @param key     HMAC key
 * @param key_len Key length
 * @param msg     Message to authenticate
 * @param msg_len Message length
 * @param out     Output MAC (32 bytes)
 */
void arm_hmac_sha256(const uint8_t* key, size_t key_len,
                    const uint8_t* msg, size_t msg_len,
                    uint8_t out[32]);

/*
 * HMAC-SHA256 with streaming interface
 */
typedef struct {
    arm_sha256_ctx inner_ctx;
    arm_sha256_ctx outer_ctx;
    uint8_t key_pad[SHA256_BLOCK_SIZE];
} arm_hmac_sha256_ctx;

/*
 * Initialize HMAC-SHA256 context
 * 
 * @param ctx     HMAC context to initialize
 * @param key     HMAC key
 * @param key_len Key length
 */
void arm_hmac_sha256_init(arm_hmac_sha256_ctx* ctx, const uint8_t* key, size_t key_len);

/*
 * Update HMAC-SHA256 with data
 * 
 * @param ctx  HMAC context
 * @param data Input data
 * @param len  Data length
 */
void arm_hmac_sha256_update(arm_hmac_sha256_ctx* ctx, const uint8_t* data, size_t len);

/*
 * Finalize HMAC-SHA256 and get MAC
 * 
 * @param ctx HMAC context
 * @param out Output MAC (32 bytes)
 */
void arm_hmac_sha256_final(arm_hmac_sha256_ctx* ctx, uint8_t out[32]);

/*
 * Clear HMAC-SHA256 context
 * 
 * @param ctx HMAC context to clear
 */
void arm_hmac_sha256_clear(arm_hmac_sha256_ctx* ctx);

/*
 * Internal functions (implemented in assembly)
 * These are exposed for testing but should not be used directly
 */

/* SHA-256 compression function (single block) */
void arm_sha256_compress(uint32_t state[8], const uint8_t block[64]);

#ifdef __cplusplus
}
#endif

#endif /* ARMCRYPTO_SHA256_H */
