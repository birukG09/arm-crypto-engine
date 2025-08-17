/*
 * SHA-256 C Implementation Wrapper
 * ArmAsm-CryptoEngine - C API for ARM Assembly SHA-256 Implementation
 * 
 * Provides high-level C interface to hand-written ARM assembly SHA-256 functions
 */

#include "armcrypto/sha256.h"
#include "armcrypto/ct.h"
#include "armcrypto/types.h"
#include <string.h>

/* External assembly functions */
extern void arm_sha256_compress(uint32_t state[8], const uint8_t block[64]);

#ifdef ARM_CORTEX_A53
/* NEON-optimized function for Cortex-A53 */
extern void arm_sha256_compress_neon(uint32_t state[8], const uint8_t block[64]);
#endif

/* SHA-256 initial hash values (first 32 bits of fractional parts of square roots of first 8 primes) */
static const uint32_t sha256_initial_state[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

/*
 * Initialize SHA-256 context
 */
void arm_sha256_init(arm_sha256_ctx* ctx)
{
    if (!ctx) {
        return;
    }
    
    /* Initialize state with SHA-256 initial values */
    memcpy(ctx->state, sha256_initial_state, sizeof(sha256_initial_state));
    
    /* Initialize counters */
    ctx->count = 0;
    ctx->buffer_len = 0;
    
    /* Clear buffer */
    memset(ctx->buffer, 0, sizeof(ctx->buffer));
}

/*
 * Update SHA-256 hash with data
 */
void arm_sha256_update(arm_sha256_ctx* ctx, const uint8_t* data, size_t len)
{
    if (!ctx || !data || len == 0) {
        return;
    }
    
    const uint8_t* input = data;
    size_t remaining = len;
    
    /* Update bit count */
    ctx->count += len * 8;
    
    /* Process any data remaining in buffer from previous update */
    if (ctx->buffer_len > 0) {
        size_t space_in_buffer = SHA256_BLOCK_SIZE - ctx->buffer_len;
        size_t to_copy = (remaining < space_in_buffer) ? remaining : space_in_buffer;
        
        memcpy(&ctx->buffer[ctx->buffer_len], input, to_copy);
        ctx->buffer_len += to_copy;
        input += to_copy;
        remaining -= to_copy;
        
        /* Process full buffer if we have a complete block */
        if (ctx->buffer_len == SHA256_BLOCK_SIZE) {
#ifdef ARM_CORTEX_A53
            arm_sha256_compress_neon(ctx->state, ctx->buffer);
#else
            arm_sha256_compress(ctx->state, ctx->buffer);
#endif
            ctx->buffer_len = 0;
        }
    }
    
    /* Process complete blocks directly from input */
    while (remaining >= SHA256_BLOCK_SIZE) {
#ifdef ARM_CORTEX_A53
        arm_sha256_compress_neon(ctx->state, input);
#else
        arm_sha256_compress(ctx->state, input);
#endif
        input += SHA256_BLOCK_SIZE;
        remaining -= SHA256_BLOCK_SIZE;
    }
    
    /* Store remaining data in buffer */
    if (remaining > 0) {
        memcpy(&ctx->buffer[ctx->buffer_len], input, remaining);
        ctx->buffer_len += remaining;
    }
}

/*
 * Finalize SHA-256 hash and get digest
 */
void arm_sha256_final(arm_sha256_ctx* ctx, uint8_t out[32])
{
    if (!ctx || !out) {
        return;
    }
    
    /* Save bit count before padding */
    uint64_t bit_count = ctx->count;
    
    /* Add padding: single '1' bit followed by zeros */
    uint8_t padding[SHA256_BLOCK_SIZE * 2]; /* Maximum padding needed */
    size_t padding_len = 0;
    
    /* First padding byte has bit 7 set */
    padding[0] = 0x80;
    padding_len = 1;
    
    /* Calculate total length after adding 1 bit */
    size_t total_len = ctx->buffer_len + 1;
    
    /* Pad to 448 bits (56 bytes) mod 512 bits (64 bytes) */
    /* This leaves 64 bits (8 bytes) for the length field */
    size_t target_len = (total_len <= 56) ? 56 : (64 + 56);
    padding_len = target_len - ctx->buffer_len;
    
    /* Fill remaining padding with zeros */
    for (size_t i = 1; i < padding_len; i++) {
        padding[i] = 0x00;
    }
    
    /* Append bit count as 64-bit big-endian integer */
    padding[padding_len++] = (bit_count >> 56) & 0xFF;
    padding[padding_len++] = (bit_count >> 48) & 0xFF;
    padding[padding_len++] = (bit_count >> 40) & 0xFF;
    padding[padding_len++] = (bit_count >> 32) & 0xFF;
    padding[padding_len++] = (bit_count >> 24) & 0xFF;
    padding[padding_len++] = (bit_count >> 16) & 0xFF;
    padding[padding_len++] = (bit_count >> 8) & 0xFF;
    padding[padding_len++] = bit_count & 0xFF;
    
    /* Process the padding */
    arm_sha256_update(ctx, padding, padding_len);
    
    /* Convert final state to big-endian output */
    for (int i = 0; i < 8; i++) {
        uint32_t word = ctx->state[i];
        out[i * 4 + 0] = (word >> 24) & 0xFF;
        out[i * 4 + 1] = (word >> 16) & 0xFF;
        out[i * 4 + 2] = (word >> 8) & 0xFF;
        out[i * 4 + 3] = word & 0xFF;
    }
    
    /* Clear sensitive data */
    arm_secure_zero(padding, sizeof(padding));
}

/*
 * Clear SHA-256 context and zeroize sensitive data
 */
void arm_sha256_clear(arm_sha256_ctx* ctx)
{
    if (!ctx) {
        return;
    }
    
    arm_secure_zero(ctx, sizeof(arm_sha256_ctx));
}

/*
 * One-shot SHA-256 hash computation
 */
void arm_sha256_hash(const uint8_t* data, size_t len, uint8_t out[32])
{
    arm_sha256_ctx ctx;
    
    arm_sha256_init(&ctx);
    arm_sha256_update(&ctx, data, len);
    arm_sha256_final(&ctx, out);
    arm_sha256_clear(&ctx);
}

/*
 * HMAC-SHA256 computation
 */
void arm_hmac_sha256(const uint8_t* key, size_t key_len,
                    const uint8_t* msg, size_t msg_len,
                    uint8_t out[32])
{
    arm_hmac_sha256_ctx ctx;
    
    arm_hmac_sha256_init(&ctx, key, key_len);
    arm_hmac_sha256_update(&ctx, msg, msg_len);
    arm_hmac_sha256_final(&ctx, out);
    arm_hmac_sha256_clear(&ctx);
}

/*
 * Initialize HMAC-SHA256 context
 */
void arm_hmac_sha256_init(arm_hmac_sha256_ctx* ctx, const uint8_t* key, size_t key_len)
{
    if (!ctx || !key) {
        return;
    }
    
    uint8_t actual_key[SHA256_DIGEST_SIZE];
    const uint8_t* key_ptr;
    size_t actual_key_len;
    
    /* If key is longer than block size, hash it first */
    if (key_len > SHA256_BLOCK_SIZE) {
        arm_sha256_hash(key, key_len, actual_key);
        key_ptr = actual_key;
        actual_key_len = SHA256_DIGEST_SIZE;
    } else {
        key_ptr = key;
        actual_key_len = key_len;
    }
    
    /* Prepare inner and outer key pads */
    memset(ctx->key_pad, 0, SHA256_BLOCK_SIZE);
    memcpy(ctx->key_pad, key_ptr, actual_key_len);
    
    /* Create inner key pad (key XOR ipad) */
    uint8_t inner_pad[SHA256_BLOCK_SIZE];
    for (size_t i = 0; i < SHA256_BLOCK_SIZE; i++) {
        inner_pad[i] = ctx->key_pad[i] ^ 0x36;
    }
    
    /* Create outer key pad (key XOR opad) */
    uint8_t outer_pad[SHA256_BLOCK_SIZE];
    for (size_t i = 0; i < SHA256_BLOCK_SIZE; i++) {
        outer_pad[i] = ctx->key_pad[i] ^ 0x5C;
    }
    
    /* Initialize inner hash with inner pad */
    arm_sha256_init(&ctx->inner_ctx);
    arm_sha256_update(&ctx->inner_ctx, inner_pad, SHA256_BLOCK_SIZE);
    
    /* Initialize outer hash with outer pad */
    arm_sha256_init(&ctx->outer_ctx);
    arm_sha256_update(&ctx->outer_ctx, outer_pad, SHA256_BLOCK_SIZE);
    
    /* Clear temporary data */
    arm_secure_zero(actual_key, sizeof(actual_key));
    arm_secure_zero(inner_pad, sizeof(inner_pad));
    arm_secure_zero(outer_pad, sizeof(outer_pad));
}

/*
 * Update HMAC-SHA256 with data
 */
void arm_hmac_sha256_update(arm_hmac_sha256_ctx* ctx, const uint8_t* data, size_t len)
{
    if (!ctx || !data || len == 0) {
        return;
    }
    
    /* Add data to inner hash */
    arm_sha256_update(&ctx->inner_ctx, data, len);
}

/*
 * Finalize HMAC-SHA256 and get MAC
 */
void arm_hmac_sha256_final(arm_hmac_sha256_ctx* ctx, uint8_t out[32])
{
    if (!ctx || !out) {
        return;
    }
    
    uint8_t inner_hash[SHA256_DIGEST_SIZE];
    
    /* Finalize inner hash */
    arm_sha256_final(&ctx->inner_ctx, inner_hash);
    
    /* Add inner hash to outer hash */
    arm_sha256_update(&ctx->outer_ctx, inner_hash, SHA256_DIGEST_SIZE);
    
    /* Finalize outer hash to get HMAC */
    arm_sha256_final(&ctx->outer_ctx, out);
    
    /* Clear sensitive data */
    arm_secure_zero(inner_hash, sizeof(inner_hash));
}

/*
 * Clear HMAC-SHA256 context
 */
void arm_hmac_sha256_clear(arm_hmac_sha256_ctx* ctx)
{
    if (!ctx) {
        return;
    }
    
    arm_secure_zero(ctx, sizeof(arm_hmac_sha256_ctx));
}

/*
 * Internal compression function (exposed for testing)
 */
void arm_sha256_compress(uint32_t state[8], const uint8_t block[64])
{
    if (!state || !block) {
        return;
    }
    
#ifdef ARM_CORTEX_A53
    arm_sha256_compress_neon(state, block);
#else
    /* Call Cortex-M4 assembly implementation */
    extern void arm_sha256_compress(uint32_t state[8], const uint8_t block[64]);
#endif
}
