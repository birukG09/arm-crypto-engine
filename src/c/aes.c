/*
 * AES C Implementation Wrapper
 * ArmAsm-CryptoEngine - C API for ARM Assembly AES Implementation
 * 
 * Provides high-level C interface to hand-written ARM assembly AES functions
 */

#include "armcrypto/aes.h"
#include "armcrypto/ct.h"
#include "armcrypto/types.h"
#include <string.h>

/* External assembly functions */
extern void arm_aes_key_schedule(const uint8_t* key, uint32_t* round_keys, uint8_t keybits);
extern void arm_aes_encrypt_block(const uint32_t* round_keys, uint8_t nr, 
                                 const uint8_t in[16], uint8_t out[16]);
extern void arm_aes_decrypt_block(const uint32_t* round_keys, uint8_t nr,
                                 const uint8_t in[16], uint8_t out[16]);

#ifdef ARM_CORTEX_A53
/* NEON-optimized functions for Cortex-A53 */
extern void arm_aes_encrypt_block_neon(const uint32_t* round_keys, uint8_t nr,
                                      const uint8_t in[16], uint8_t out[16]);
extern void arm_aes_decrypt_block_neon(const uint32_t* round_keys, uint8_t nr,
                                      const uint8_t in[16], uint8_t out[16]);
extern void arm_aes_key_schedule_neon(const uint8_t* key, uint32_t* round_keys, uint8_t keybits);
#endif

/*
 * Initialize AES context with key
 */
void arm_aes_init(arm_aes_ctx* ctx, const uint8_t* key, size_t keybits)
{
    if (!ctx || !key) {
        return;
    }
    
    /* Validate key size */
    if (keybits != 128 && keybits != 192 && keybits != 256) {
        return;
    }
    
    /* Set context parameters */
    ctx->key_size = keybits / 8;
    
    /* Determine number of rounds */
    switch (keybits) {
        case 128: ctx->nr = 10; break;
        case 192: ctx->nr = 12; break;
        case 256: ctx->nr = 14; break;
        default: return;
    }
    
    /* Generate round keys using assembly implementation */
#ifdef ARM_CORTEX_A53
    arm_aes_key_schedule_neon(key, ctx->round_keys, keybits);
#else
    arm_aes_key_schedule(key, ctx->round_keys, keybits);
#endif
}

/*
 * Clear AES context and zeroize sensitive data
 */
void arm_aes_clear(arm_aes_ctx* ctx)
{
    if (!ctx) {
        return;
    }
    
    /* Securely zero all key material */
    arm_secure_zero(ctx->round_keys, sizeof(ctx->round_keys));
    ctx->nr = 0;
    ctx->key_size = 0;
}

/*
 * AES ECB mode encryption (single block)
 */
void arm_aes_ecb_encrypt(const arm_aes_ctx* ctx, const uint8_t in[16], uint8_t out[16])
{
    if (!ctx || !in || !out) {
        return;
    }
    
#ifdef ARM_CORTEX_A53
    arm_aes_encrypt_block_neon(ctx->round_keys, ctx->nr, in, out);
#else
    arm_aes_encrypt_block(ctx->round_keys, ctx->nr, in, out);
#endif
}

/*
 * AES ECB mode decryption (single block)
 */
void arm_aes_ecb_decrypt(const arm_aes_ctx* ctx, const uint8_t in[16], uint8_t out[16])
{
    if (!ctx || !in || !out) {
        return;
    }
    
#ifdef ARM_CORTEX_A53
    arm_aes_decrypt_block_neon(ctx->round_keys, ctx->nr, in, out);
#else
    arm_aes_decrypt_block(ctx->round_keys, ctx->nr, in, out);
#endif
}

/*
 * AES CBC mode encryption
 */
void arm_aes_cbc_encrypt(const arm_aes_ctx* ctx, uint8_t* iv, 
                        const uint8_t* in, uint8_t* out, size_t len)
{
    if (!ctx || !iv || !in || !out || len == 0 || (len % AES_BLOCK_SIZE) != 0) {
        return;
    }
    
    uint8_t temp_block[AES_BLOCK_SIZE];
    const uint8_t* current_iv = iv;
    
    for (size_t i = 0; i < len; i += AES_BLOCK_SIZE) {
        /* XOR plaintext with IV/previous ciphertext */
        arm_ct_memxor(temp_block, &in[i], current_iv, AES_BLOCK_SIZE);
        
        /* Encrypt XORed block */
        arm_aes_ecb_encrypt(ctx, temp_block, &out[i]);
        
        /* Current ciphertext becomes next IV */
        current_iv = &out[i];
    }
    
    /* Update IV with last ciphertext block */
    memcpy(iv, &out[len - AES_BLOCK_SIZE], AES_BLOCK_SIZE);
    
    /* Clear temporary data */
    arm_secure_zero(temp_block, sizeof(temp_block));
}

/*
 * AES CBC mode decryption
 */
void arm_aes_cbc_decrypt(const arm_aes_ctx* ctx, uint8_t* iv,
                        const uint8_t* in, uint8_t* out, size_t len)
{
    if (!ctx || !iv || !in || !out || len == 0 || (len % AES_BLOCK_SIZE) != 0) {
        return;
    }
    
    uint8_t temp_block[AES_BLOCK_SIZE];
    uint8_t next_iv[AES_BLOCK_SIZE];
    
    for (size_t i = 0; i < len; i += AES_BLOCK_SIZE) {
        /* Save current ciphertext as next IV */
        memcpy(next_iv, &in[i], AES_BLOCK_SIZE);
        
        /* Decrypt block */
        arm_aes_ecb_decrypt(ctx, &in[i], temp_block);
        
        /* XOR with IV/previous ciphertext */
        arm_ct_memxor(&out[i], temp_block, iv, AES_BLOCK_SIZE);
        
        /* Update IV */
        memcpy(iv, next_iv, AES_BLOCK_SIZE);
    }
    
    /* Clear temporary data */
    arm_secure_zero(temp_block, sizeof(temp_block));
    arm_secure_zero(next_iv, sizeof(next_iv));
}

/*
 * AES CTR mode encryption/decryption
 */
void arm_aes_ctr_crypt(const arm_aes_ctx* ctx, uint8_t* nonce,
                      const uint8_t* in, uint8_t* out, size_t len)
{
    if (!ctx || !nonce || !in || !out || len == 0) {
        return;
    }
    
    uint8_t counter_block[AES_BLOCK_SIZE];
    uint8_t keystream[AES_BLOCK_SIZE];
    size_t remaining = len;
    size_t offset = 0;
    
    /* Copy nonce to counter block */
    memcpy(counter_block, nonce, AES_BLOCK_SIZE);
    
    while (remaining > 0) {
        /* Encrypt counter to generate keystream */
        arm_aes_ecb_encrypt(ctx, counter_block, keystream);
        
        /* XOR with plaintext/ciphertext */
        size_t block_size = (remaining < AES_BLOCK_SIZE) ? remaining : AES_BLOCK_SIZE;
        arm_ct_memxor(&out[offset], &in[offset], keystream, block_size);
        
        /* Increment counter (big-endian) */
        for (int i = AES_BLOCK_SIZE - 1; i >= 0; i--) {
            if (++counter_block[i] != 0) {
                break; /* No carry needed */
            }
        }
        
        offset += block_size;
        remaining -= block_size;
    }
    
    /* Update nonce with final counter value */
    memcpy(nonce, counter_block, AES_BLOCK_SIZE);
    
    /* Clear sensitive data */
    arm_secure_zero(counter_block, sizeof(counter_block));
    arm_secure_zero(keystream, sizeof(keystream));
}

/*
 * Internal key schedule function (exposed for testing)
 */
void arm_aes_key_schedule(const uint8_t* key, uint32_t* round_keys, uint8_t keybits)
{
    /* This function is implemented in assembly */
    /* The C wrapper just validates parameters and calls assembly */
    if (!key || !round_keys) {
        return;
    }
    
    if (keybits != 128 && keybits != 192 && keybits != 256) {
        return;
    }
    
    /* Call platform-specific assembly implementation */
#ifdef ARM_CORTEX_A53
    arm_aes_key_schedule_neon(key, round_keys, keybits);
#else
    /* Cortex-M4 or fallback implementation */
    extern void arm_aes_key_schedule(const uint8_t* key, uint32_t* round_keys, uint8_t keybits);
#endif
}

/*
 * Internal block encrypt function (exposed for testing)
 */
void arm_aes_encrypt_block(const uint32_t* round_keys, uint8_t nr, 
                          const uint8_t in[16], uint8_t out[16])
{
    if (!round_keys || !in || !out || nr < 10 || nr > 14) {
        return;
    }
    
#ifdef ARM_CORTEX_A53
    arm_aes_encrypt_block_neon(round_keys, nr, in, out);
#else
    /* Call Cortex-M4 assembly implementation */
    extern void arm_aes_encrypt_block(const uint32_t* round_keys, uint8_t nr, 
                                     const uint8_t in[16], uint8_t out[16]);
#endif
}

/*
 * Internal block decrypt function (exposed for testing)
 */
void arm_aes_decrypt_block(const uint32_t* round_keys, uint8_t nr,
                          const uint8_t in[16], uint8_t out[16])
{
    if (!round_keys || !in || !out || nr < 10 || nr > 14) {
        return;
    }
    
#ifdef ARM_CORTEX_A53
    arm_aes_decrypt_block_neon(round_keys, nr, in, out);
#else
    /* Call Cortex-M4 assembly implementation */
    extern void arm_aes_decrypt_block(const uint32_t* round_keys, uint8_t nr,
                                     const uint8_t in[16], uint8_t out[16]);
#endif
}
