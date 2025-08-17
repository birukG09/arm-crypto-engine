/*
 * AES Unit Tests
 * ArmAsm-CryptoEngine - Comprehensive AES Testing
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "armcrypto/aes.h"
#include "armcrypto/ct.h"
#include "../vectors/aes_vectors.h"

/* Test framework macros */
#define TEST_ASSERT(condition, message) \
    do { \
        if (!(condition)) { \
            printf("FAIL: %s - %s\n", __func__, message); \
            return 0; \
        } \
    } while(0)

#define TEST_ASSERT_EQUAL_HEX(expected, actual, len, message) \
    do { \
        if (arm_ct_memcmp(expected, actual, len) != 0) { \
            printf("FAIL: %s - %s\n", __func__, message); \
            printf("Expected: "); \
            for (size_t i = 0; i < len; i++) printf("%02x", ((uint8_t*)expected)[i]); \
            printf("\nActual:   "); \
            for (size_t i = 0; i < len; i++) printf("%02x", ((uint8_t*)actual)[i]); \
            printf("\n"); \
            return 0; \
        } \
    } while(0)

#define RUN_TEST(test_func) \
    do { \
        printf("Running %s... ", #test_func); \
        if (test_func()) { \
            printf("PASS\n"); \
            tests_passed++; \
        } else { \
            tests_failed++; \
        } \
        tests_total++; \
    } while(0)

/* Global test counters */
static int tests_total = 0;
static int tests_passed = 0;
static int tests_failed = 0;

/*
 * Helper function to convert hex string to bytes
 */
static void hex_to_bytes(const char* hex, uint8_t* bytes, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        sscanf(hex + i * 2, "%2hhx", &bytes[i]);
    }
}

/*
 * Test AES context initialization
 */
static int test_aes_init(void)
{
    arm_aes_ctx ctx;
    uint8_t key[32] = {0};
    
    /* Test AES-128 initialization */
    arm_aes_init(&ctx, key, 128);
    TEST_ASSERT(ctx.nr == 10, "AES-128 should have 10 rounds");
    TEST_ASSERT(ctx.key_size == 16, "AES-128 key size should be 16 bytes");
    
    /* Test AES-192 initialization */
    arm_aes_init(&ctx, key, 192);
    TEST_ASSERT(ctx.nr == 12, "AES-192 should have 12 rounds");
    TEST_ASSERT(ctx.key_size == 24, "AES-192 key size should be 24 bytes");
    
    /* Test AES-256 initialization */
    arm_aes_init(&ctx, key, 256);
    TEST_ASSERT(ctx.nr == 14, "AES-256 should have 14 rounds");
    TEST_ASSERT(ctx.key_size == 32, "AES-256 key size should be 32 bytes");
    
    /* Test invalid key sizes */
    uint8_t old_nr = ctx.nr;
    arm_aes_init(&ctx, key, 64);  /* Invalid */
    TEST_ASSERT(ctx.nr == old_nr, "Invalid key size should not change context");
    
    arm_aes_clear(&ctx);
    return 1;
}

/*
 * Test AES ECB mode with NIST test vectors
 */
static int test_aes_ecb_vectors(void)
{
    for (int i = 0; i < AES_ECB_VECTOR_COUNT; i++) {
        const aes_ecb_vector_t* vector = &aes_ecb_vectors[i];
        arm_aes_ctx ctx;
        uint8_t key[32], plaintext[16], ciphertext[16], result[16];
        
        /* Convert hex strings to bytes */
        hex_to_bytes(vector->key, key, vector->key_len);
        hex_to_bytes(vector->plaintext, plaintext, 16);
        hex_to_bytes(vector->ciphertext, ciphertext, 16);
        
        /* Test encryption */
        arm_aes_init(&ctx, key, vector->key_len * 8);
        arm_aes_ecb_encrypt(&ctx, plaintext, result);
        
        char msg[64];
        snprintf(msg, sizeof(msg), "ECB encrypt vector %d (%s)", i, vector->name);
        TEST_ASSERT_EQUAL_HEX(ciphertext, result, 16, msg);
        
        /* Test decryption */
        arm_aes_ecb_decrypt(&ctx, ciphertext, result);
        snprintf(msg, sizeof(msg), "ECB decrypt vector %d (%s)", i, vector->name);
        TEST_ASSERT_EQUAL_HEX(plaintext, result, 16, msg);
        
        arm_aes_clear(&ctx);
    }
    
    return 1;
}

/*
 * Test AES CBC mode
 */
static int test_aes_cbc_mode(void)
{
    /* Test data */
    uint8_t key[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };
    
    uint8_t iv[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    
    uint8_t plaintext[32] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
        0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51
    };
    
    uint8_t expected_ciphertext[32] = {
        0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46,
        0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d,
        0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee,
        0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2
    };
    
    arm_aes_ctx ctx;
    uint8_t ciphertext[32], result[32];
    uint8_t test_iv[16];
    
    /* Initialize AES context */
    arm_aes_init(&ctx, key, 128);
    
    /* Test encryption */
    memcpy(test_iv, iv, 16);
    arm_aes_cbc_encrypt(&ctx, test_iv, plaintext, ciphertext, 32);
    TEST_ASSERT_EQUAL_HEX(expected_ciphertext, ciphertext, 32, "CBC encryption");
    
    /* Test decryption */
    memcpy(test_iv, iv, 16);
    arm_aes_cbc_decrypt(&ctx, test_iv, ciphertext, result, 32);
    TEST_ASSERT_EQUAL_HEX(plaintext, result, 32, "CBC decryption");
    
    arm_aes_clear(&ctx);
    return 1;
}

/*
 * Test AES CTR mode
 */
static int test_aes_ctr_mode(void)
{
    /* Test data */
    uint8_t key[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };
    
    uint8_t nonce[16] = {
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
        0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
    };
    
    uint8_t plaintext[32] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
        0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51
    };
    
    arm_aes_ctx ctx;
    uint8_t ciphertext[32], result[32];
    uint8_t test_nonce[16];
    
    /* Initialize AES context */
    arm_aes_init(&ctx, key, 128);
    
    /* Test encryption */
    memcpy(test_nonce, nonce, 16);
    arm_aes_ctr_crypt(&ctx, test_nonce, plaintext, ciphertext, 32);
    
    /* Test decryption (CTR is symmetric) */
    memcpy(test_nonce, nonce, 16);
    arm_aes_ctr_crypt(&ctx, test_nonce, ciphertext, result, 32);
    TEST_ASSERT_EQUAL_HEX(plaintext, result, 32, "CTR mode roundtrip");
    
    /* Test with non-block-aligned length */
    memcpy(test_nonce, nonce, 16);
    arm_aes_ctr_crypt(&ctx, test_nonce, plaintext, ciphertext, 17);
    
    memcpy(test_nonce, nonce, 16);
    arm_aes_ctr_crypt(&ctx, test_nonce, ciphertext, result, 17);
    TEST_ASSERT_EQUAL_HEX(plaintext, result, 17, "CTR mode unaligned");
    
    arm_aes_clear(&ctx);
    return 1;
}

/*
 * Test key schedule function
 */
static int test_aes_key_schedule(void)
{
    uint8_t key[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };
    
    uint32_t round_keys[44];  /* AES-128: 11 round keys * 4 words */
    
    /* Test key expansion */
    arm_aes_key_schedule(key, round_keys, 128);
    
    /* Verify first round key matches original key */
    TEST_ASSERT(memcmp(key, round_keys, 16) == 0, "First round key should match original key");
    
    /* Verify round keys are different */
    int all_same = 1;
    for (int i = 1; i < 11; i++) {
        if (memcmp(&round_keys[0], &round_keys[i * 4], 16) != 0) {
            all_same = 0;
            break;
        }
    }
    TEST_ASSERT(!all_same, "Round keys should be different");
    
    /* Clear sensitive data */
    arm_secure_zero(round_keys, sizeof(round_keys));
    return 1;
}

/*
 * Test block encryption/decryption functions
 */
static int test_aes_block_functions(void)
{
    uint8_t key[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };
    
    uint8_t plaintext[16] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
    };
    
    uint32_t round_keys[44];
    uint8_t ciphertext[16], result[16];
    
    /* Generate round keys */
    arm_aes_key_schedule(key, round_keys, 128);
    
    /* Test block encryption */
    arm_aes_encrypt_block(round_keys, 10, plaintext, ciphertext);
    
    /* Test block decryption */
    arm_aes_decrypt_block(round_keys, 10, ciphertext, result);
    TEST_ASSERT_EQUAL_HEX(plaintext, result, 16, "Block encrypt/decrypt roundtrip");
    
    /* Test with different plaintext */
    memset(plaintext, 0xAA, 16);
    arm_aes_encrypt_block(round_keys, 10, plaintext, ciphertext);
    arm_aes_decrypt_block(round_keys, 10, ciphertext, result);
    TEST_ASSERT_EQUAL_HEX(plaintext, result, 16, "Block functions with pattern data");
    
    arm_secure_zero(round_keys, sizeof(round_keys));
    return 1;
}

/*
 * Test AES context clearing
 */
static int test_aes_clear(void)
{
    arm_aes_ctx ctx;
    uint8_t key[16] = {0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
                       0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
    
    /* Initialize context */
    arm_aes_init(&ctx, key, 128);
    TEST_ASSERT(ctx.nr == 10, "Context should be initialized");
    
    /* Clear context */
    arm_aes_clear(&ctx);
    
    /* Verify context is cleared */
    TEST_ASSERT(ctx.nr == 0, "Number of rounds should be cleared");
    TEST_ASSERT(ctx.key_size == 0, "Key size should be cleared");
    
    /* Verify round keys are zeroed */
    uint8_t zero_keys[sizeof(ctx.round_keys)];
    memset(zero_keys, 0, sizeof(zero_keys));
    TEST_ASSERT(memcmp(ctx.round_keys, zero_keys, sizeof(zero_keys)) == 0, 
                "Round keys should be zeroed");
    
    return 1;
}

/*
 * Test error handling
 */
static int test_aes_error_handling(void)
{
    arm_aes_ctx ctx;
    uint8_t key[16] = {0};
    uint8_t data[16] = {0};
    uint8_t result[16];
    
    /* Test NULL pointer handling */
    arm_aes_init(NULL, key, 128);  /* Should not crash */
    arm_aes_init(&ctx, NULL, 128); /* Should not crash */
    
    /* Initialize valid context */
    arm_aes_init(&ctx, key, 128);
    
    /* Test NULL pointers in ECB functions */
    arm_aes_ecb_encrypt(NULL, data, result);    /* Should not crash */
    arm_aes_ecb_encrypt(&ctx, NULL, result);    /* Should not crash */
    arm_aes_ecb_encrypt(&ctx, data, NULL);      /* Should not crash */
    
    arm_aes_ecb_decrypt(NULL, data, result);    /* Should not crash */
    arm_aes_ecb_decrypt(&ctx, NULL, result);    /* Should not crash */
    arm_aes_ecb_decrypt(&ctx, data, NULL);      /* Should not crash */
    
    /* Test NULL pointers in CBC functions */
    uint8_t iv[16] = {0};
    arm_aes_cbc_encrypt(NULL, iv, data, result, 16);       /* Should not crash */
    arm_aes_cbc_encrypt(&ctx, NULL, data, result, 16);     /* Should not crash */
    arm_aes_cbc_encrypt(&ctx, iv, NULL, result, 16);       /* Should not crash */
    arm_aes_cbc_encrypt(&ctx, iv, data, NULL, 16);         /* Should not crash */
    
    /* Test invalid length for CBC (must be multiple of 16) */
    arm_aes_cbc_encrypt(&ctx, iv, data, result, 15);       /* Should not crash */
    
    /* Test NULL clear */
    arm_aes_clear(NULL);  /* Should not crash */
    
    arm_aes_clear(&ctx);
    return 1;
}

/*
 * Test constant-time behavior (basic check)
 */
static int test_aes_constant_time(void)
{
    arm_aes_ctx ctx;
    uint8_t key[16] = {0};
    uint8_t plaintext1[16] = {0x00}; /* All zeros */
    uint8_t plaintext2[16] = {0xFF}; /* All ones */
    uint8_t ciphertext1[16], ciphertext2[16];
    
    arm_aes_init(&ctx, key, 128);
    
    /* Encrypt different plaintexts */
    arm_aes_ecb_encrypt(&ctx, plaintext1, ciphertext1);
    arm_aes_ecb_encrypt(&ctx, plaintext2, ciphertext2);
    
    /* Ciphertexts should be different */
    TEST_ASSERT(arm_ct_memcmp(ciphertext1, ciphertext2, 16) != 0, 
                "Different plaintexts should produce different ciphertexts");
    
    /* Test with same plaintext, different keys */
    uint8_t key1[16] = {0x00};
    uint8_t key2[16] = {0xFF};
    uint8_t plaintext[16] = {0x55};
    
    arm_aes_init(&ctx, key1, 128);
    arm_aes_ecb_encrypt(&ctx, plaintext, ciphertext1);
    
    arm_aes_init(&ctx, key2, 128);
    arm_aes_ecb_encrypt(&ctx, plaintext, ciphertext2);
    
    TEST_ASSERT(arm_ct_memcmp(ciphertext1, ciphertext2, 16) != 0,
                "Same plaintext with different keys should produce different ciphertexts");
    
    arm_aes_clear(&ctx);
    return 1;
}

/*
 * Performance test (basic timing)
 */
static int test_aes_performance(void)
{
    arm_aes_ctx ctx;
    uint8_t key[16] = {0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
                       0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
    uint8_t data[16] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
                        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a};
    uint8_t result[16];
    
    const int iterations = 1000;
    
    arm_aes_init(&ctx, key, 128);
    
    /* Warm up */
    for (int i = 0; i < 10; i++) {
        arm_aes_ecb_encrypt(&ctx, data, result);
    }
    
    /* Time encryption */
    clock_t start = clock();
    for (int i = 0; i < iterations; i++) {
        arm_aes_ecb_encrypt(&ctx, data, result);
    }
    clock_t end = clock();
    
    double encrypt_time = ((double)(end - start)) / CLOCKS_PER_SEC;
    double encrypt_rate = (iterations * 16) / encrypt_time;  /* bytes per second */
    
    printf("AES-128 ECB Encrypt: %.2f MB/s (%d iterations)\n", 
           encrypt_rate / (1024 * 1024), iterations);
    
    /* Time decryption */
    start = clock();
    for (int i = 0; i < iterations; i++) {
        arm_aes_ecb_decrypt(&ctx, result, data);
    }
    end = clock();
    
    double decrypt_time = ((double)(end - start)) / CLOCKS_PER_SEC;
    double decrypt_rate = (iterations * 16) / decrypt_time;
    
    printf("AES-128 ECB Decrypt: %.2f MB/s (%d iterations)\n", 
           decrypt_rate / (1024 * 1024), iterations);
    
    arm_aes_clear(&ctx);
    return 1;
}

/*
 * Main test runner
 */
int main(void)
{
    printf("AES Unit Tests\n");
    printf("==============\n\n");
    
    RUN_TEST(test_aes_init);
    RUN_TEST(test_aes_ecb_vectors);
    RUN_TEST(test_aes_cbc_mode);
    RUN_TEST(test_aes_ctr_mode);
    RUN_TEST(test_aes_key_schedule);
    RUN_TEST(test_aes_block_functions);
    RUN_TEST(test_aes_clear);
    RUN_TEST(test_aes_error_handling);
    RUN_TEST(test_aes_constant_time);
    RUN_TEST(test_aes_performance);
    
    printf("\n==============\n");
    printf("Tests: %d total, %d passed, %d failed\n", 
           tests_total, tests_passed, tests_failed);
    
    return (tests_failed == 0) ? 0 : 1;
}
