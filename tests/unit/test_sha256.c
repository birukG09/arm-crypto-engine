/*
 * SHA-256 Unit Tests
 * ArmAsm-CryptoEngine - Comprehensive SHA-256 Testing
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include "armcrypto/sha256.h"
#include "armcrypto/ct.h"
#include "../vectors/sha256_vectors.h"

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
 * Test SHA-256 context initialization
 */
static int test_sha256_init(void)
{
    arm_sha256_ctx ctx;
    
    arm_sha256_init(&ctx);
    
    /* Verify initial state */
    TEST_ASSERT(ctx.count == 0, "Initial count should be zero");
    TEST_ASSERT(ctx.buffer_len == 0, "Initial buffer length should be zero");
    
    /* Verify initial hash values (first 32 bits of fractional parts of square roots of first 8 primes) */
    uint32_t expected_state[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };
    
    for (int i = 0; i < 8; i++) {
        TEST_ASSERT(ctx.state[i] == expected_state[i], "Initial state values should match SHA-256 constants");
    }
    
    return 1;
}

/*
 * Test SHA-256 with empty input
 */
static int test_sha256_empty(void)
{
    arm_sha256_ctx ctx;
    uint8_t hash[32];
    
    /* Expected hash of empty string */
    uint8_t expected[32] = {
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
        0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
        0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
        0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
    };
    
    arm_sha256_init(&ctx);
    arm_sha256_final(&ctx, hash);
    
    TEST_ASSERT_EQUAL_HEX(expected, hash, 32, "SHA-256 of empty string");
    
    /* Test one-shot function */
    arm_sha256_hash(NULL, 0, hash);
    TEST_ASSERT_EQUAL_HEX(expected, hash, 32, "SHA-256 one-shot empty string");
    
    return 1;
}

/*
 * Test SHA-256 with NIST test vectors
 */
static int test_sha256_vectors(void)
{
    for (int i = 0; i < SHA256_VECTOR_COUNT; i++) {
        const sha256_vector_t* vector = &sha256_vectors[i];
        arm_sha256_ctx ctx;
        uint8_t hash[32];
        uint8_t expected[32];
        
        /* Convert expected hash from hex */
        hex_to_bytes(vector->hash, expected, 32);
        
        if (vector->message == NULL) {
            /* Special case for very long messages (e.g., 1 million 'a's) */
            arm_sha256_init(&ctx);
            for (size_t j = 0; j < vector->len; j++) {
                uint8_t byte = 'a';
                arm_sha256_update(&ctx, &byte, 1);
            }
            arm_sha256_final(&ctx, hash);
        } else {
            /* Regular test vector */
            uint8_t* message = malloc(vector->len);
            TEST_ASSERT(message != NULL, "Failed to allocate memory for test vector");
            
            hex_to_bytes(vector->message, message, vector->len);
            
            /* Test streaming interface */
            arm_sha256_init(&ctx);
            arm_sha256_update(&ctx, message, vector->len);
            arm_sha256_final(&ctx, hash);
            
            char msg[64];
            snprintf(msg, sizeof(msg), "SHA-256 vector %d (%s) streaming", i, vector->name);
            TEST_ASSERT_EQUAL_HEX(expected, hash, 32, msg);
            
            /* Test one-shot interface */
            arm_sha256_hash(message, vector->len, hash);
            snprintf(msg, sizeof(msg), "SHA-256 vector %d (%s) one-shot", i, vector->name);
            TEST_ASSERT_EQUAL_HEX(expected, hash, 32, msg);
            
            free(message);
        }
    }
    
    return 1;
}

/*
 * Test SHA-256 with various input sizes
 */
static int test_sha256_sizes(void)
{
    arm_sha256_ctx ctx;
    uint8_t hash1[32], hash2[32];
    
    /* Test sizes around block boundaries */
    size_t test_sizes[] = {1, 55, 56, 63, 64, 65, 127, 128, 129, 256, 1000};
    int num_sizes = sizeof(test_sizes) / sizeof(test_sizes[0]);
    
    for (int i = 0; i < num_sizes; i++) {
        size_t size = test_sizes[i];
        uint8_t* data = malloc(size);
        TEST_ASSERT(data != NULL, "Failed to allocate test data");
        
        /* Fill with pattern */
        for (size_t j = 0; j < size; j++) {
            data[j] = (uint8_t)(j & 0xFF);
        }
        
        /* Test streaming vs one-shot */
        arm_sha256_init(&ctx);
        arm_sha256_update(&ctx, data, size);
        arm_sha256_final(&ctx, hash1);
        
        arm_sha256_hash(data, size, hash2);
        
        char msg[64];
        snprintf(msg, sizeof(msg), "Streaming vs one-shot for size %zu", size);
        TEST_ASSERT_EQUAL_HEX(hash1, hash2, 32, msg);
        
        free(data);
    }
    
    return 1;
}

/*
 * Test SHA-256 incremental updates
 */
static int test_sha256_incremental(void)
{
    arm_sha256_ctx ctx1, ctx2;
    uint8_t hash1[32], hash2[32];
    
    const char* test_string = "The quick brown fox jumps over the lazy dog";
    size_t len = strlen(test_string);
    
    /* Hash all at once */
    arm_sha256_init(&ctx1);
    arm_sha256_update(&ctx1, (const uint8_t*)test_string, len);
    arm_sha256_final(&ctx1, hash1);
    
    /* Hash incrementally */
    arm_sha256_init(&ctx2);
    for (size_t i = 0; i < len; i++) {
        arm_sha256_update(&ctx2, (const uint8_t*)&test_string[i], 1);
    }
    arm_sha256_final(&ctx2, hash2);
    
    TEST_ASSERT_EQUAL_HEX(hash1, hash2, 32, "Incremental vs batch update");
    
    /* Test different chunk sizes */
    arm_sha256_init(&ctx2);
    size_t pos = 0;
    while (pos < len) {
        size_t chunk_size = (pos + 5 <= len) ? 5 : (len - pos);
        arm_sha256_update(&ctx2, (const uint8_t*)&test_string[pos], chunk_size);
        pos += chunk_size;
    }
    arm_sha256_final(&ctx2, hash2);
    
    TEST_ASSERT_EQUAL_HEX(hash1, hash2, 32, "Chunked vs batch update");
    
    return 1;
}

/*
 * Test HMAC-SHA256
 */
static int test_hmac_sha256(void)
{
    /* RFC 4231 test vectors */
    struct {
        const char* key;
        const char* data;
        const char* expected;
        size_t key_len;
        size_t data_len;
    } vectors[] = {
        {
            "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b",
            "Hi There",
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
            20, 8
        },
        {
            "Jefe",
            "what do ya want for nothing?",
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
            4, 28
        },
        {
            "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa",
            "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd",
            "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
            20, 50
        }
    };
    
    int num_vectors = sizeof(vectors) / sizeof(vectors[0]);
    
    for (int i = 0; i < num_vectors; i++) {
        uint8_t mac[32];
        uint8_t expected[32];
        
        hex_to_bytes(vectors[i].expected, expected, 32);
        
        /* Test one-shot HMAC */
        arm_hmac_sha256((const uint8_t*)vectors[i].key, vectors[i].key_len,
                       (const uint8_t*)vectors[i].data, vectors[i].data_len,
                       mac);
        
        char msg[64];
        snprintf(msg, sizeof(msg), "HMAC-SHA256 vector %d (one-shot)", i);
        TEST_ASSERT_EQUAL_HEX(expected, mac, 32, msg);
        
        /* Test streaming HMAC */
        arm_hmac_sha256_ctx hmac_ctx;
        arm_hmac_sha256_init(&hmac_ctx, (const uint8_t*)vectors[i].key, vectors[i].key_len);
        arm_hmac_sha256_update(&hmac_ctx, (const uint8_t*)vectors[i].data, vectors[i].data_len);
        arm_hmac_sha256_final(&hmac_ctx, mac);
        arm_hmac_sha256_clear(&hmac_ctx);
        
        snprintf(msg, sizeof(msg), "HMAC-SHA256 vector %d (streaming)", i);
        TEST_ASSERT_EQUAL_HEX(expected, mac, 32, msg);
    }
    
    return 1;
}

/*
 * Test SHA-256 context clearing
 */
static int test_sha256_clear(void)
{
    arm_sha256_ctx ctx;
    uint8_t data[] = "test data";
    
    /* Initialize and use context */
    arm_sha256_init(&ctx);
    arm_sha256_update(&ctx, data, sizeof(data) - 1);
    
    /* Verify context has data */
    TEST_ASSERT(ctx.count > 0, "Context should have processed data");
    
    /* Clear context */
    arm_sha256_clear(&ctx);
    
    /* Verify context is cleared */
    TEST_ASSERT(ctx.count == 0, "Count should be cleared");
    TEST_ASSERT(ctx.buffer_len == 0, "Buffer length should be cleared");
    
    /* Verify state is zeroed */
    uint8_t zero_state[sizeof(ctx.state)];
    memset(zero_state, 0, sizeof(zero_state));
    TEST_ASSERT(memcmp(ctx.state, zero_state, sizeof(zero_state)) == 0,
                "State should be zeroed");
    
    return 1;
}

/*
 * Test error handling
 */
static int test_sha256_error_handling(void)
{
    arm_sha256_ctx ctx;
    uint8_t data[] = "test";
    uint8_t hash[32];
    
    /* Test NULL pointer handling */
    arm_sha256_init(NULL);  /* Should not crash */
    
    arm_sha256_init(&ctx);
    
    arm_sha256_update(NULL, data, sizeof(data));       /* Should not crash */
    arm_sha256_update(&ctx, NULL, sizeof(data));       /* Should not crash */
    arm_sha256_update(&ctx, data, 0);                  /* Should not crash */
    
    arm_sha256_final(NULL, hash);                      /* Should not crash */
    arm_sha256_final(&ctx, NULL);                      /* Should not crash */
    
    arm_sha256_hash(NULL, sizeof(data), hash);         /* Should not crash */
    arm_sha256_hash(data, sizeof(data), NULL);         /* Should not crash */
    
    arm_sha256_clear(NULL);                            /* Should not crash */
    
    /* Test HMAC error handling */
    arm_hmac_sha256(NULL, 16, data, sizeof(data), hash);       /* Should not crash */
    arm_hmac_sha256(data, 16, NULL, sizeof(data), hash);       /* Should not crash */
    arm_hmac_sha256(data, 16, data, sizeof(data), NULL);       /* Should not crash */
    
    return 1;
}

/*
 * Test constant-time behavior (basic check)
 */
static int test_sha256_constant_time(void)
{
    uint8_t data1[64] = {0x00};  /* All zeros */
    uint8_t data2[64] = {0xFF};  /* All ones */
    uint8_t hash1[32], hash2[32];
    
    /* Hash different data */
    arm_sha256_hash(data1, 64, hash1);
    arm_sha256_hash(data2, 64, hash2);
    
    /* Results should be different */
    TEST_ASSERT(arm_ct_memcmp(hash1, hash2, 32) != 0,
                "Different inputs should produce different hashes");
    
    /* Test with identical data */
    arm_sha256_hash(data1, 64, hash2);
    TEST_ASSERT(arm_ct_memcmp(hash1, hash2, 32) == 0,
                "Identical inputs should produce identical hashes");
    
    return 1;
}

/*
 * Test compression function directly
 */
static int test_sha256_compression(void)
{
    uint32_t state[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };
    
    uint8_t block[64];
    memset(block, 0, 64);
    
    uint32_t original_state[8];
    memcpy(original_state, state, sizeof(original_state));
    
    /* Call compression function */
    arm_sha256_compress(state, block);
    
    /* State should have changed */
    int changed = 0;
    for (int i = 0; i < 8; i++) {
        if (state[i] != original_state[i]) {
            changed = 1;
            break;
        }
    }
    TEST_ASSERT(changed, "Compression function should modify state");
    
    return 1;
}

/*
 * Performance test (basic timing)
 */
static int test_sha256_performance(void)
{
    const size_t test_size = 1024 * 1024;  /* 1 MB */
    uint8_t* data = malloc(test_size);
    uint8_t hash[32];
    
    TEST_ASSERT(data != NULL, "Failed to allocate test data");
    
    /* Fill with pattern */
    for (size_t i = 0; i < test_size; i++) {
        data[i] = (uint8_t)(i & 0xFF);
    }
    
    const int iterations = 10;
    
    /* Warm up */
    arm_sha256_hash(data, test_size, hash);
    
    /* Time hashing */
    clock_t start = clock();
    for (int i = 0; i < iterations; i++) {
        arm_sha256_hash(data, test_size, hash);
    }
    clock_t end = clock();
    
    double total_time = ((double)(end - start)) / CLOCKS_PER_SEC;
    double rate = (iterations * test_size) / total_time;  /* bytes per second */
    
    printf("SHA-256: %.2f MB/s (%d iterations of %zu bytes)\n", 
           rate / (1024 * 1024), iterations, test_size);
    
    free(data);
    return 1;
}

/*
 * Main test runner
 */
int main(void)
{
    printf("SHA-256 Unit Tests\n");
    printf("==================\n\n");
    
    RUN_TEST(test_sha256_init);
    RUN_TEST(test_sha256_empty);
    RUN_TEST(test_sha256_vectors);
    RUN_TEST(test_sha256_sizes);
    RUN_TEST(test_sha256_incremental);
    RUN_TEST(test_hmac_sha256);
    RUN_TEST(test_sha256_clear);
    RUN_TEST(test_sha256_error_handling);
    RUN_TEST(test_sha256_constant_time);
    RUN_TEST(test_sha256_compression);
    RUN_TEST(test_sha256_performance);
    
    printf("\n==================\n");
    printf("Tests: %d total, %d passed, %d failed\n", 
           tests_total, tests_passed, tests_failed);
    
    return (tests_failed == 0) ? 0 : 1;
}
