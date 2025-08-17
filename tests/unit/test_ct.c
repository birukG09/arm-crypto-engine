/*
 * Constant-Time Utilities Unit Tests
 * ArmAsm-CryptoEngine - Comprehensive Constant-Time Testing
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include "armcrypto/ct.h"

/* Test framework macros */
#define TEST_ASSERT(condition, message) \
    do { \
        if (!(condition)) { \
            printf("FAIL: %s - %s\n", __func__, message); \
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
 * Test constant-time memory comparison
 */
static int test_ct_memcmp(void)
{
    uint8_t data1[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                         0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};
    uint8_t data2[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                         0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};
    uint8_t data3[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                         0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x11};
    
    /* Test equal arrays */
    TEST_ASSERT(arm_ct_memcmp(data1, data2, 16) == 0, "Equal arrays should return 0");
    
    /* Test different arrays */
    TEST_ASSERT(arm_ct_memcmp(data1, data3, 16) != 0, "Different arrays should return non-zero");
    
    /* Test different lengths */
    TEST_ASSERT(arm_ct_memcmp(data1, data2, 0) == 0, "Zero length should return 0");
    TEST_ASSERT(arm_ct_memcmp(data1, data2, 15) == 0, "Partial equal comparison");
    TEST_ASSERT(arm_ct_memcmp(data1, data3, 15) == 0, "Partial comparison ignoring last byte");
    
    /* Test with all possible byte differences */
    for (int i = 0; i < 16; i++) {
        uint8_t test_data[16];
        memcpy(test_data, data1, 16);
        test_data[i] ^= 0x01;  /* Flip one bit */
        
        TEST_ASSERT(arm_ct_memcmp(data1, test_data, 16) != 0, 
                   "Single bit difference should be detected");
    }
    
    /* Test NULL pointers */
    TEST_ASSERT(arm_ct_memcmp(NULL, data1, 16) != 0, "NULL pointer should return non-zero");
    TEST_ASSERT(arm_ct_memcmp(data1, NULL, 16) != 0, "NULL pointer should return non-zero");
    
    return 1;
}

/*
 * Test constant-time memory XOR
 */
static int test_ct_memxor(void)
{
    uint8_t src1[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};
    uint8_t src2[16] = {0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8,
                        0xF7, 0xF6, 0xF5, 0xF4, 0xF3, 0xF2, 0xF1, 0xF0};
    uint8_t dst[16];
    uint8_t expected[16];
    
    /* Calculate expected result */
    for (int i = 0; i < 16; i++) {
        expected[i] = src1[i] ^ src2[i];
    }
    
    /* Test XOR operation */
    arm_ct_memxor(dst, src1, src2, 16);
    TEST_ASSERT(memcmp(dst, expected, 16) == 0, "XOR result should match expected");
    
    /* Test XOR with self (should produce zeros) */
    arm_ct_memxor(dst, src1, src1, 16);
    uint8_t zeros[16] = {0};
    TEST_ASSERT(memcmp(dst, zeros, 16) == 0, "XOR with self should produce zeros");
    
    /* Test in-place XOR */
    memcpy(dst, src1, 16);
    arm_ct_memxor(dst, dst, src2, 16);
    TEST_ASSERT(memcmp(dst, expected, 16) == 0, "In-place XOR should work");
    
    /* Test with different lengths */
    arm_ct_memxor(dst, src1, src2, 1);
    TEST_ASSERT(dst[0] == expected[0], "Single byte XOR");
    TEST_ASSERT(dst[1] != expected[1], "Other bytes should be unchanged");
    
    /* Test NULL pointer handling */
    arm_ct_memxor(NULL, src1, src2, 16);  /* Should not crash */
    arm_ct_memxor(dst, NULL, src2, 16);   /* Should not crash */
    arm_ct_memxor(dst, src1, NULL, 16);   /* Should not crash */
    
    return 1;
}

/*
 * Test constant-time conditional select
 */
static int test_ct_select_u32(void)
{
    uint32_t a = 0x12345678;
    uint32_t b = 0x87654321;
    
    /* Test condition true (non-zero) */
    TEST_ASSERT(arm_ct_select_u32(1, a, b) == a, "Condition 1 should select first value");
    TEST_ASSERT(arm_ct_select_u32(42, a, b) == a, "Any non-zero condition should select first value");
    TEST_ASSERT(arm_ct_select_u32(0xFFFFFFFF, a, b) == a, "Max value condition should select first value");
    
    /* Test condition false (zero) */
    TEST_ASSERT(arm_ct_select_u32(0, a, b) == b, "Condition 0 should select second value");
    
    /* Test with same values */
    TEST_ASSERT(arm_ct_select_u32(1, a, a) == a, "Same values should return same result");
    TEST_ASSERT(arm_ct_select_u32(0, a, a) == a, "Same values should return same result");
    
    /* Test edge cases */
    TEST_ASSERT(arm_ct_select_u32(1, 0, 0xFFFFFFFF) == 0, "Should select 0");
    TEST_ASSERT(arm_ct_select_u32(0, 0, 0xFFFFFFFF) == 0xFFFFFFFF, "Should select max value");
    
    return 1;
}

/*
 * Test constant-time conditional copy
 */
static int test_ct_conditional_copy(void)
{
    uint8_t src[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                       0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};
    uint8_t dst[16] = {0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8,
                       0xF7, 0xF6, 0xF5, 0xF4, 0xF3, 0xF2, 0xF1, 0xF0};
    uint8_t original_dst[16];
    
    memcpy(original_dst, dst, 16);
    
    /* Test condition true - should copy */
    arm_ct_conditional_copy(1, dst, src, 16);
    TEST_ASSERT(memcmp(dst, src, 16) == 0, "Condition true should copy source to destination");
    
    /* Reset destination */
    memcpy(dst, original_dst, 16);
    
    /* Test condition false - should not copy */
    arm_ct_conditional_copy(0, dst, src, 16);
    TEST_ASSERT(memcmp(dst, original_dst, 16) == 0, "Condition false should not modify destination");
    
    /* Test with non-zero condition */
    arm_ct_conditional_copy(42, dst, src, 16);
    TEST_ASSERT(memcmp(dst, src, 16) == 0, "Any non-zero condition should copy");
    
    /* Test partial copy */
    memcpy(dst, original_dst, 16);
    arm_ct_conditional_copy(1, dst, src, 8);
    TEST_ASSERT(memcmp(dst, src, 8) == 0, "First 8 bytes should be copied");
    TEST_ASSERT(memcmp(&dst[8], &original_dst[8], 8) == 0, "Last 8 bytes should be unchanged");
    
    /* Test NULL pointer handling */
    arm_ct_conditional_copy(1, NULL, src, 16);  /* Should not crash */
    arm_ct_conditional_copy(1, dst, NULL, 16);  /* Should not crash */
    
    return 1;
}

/*
 * Test secure memory zeroization
 */
static int test_secure_zero(void)
{
    uint8_t data[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};
    uint8_t zeros[16] = {0};
    
    /* Verify data is not initially zero */
    TEST_ASSERT(memcmp(data, zeros, 16) != 0, "Initial data should not be zero");
    
    /* Zero the data */
    arm_secure_zero(data, 16);
    
    /* Verify data is now zero */
    TEST_ASSERT(memcmp(data, zeros, 16) == 0, "Data should be zeroed");
    
    /* Test with different sizes */
    uint8_t small_data[4] = {0xFF, 0xFF, 0xFF, 0xFF};
    arm_secure_zero(small_data, 4);
    TEST_ASSERT(memcmp(small_data, zeros, 4) == 0, "Small data should be zeroed");
    
    /* Test with large data */
    uint8_t* large_data = malloc(1024);
    TEST_ASSERT(large_data != NULL, "Failed to allocate large data");
    
    memset(large_data, 0xAA, 1024);
    arm_secure_zero(large_data, 1024);
    
    int all_zero = 1;
    for (int i = 0; i < 1024; i++) {
        if (large_data[i] != 0) {
            all_zero = 0;
            break;
        }
    }
    TEST_ASSERT(all_zero, "Large data should be completely zeroed");
    
    free(large_data);
    
    /* Test NULL pointer handling */
    arm_secure_zero(NULL, 16);  /* Should not crash */
    arm_secure_zero(data, 0);   /* Should not crash */
    
    return 1;
}

/*
 * Test constant-time equality checks
 */
static int test_ct_equality(void)
{
    /* Test byte equality */
    TEST_ASSERT(arm_ct_eq_u8(0x42, 0x42) == 0xFF, "Equal bytes should return 0xFF");
    TEST_ASSERT(arm_ct_eq_u8(0x42, 0x43) == 0x00, "Different bytes should return 0x00");
    TEST_ASSERT(arm_ct_eq_u8(0x00, 0x00) == 0xFF, "Zero bytes should be equal");
    TEST_ASSERT(arm_ct_eq_u8(0xFF, 0xFF) == 0xFF, "Max bytes should be equal");
    
    /* Test 32-bit equality */
    TEST_ASSERT(arm_ct_eq_u32(0x12345678, 0x12345678) == 0xFFFFFFFF, "Equal 32-bit values");
    TEST_ASSERT(arm_ct_eq_u32(0x12345678, 0x12345679) == 0x00000000, "Different 32-bit values");
    TEST_ASSERT(arm_ct_eq_u32(0x00000000, 0x00000000) == 0xFFFFFFFF, "Zero 32-bit values");
    TEST_ASSERT(arm_ct_eq_u32(0xFFFFFFFF, 0xFFFFFFFF) == 0xFFFFFFFF, "Max 32-bit values");
    
    /* Test edge cases */
    TEST_ASSERT(arm_ct_eq_u32(0x80000000, 0x80000000) == 0xFFFFFFFF, "Sign bit set equality");
    TEST_ASSERT(arm_ct_eq_u32(0x7FFFFFFF, 0x7FFFFFFF) == 0xFFFFFFFF, "Max positive equality");
    
    return 1;
}

/*
 * Test constant-time comparisons
 */
static int test_ct_comparisons(void)
{
    /* Test less-than */
    TEST_ASSERT(arm_ct_lt_u32(5, 10) == 0xFFFFFFFF, "5 < 10 should be true");
    TEST_ASSERT(arm_ct_lt_u32(10, 5) == 0x00000000, "10 < 5 should be false");
    TEST_ASSERT(arm_ct_lt_u32(5, 5) == 0x00000000, "5 < 5 should be false");
    
    /* Test greater-than */
    TEST_ASSERT(arm_ct_gt_u32(10, 5) == 0xFFFFFFFF, "10 > 5 should be true");
    TEST_ASSERT(arm_ct_gt_u32(5, 10) == 0x00000000, "5 > 10 should be false");
    TEST_ASSERT(arm_ct_gt_u32(5, 5) == 0x00000000, "5 > 5 should be false");
    
    /* Test with edge values */
    TEST_ASSERT(arm_ct_lt_u32(0, 1) == 0xFFFFFFFF, "0 < 1");
    TEST_ASSERT(arm_ct_lt_u32(0xFFFFFFFE, 0xFFFFFFFF) == 0xFFFFFFFF, "Max-1 < Max");
    TEST_ASSERT(arm_ct_gt_u32(0xFFFFFFFF, 0xFFFFFFFE) == 0xFFFFFFFF, "Max > Max-1");
    
    return 1;
}

/*
 * Test constant-time array lookup
 */
static int test_ct_array_lookup(void)
{
    uint8_t array[8] = {0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80};
    
    /* Test valid indices */
    for (size_t i = 0; i < 8; i++) {
        uint8_t result = arm_ct_array_lookup_u8(array, 8, i);
        TEST_ASSERT(result == array[i], "Array lookup should return correct value");
    }
    
    /* Test out-of-bounds indices */
    TEST_ASSERT(arm_ct_array_lookup_u8(array, 8, 8) == 0, "Out-of-bounds should return 0");
    TEST_ASSERT(arm_ct_array_lookup_u8(array, 8, 100) == 0, "Far out-of-bounds should return 0");
    
    /* Test with empty array */
    TEST_ASSERT(arm_ct_array_lookup_u8(array, 0, 0) == 0, "Empty array should return 0");
    
    /* Test NULL array */
    TEST_ASSERT(arm_ct_array_lookup_u8(NULL, 8, 0) == 0, "NULL array should return 0");
    
    return 1;
}

/*
 * Test constant-time bit operations
 */
static int test_ct_bit_operations(void)
{
    /* Test population count */
    TEST_ASSERT(arm_ct_popcount_u32(0x00000000) == 0, "Zero should have 0 bits set");
    TEST_ASSERT(arm_ct_popcount_u32(0xFFFFFFFF) == 32, "All ones should have 32 bits set");
    TEST_ASSERT(arm_ct_popcount_u32(0x00000001) == 1, "Single bit should have count 1");
    TEST_ASSERT(arm_ct_popcount_u32(0x80000000) == 1, "Sign bit should have count 1");
    TEST_ASSERT(arm_ct_popcount_u32(0x0F0F0F0F) == 16, "Alternating pattern");
    
    /* Test leading zero count */
    TEST_ASSERT(arm_ct_clz_u32(0x80000000) == 0, "Sign bit set should have 0 leading zeros");
    TEST_ASSERT(arm_ct_clz_u32(0x40000000) == 1, "Bit 30 set should have 1 leading zero");
    TEST_ASSERT(arm_ct_clz_u32(0x00000001) == 31, "LSB set should have 31 leading zeros");
    TEST_ASSERT(arm_ct_clz_u32(0x00000000) == 32, "Zero should have 32 leading zeros");
    
    /* Test powers of 2 */
    for (int i = 0; i < 32; i++) {
        uint32_t val = 1U << i;
        TEST_ASSERT(arm_ct_clz_u32(val) == (31 - i), "Leading zeros for power of 2");
        TEST_ASSERT(arm_ct_popcount_u32(val) == 1, "Population count for power of 2");
    }
    
    return 1;
}

/*
 * Test constant-time min/max functions
 */
static int test_ct_min_max(void)
{
    /* Test minimum */
    TEST_ASSERT(arm_ct_min_u32(5, 10) == 5, "min(5, 10) should be 5");
    TEST_ASSERT(arm_ct_min_u32(10, 5) == 5, "min(10, 5) should be 5");
    TEST_ASSERT(arm_ct_min_u32(7, 7) == 7, "min(7, 7) should be 7");
    TEST_ASSERT(arm_ct_min_u32(0, 0xFFFFFFFF) == 0, "min(0, max) should be 0");
    
    /* Test maximum */
    TEST_ASSERT(arm_ct_max_u32(5, 10) == 10, "max(5, 10) should be 10");
    TEST_ASSERT(arm_ct_max_u32(10, 5) == 10, "max(10, 5) should be 10");
    TEST_ASSERT(arm_ct_max_u32(7, 7) == 7, "max(7, 7) should be 7");
    TEST_ASSERT(arm_ct_max_u32(0, 0xFFFFFFFF) == 0xFFFFFFFF, "max(0, max) should be max");
    
    return 1;
}

/*
 * Performance test for constant-time operations
 */
static int test_ct_performance(void)
{
    const int iterations = 1000000;
    uint8_t data1[1024], data2[1024];
    uint32_t result;
    
    /* Initialize test data */
    for (int i = 0; i < 1024; i++) {
        data1[i] = (uint8_t)(i & 0xFF);
        data2[i] = (uint8_t)((i + 1) & 0xFF);
    }
    
    /* Time memory comparison */
    clock_t start = clock();
    for (int i = 0; i < iterations; i++) {
        result = arm_ct_memcmp(data1, data2, 1024);
    }
    clock_t end = clock();
    
    double time_per_op = ((double)(end - start)) / CLOCKS_PER_SEC / iterations;
    double bytes_per_sec = 1024 / time_per_op;
    
    printf("CT memcmp: %.2f MB/s (%d iterations of 1024 bytes)\n", 
           bytes_per_sec / (1024 * 1024), iterations);
    
    /* Time XOR operation */
    start = clock();
    for (int i = 0; i < iterations; i++) {
        arm_ct_memxor(data1, data1, data2, 1024);
    }
    end = clock();
    
    time_per_op = ((double)(end - start)) / CLOCKS_PER_SEC / iterations;
    bytes_per_sec = 1024 / time_per_op;
    
    printf("CT memxor: %.2f MB/s (%d iterations of 1024 bytes)\n", 
           bytes_per_sec / (1024 * 1024), iterations);
    
    /* Avoid compiler optimization */
    (void)result;
    
    return 1;
}

/*
 * Main test runner
 */
int main(void)
{
    printf("Constant-Time Utilities Unit Tests\n");
    printf("===================================\n\n");
    
    RUN_TEST(test_ct_memcmp);
    RUN_TEST(test_ct_memxor);
    RUN_TEST(test_ct_select_u32);
    RUN_TEST(test_ct_conditional_copy);
    RUN_TEST(test_secure_zero);
    RUN_TEST(test_ct_equality);
    RUN_TEST(test_ct_comparisons);
    RUN_TEST(test_ct_array_lookup);
    RUN_TEST(test_ct_bit_operations);
    RUN_TEST(test_ct_min_max);
    RUN_TEST(test_ct_performance);
    
    printf("\n===================================\n");
    printf("Tests: %d total, %d passed, %d failed\n", 
           tests_total, tests_passed, tests_failed);
    
    return (tests_failed == 0) ? 0 : 1;
}
