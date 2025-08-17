/*
 * Constant-Time Utilities Implementation
 * ArmAsm-CryptoEngine - Constant-time operations to prevent timing attacks
 * 
 * All functions in this module are designed to execute in constant time
 * regardless of input values to prevent side-channel information leakage
 */

#include "armcrypto/ct.h"
#include "armcrypto/types.h"
#include <string.h>

/* Platform-specific memory barrier */
#define MEMORY_BARRIER() ARM_CRYPTO_MEMORY_BARRIER()

/*
 * Constant-time memory comparison
 * Returns 0 if equal, non-zero if different
 * Execution time is independent of input data
 */
uint32_t arm_ct_memcmp(const void* a, const void* b, size_t len)
{
    if (!a || !b) {
        return 1; /* Different if either pointer is NULL */
    }
    
    const volatile uint8_t* ptr_a = (const volatile uint8_t*)a;
    const volatile uint8_t* ptr_b = (const volatile uint8_t*)b;
    volatile uint8_t result = 0;
    
    /* Compare each byte, accumulating differences */
    for (size_t i = 0; i < len; i++) {
        result |= ptr_a[i] ^ ptr_b[i];
    }
    
    MEMORY_BARRIER();
    
    /* Convert to 0 (equal) or 1 (different) */
    return (uint32_t)result;
}

/*
 * Constant-time memory XOR
 * Computes dst = src1 XOR src2 in constant time
 */
void arm_ct_memxor(void* dst, const void* src1, const void* src2, size_t len)
{
    if (!dst || !src1 || !src2) {
        return;
    }
    
    volatile uint8_t* d = (volatile uint8_t*)dst;
    const volatile uint8_t* s1 = (const volatile uint8_t*)src1;
    const volatile uint8_t* s2 = (const volatile uint8_t*)src2;
    
    /* XOR each byte */
    for (size_t i = 0; i < len; i++) {
        d[i] = s1[i] ^ s2[i];
    }
    
    MEMORY_BARRIER();
}

/*
 * Constant-time conditional select for 32-bit values
 * Returns a if condition is non-zero, b if condition is zero
 * Execution time is independent of condition value
 */
uint32_t arm_ct_select_u32(uint32_t condition, uint32_t a, uint32_t b)
{
    /* Create mask: all 1s if condition != 0, all 0s if condition == 0 */
    volatile uint32_t mask = 0;
    volatile uint32_t temp_condition = condition;
    
    /* Convert any non-zero value to all 1s */
    mask = temp_condition;
    mask |= mask >> 16;
    mask |= mask >> 8;
    mask |= mask >> 4;
    mask |= mask >> 2;
    mask |= mask >> 1;
    mask = ~mask + 1;  /* Now 0x00000000 or 0xFFFFFFFF */
    
    MEMORY_BARRIER();
    
    /* Select using bitwise operations */
    return (a & mask) | (b & ~mask);
}

/*
 * Constant-time conditional copy
 * Copies src to dst if condition is non-zero
 */
void arm_ct_conditional_copy(uint32_t condition, void* dst, const void* src, size_t len)
{
    if (!dst || !src) {
        return;
    }
    
    volatile uint8_t* d = (volatile uint8_t*)dst;
    const volatile uint8_t* s = (const volatile uint8_t*)src;
    
    /* Create byte mask from condition */
    volatile uint8_t mask = (uint8_t)arm_ct_select_u32(condition, 0xFF, 0x00);
    
    /* Conditionally copy each byte */
    for (size_t i = 0; i < len; i++) {
        d[i] = (s[i] & mask) | (d[i] & ~mask);
    }
    
    MEMORY_BARRIER();
}

/*
 * Secure memory zeroization
 * Guaranteed to zero memory even with compiler optimizations
 */
void arm_secure_zero(void* ptr, size_t len)
{
    if (!ptr || len == 0) {
        return;
    }
    
    volatile uint8_t* p = (volatile uint8_t*)ptr;
    
    /* Zero each byte using volatile to prevent optimization */
    for (size_t i = 0; i < len; i++) {
        p[i] = 0;
    }
    
    MEMORY_BARRIER();
}

/*
 * Constant-time byte equality check
 * Returns 0xFF if equal, 0x00 if different
 */
uint8_t arm_ct_eq_u8(uint8_t a, uint8_t b)
{
    volatile uint8_t diff = a ^ b;
    volatile uint8_t result;
    
    /* Convert 0 to 0xFF, any other value to 0x00 */
    diff |= diff >> 4;
    diff |= diff >> 2;
    diff |= diff >> 1;
    result = ~diff & 1;
    
    MEMORY_BARRIER();
    
    return (uint8_t)(-(int8_t)result); /* Sign extend: 0 -> 0x00, 1 -> 0xFF */
}

/*
 * Constant-time 32-bit equality check
 * Returns 0xFFFFFFFF if equal, 0x00000000 if different
 */
uint32_t arm_ct_eq_u32(uint32_t a, uint32_t b)
{
    volatile uint32_t diff = a ^ b;
    volatile uint32_t result;
    
    /* Convert 0 to 0xFFFFFFFF, any other value to 0x00000000 */
    diff |= diff >> 16;
    diff |= diff >> 8;
    diff |= diff >> 4;
    diff |= diff >> 2;
    diff |= diff >> 1;
    result = ~diff & 1;
    
    MEMORY_BARRIER();
    
    return (uint32_t)(-(int32_t)result); /* Sign extend */
}

/*
 * Constant-time less-than comparison for 32-bit values
 * Returns 0xFFFFFFFF if a < b, 0x00000000 otherwise
 */
uint32_t arm_ct_lt_u32(uint32_t a, uint32_t b)
{
    volatile uint32_t result;
    
    /* Compute (a - b) and check sign bit */
    /* This works for unsigned values when interpreted as signed */
    result = (uint32_t)((int32_t)(a - b) >> 31);
    
    MEMORY_BARRIER();
    
    return result;
}

/*
 * Constant-time greater-than comparison for 32-bit values  
 * Returns 0xFFFFFFFF if a > b, 0x00000000 otherwise
 */
uint32_t arm_ct_gt_u32(uint32_t a, uint32_t b)
{
    /* a > b is equivalent to b < a */
    return arm_ct_lt_u32(b, a);
}

/*
 * Constant-time minimum of two 32-bit values
 */
uint32_t arm_ct_min_u32(uint32_t a, uint32_t b)
{
    uint32_t mask = arm_ct_lt_u32(a, b);
    return arm_ct_select_u32(mask, a, b);
}

/*
 * Constant-time maximum of two 32-bit values
 */
uint32_t arm_ct_max_u32(uint32_t a, uint32_t b)
{
    uint32_t mask = arm_ct_gt_u32(a, b);
    return arm_ct_select_u32(mask, a, b);
}

/*
 * Constant-time array lookup
 * Selects array[index] in constant time, regardless of index value
 * If index >= array_len, returns 0
 */
uint8_t arm_ct_array_lookup_u8(const uint8_t* array, size_t array_len, size_t index)
{
    if (!array || array_len == 0) {
        return 0;
    }
    
    volatile uint8_t result = 0;
    
    /* Check each array position in constant time */
    for (size_t i = 0; i < array_len; i++) {
        uint32_t match = arm_ct_eq_u32((uint32_t)i, (uint32_t)index);
        uint8_t match_byte = (uint8_t)(match & 0xFF);
        result |= array[i] & match_byte;
    }
    
    MEMORY_BARRIER();
    
    return result;
}

/*
 * Constant-time bit counting (population count)
 * Counts the number of 1 bits in constant time
 */
uint32_t arm_ct_popcount_u32(uint32_t x)
{
    volatile uint32_t result = x;
    
    /* Brian Kernighan's algorithm adapted for constant time */
    /* Count bits using bit manipulation without branches */
    result = result - ((result >> 1) & 0x55555555);
    result = (result & 0x33333333) + ((result >> 2) & 0x33333333);
    result = (result + (result >> 4)) & 0x0F0F0F0F;
    result = result + (result >> 8);
    result = result + (result >> 16);
    
    MEMORY_BARRIER();
    
    return result & 0x3F; /* Mask to get count (max 32) */
}

/*
 * Constant-time leading zero count
 * Counts leading zeros in constant time
 */
uint32_t arm_ct_clz_u32(uint32_t x)
{
    if (x == 0) {
        return 32;
    }
    
    volatile uint32_t n = 0;
    volatile uint32_t temp = x;
    
    /* Binary search for first set bit */
    uint32_t mask;
    
    mask = arm_ct_eq_u32(temp & 0xFFFF0000, 0);
    n += arm_ct_select_u32(mask, 16, 0);
    temp = arm_ct_select_u32(mask, temp << 16, temp);
    
    mask = arm_ct_eq_u32(temp & 0xFF000000, 0);
    n += arm_ct_select_u32(mask, 8, 0);
    temp = arm_ct_select_u32(mask, temp << 8, temp);
    
    mask = arm_ct_eq_u32(temp & 0xF0000000, 0);
    n += arm_ct_select_u32(mask, 4, 0);
    temp = arm_ct_select_u32(mask, temp << 4, temp);
    
    mask = arm_ct_eq_u32(temp & 0xC0000000, 0);
    n += arm_ct_select_u32(mask, 2, 0);
    temp = arm_ct_select_u32(mask, temp << 2, temp);
    
    mask = arm_ct_eq_u32(temp & 0x80000000, 0);
    n += arm_ct_select_u32(mask, 1, 0);
    
    MEMORY_BARRIER();
    
    return n;
}
