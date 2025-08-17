/*
 * Constant-Time Utilities
 * ArmAsm-CryptoEngine - ARM Assembly Cryptography Library
 * 
 * Constant-time operations to prevent timing side-channel attacks
 */

#ifndef ARMCRYPTO_CT_H
#define ARMCRYPTO_CT_H

#include <stdint.h>
#include <stddef.h>
#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Constant-time memory comparison
 * Returns 0 if equal, non-zero if different
 * 
 * @param a   First buffer
 * @param b   Second buffer  
 * @param len Length to compare
 * @return 0 if equal, 1 if different
 */
uint32_t arm_ct_memcmp(const void* a, const void* b, size_t len);

/*
 * Constant-time memory XOR
 * Computes dst = src1 XOR src2
 * 
 * @param dst  Destination buffer
 * @param src1 First source buffer
 * @param src2 Second source buffer
 * @param len  Length to XOR
 */
void arm_ct_memxor(void* dst, const void* src1, const void* src2, size_t len);

/*
 * Constant-time conditional select
 * Returns a if condition is true (non-zero), b otherwise
 * 
 * @param condition Selection condition
 * @param a         Value if condition is true
 * @param b         Value if condition is false
 * @return Selected value
 */
uint32_t arm_ct_select_u32(uint32_t condition, uint32_t a, uint32_t b);

/*
 * Constant-time conditional copy
 * Copies src to dst if condition is true (non-zero)
 * 
 * @param condition Copy condition
 * @param dst       Destination buffer
 * @param src       Source buffer
 * @param len       Length to copy
 */
void arm_ct_conditional_copy(uint32_t condition, void* dst, const void* src, size_t len);

/*
 * Secure memory zeroization
 * Guaranteed to zero memory even with compiler optimizations
 * 
 * @param ptr Pointer to memory to zero
 * @param len Length to zero
 */
void arm_secure_zero(void* ptr, size_t len);

/*
 * Constant-time byte equality check
 * Returns 0xFF if a == b, 0x00 otherwise
 * 
 * @param a First byte
 * @param b Second byte
 * @return 0xFF if equal, 0x00 if different
 */
uint8_t arm_ct_eq_u8(uint8_t a, uint8_t b);

/*
 * Constant-time 32-bit equality check
 * Returns 0xFFFFFFFF if a == b, 0x00000000 otherwise
 * 
 * @param a First value
 * @param b Second value
 * @return 0xFFFFFFFF if equal, 0x00000000 if different
 */
uint32_t arm_ct_eq_u32(uint32_t a, uint32_t b);

/*
 * Constant-time less-than comparison
 * Returns 0xFFFFFFFF if a < b, 0x00000000 otherwise
 * 
 * @param a First value
 * @param b Second value
 * @return 0xFFFFFFFF if a < b, 0x00000000 otherwise
 */
uint32_t arm_ct_lt_u32(uint32_t a, uint32_t b);

/*
 * Constant-time greater-than comparison
 * Returns 0xFFFFFFFF if a > b, 0x00000000 otherwise
 * 
 * @param a First value
 * @param b Second value
 * @return 0xFFFFFFFF if a > b, 0x00000000 otherwise
 */
uint32_t arm_ct_gt_u32(uint32_t a, uint32_t b);

#ifdef __cplusplus
}
#endif

#endif /* ARMCRYPTO_CT_H */
