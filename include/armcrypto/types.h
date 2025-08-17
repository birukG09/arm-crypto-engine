/*
 * Common types and definitions
 * ArmAsm-CryptoEngine - ARM Assembly Cryptography Library
 */

#ifndef ARMCRYPTO_TYPES_H
#define ARMCRYPTO_TYPES_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Library version */
#define ARMCRYPTO_VERSION_MAJOR 1
#define ARMCRYPTO_VERSION_MINOR 0
#define ARMCRYPTO_VERSION_PATCH 0

/* Error codes */
typedef enum {
    ARM_CRYPTO_SUCCESS = 0,
    ARM_CRYPTO_ERROR_INVALID_PARAM = -1,
    ARM_CRYPTO_ERROR_INVALID_KEY_SIZE = -2,
    ARM_CRYPTO_ERROR_INVALID_DATA_SIZE = -3,
    ARM_CRYPTO_ERROR_NOT_IMPLEMENTED = -4,
    ARM_CRYPTO_ERROR_INTERNAL = -5
} arm_crypto_result_t;

/* Platform detection */
#if defined(__ARM_ARCH_7M__) || defined(__ARM_ARCH_7EM__)
#define ARM_CORTEX_M4
#elif defined(__aarch64__)
#define ARM_CORTEX_A53
#endif

/* Compiler attributes */
#ifdef __GNUC__
#define ARM_CRYPTO_NOINLINE __attribute__((noinline))
#define ARM_CRYPTO_ALWAYS_INLINE __attribute__((always_inline))
#define ARM_CRYPTO_ALIGNED(x) __attribute__((aligned(x)))
#define ARM_CRYPTO_PACKED __attribute__((packed))
#else
#define ARM_CRYPTO_NOINLINE
#define ARM_CRYPTO_ALWAYS_INLINE
#define ARM_CRYPTO_ALIGNED(x)
#define ARM_CRYPTO_PACKED
#endif

/* Memory alignment macros */
#define ARM_CRYPTO_ALIGN_4 ARM_CRYPTO_ALIGNED(4)
#define ARM_CRYPTO_ALIGN_8 ARM_CRYPTO_ALIGNED(8)
#define ARM_CRYPTO_ALIGN_16 ARM_CRYPTO_ALIGNED(16)

/* Endianness handling */
#ifdef __BYTE_ORDER__
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define ARM_CRYPTO_BIG_ENDIAN
#elif __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define ARM_CRYPTO_LITTLE_ENDIAN
#endif
#endif

/* Byte order conversion */
#if defined(ARM_CRYPTO_LITTLE_ENDIAN)
#define ARM_CRYPTO_BE32(x) __builtin_bswap32(x)
#define ARM_CRYPTO_LE32(x) (x)
#elif defined(ARM_CRYPTO_BIG_ENDIAN)
#define ARM_CRYPTO_BE32(x) (x)
#define ARM_CRYPTO_LE32(x) __builtin_bswap32(x)
#else
/* Fallback - assume little endian */
#define ARM_CRYPTO_BE32(x) __builtin_bswap32(x)
#define ARM_CRYPTO_LE32(x) (x)
#endif

/* Memory barrier for constant-time operations */
#ifdef ARM_CORTEX_M4
#define ARM_CRYPTO_MEMORY_BARRIER() __asm__ __volatile__("dmb" ::: "memory")
#else
#define ARM_CRYPTO_MEMORY_BARRIER() __asm__ __volatile__("" ::: "memory")
#endif

/* Branch prediction hints */
#ifdef __GNUC__
#define ARM_CRYPTO_LIKELY(x) __builtin_expect(!!(x), 1)
#define ARM_CRYPTO_UNLIKELY(x) __builtin_expect(!!(x), 0)
#else
#define ARM_CRYPTO_LIKELY(x) (x)
#define ARM_CRYPTO_UNLIKELY(x) (x)
#endif

#ifdef __cplusplus
}
#endif

#endif /* ARMCRYPTO_TYPES_H */
