/*
 * AES Test Vectors
 * ArmAsm-CryptoEngine - NIST AES Test Vectors
 * 
 * Contains test vectors from NIST SP 800-38A and additional test cases
 */

#ifndef AES_VECTORS_H
#define AES_VECTORS_H

#include <stdint.h>
#include <stddef.h>

/* AES ECB Test Vector Structure */
typedef struct {
    const char* name;
    const char* key;
    size_t key_len;         /* Key length in bytes */
    const char* plaintext;
    const char* ciphertext;
} aes_ecb_vector_t;

/* AES CBC Test Vector Structure */
typedef struct {
    const char* name;
    const char* key;
    size_t key_len;
    const char* iv;
    const char* plaintext;
    const char* ciphertext;
    size_t data_len;        /* Data length in bytes */
} aes_cbc_vector_t;

/* AES CTR Test Vector Structure */
typedef struct {
    const char* name;
    const char* key;
    size_t key_len;
    const char* counter;
    const char* plaintext;
    const char* ciphertext;
    size_t data_len;
} aes_ctr_vector_t;

/* AES ECB Test Vectors (NIST SP 800-38A) */
static const aes_ecb_vector_t aes_ecb_vectors[] = {
    /* AES-128 ECB */
    {
        "AES128-ECB-1",
        "2b7e151628aed2a6abf7158809cf4f3c",
        16,
        "6bc1bee22e409f96e93d7e117393172a",
        "3ad77bb40d7a3660a89ecaf32466ef97"
    },
    {
        "AES128-ECB-2", 
        "2b7e151628aed2a6abf7158809cf4f3c",
        16,
        "ae2d8a571e03ac9c9eb76fac45af8e51",
        "f5d3d58503b9699de785895a96fdbaaf"
    },
    {
        "AES128-ECB-3",
        "2b7e151628aed2a6abf7158809cf4f3c", 
        16,
        "30c81c46a35ce411e5fbc1191a0a52ef",
        "43b1cd7f598ece23881b00e3ed030688"
    },
    {
        "AES128-ECB-4",
        "2b7e151628aed2a6abf7158809cf4f3c",
        16,
        "f69f2445df4f9b17ad2b417be66c3710",
        "7b0c785e27e8ad3f8223207104725dd4"
    },
    
    /* AES-192 ECB */
    {
        "AES192-ECB-1",
        "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
        24,
        "6bc1bee22e409f96e93d7e117393172a",
        "bd334f1d6e45f25ff712a214571fa5cc"
    },
    {
        "AES192-ECB-2",
        "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
        24,
        "ae2d8a571e03ac9c9eb76fac45af8e51",
        "974104846d0ad3ad7734ecb3ecee4eef"
    },
    {
        "AES192-ECB-3",
        "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
        24,
        "30c81c46a35ce411e5fbc1191a0a52ef",
        "ef7afd2270e2e60adce0ba2face6444e"
    },
    {
        "AES192-ECB-4",
        "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
        24,
        "f69f2445df4f9b17ad2b417be66c3710",
        "9a4b41ba738d6c72fb16691603c18e0e"
    },
    
    /* AES-256 ECB */
    {
        "AES256-ECB-1",
        "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
        32,
        "6bc1bee22e409f96e93d7e117393172a",
        "f3eed1bdb5d2a03c064b5a7e3db181f8"
    },
    {
        "AES256-ECB-2",
        "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
        32,
        "ae2d8a571e03ac9c9eb76fac45af8e51",
        "591ccb10d410ed26dc5ba74a31362870"
    },
    {
        "AES256-ECB-3",
        "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
        32,
        "30c81c46a35ce411e5fbc1191a0a52ef",
        "b6ed21b99ca6f4f9f153e7b1beafed1d"
    },
    {
        "AES256-ECB-4",
        "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
        32,
        "f69f2445df4f9b17ad2b417be66c3710",
        "23304b7a39f9f3ff067d8d8f9e24ecc7"
    }
};

#define AES_ECB_VECTOR_COUNT (sizeof(aes_ecb_vectors) / sizeof(aes_ecb_vectors[0]))

/* AES CBC Test Vectors (NIST SP 800-38A) */
static const aes_cbc_vector_t aes_cbc_vectors[] = {
    /* AES-128 CBC */
    {
        "AES128-CBC-1",
        "2b7e151628aed2a6abf7158809cf4f3c",
        16,
        "000102030405060708090a0b0c0d0e0f",
        "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
        "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b273bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7",
        64
    },
    
    /* AES-192 CBC */
    {
        "AES192-CBC-1", 
        "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
        24,
        "000102030405060708090a0b0c0d0e0f",
        "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
        "4f021db243bc633d7178183a9fa071e8b4d9ada9ad7dedf4e5e738763f69145a571b242012fb7ae07fa9baac3df102e008b0e27988598881d920a9e64f5615cd",
        64
    },
    
    /* AES-256 CBC */
    {
        "AES256-CBC-1",
        "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
        32,
        "000102030405060708090a0b0c0d0e0f",
        "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
        "f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d39f23369a9d9bacfa530e26304231461b2eb05e2c39be9fcda6c19078c6a9d1b",
        64
    }
};

#define AES_CBC_VECTOR_COUNT (sizeof(aes_cbc_vectors) / sizeof(aes_cbc_vectors[0]))

/* AES CTR Test Vectors (NIST SP 800-38A) */
static const aes_ctr_vector_t aes_ctr_vectors[] = {
    /* AES-128 CTR */
    {
        "AES128-CTR-1",
        "2b7e151628aed2a6abf7158809cf4f3c",
        16,
        "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
        "874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee",
        64
    },
    
    /* AES-192 CTR */
    {
        "AES192-CTR-1",
        "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
        24,
        "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
        "1abc932417521ca24f2b0459fe7e6e0b090339ec0aa6faefd5ccc2c6f4ce8e941e36b26bd1ebc670d1bd1d665620abf74f78a7f6d29809585a97daec58c6b050",
        64
    },
    
    /* AES-256 CTR */
    {
        "AES256-CTR-1",
        "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
        32,
        "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
        "601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c52b0930daa23de94ce87017ba2d84988ddfc9c58db67aada613c2dd08457941a6",
        64
    }
};

#define AES_CTR_VECTOR_COUNT (sizeof(aes_ctr_vectors) / sizeof(aes_ctr_vectors[0]))

/* Additional Edge Case Test Vectors */
static const aes_ecb_vector_t aes_edge_vectors[] = {
    /* All zeros key and data */
    {
        "AES128-ZERO",
        "00000000000000000000000000000000",
        16,
        "00000000000000000000000000000000",
        "66e94bd4ef8a2c3b884cfa59ca342b2e"
    },
    
    /* All ones key and data */
    {
        "AES128-ONES",
        "ffffffffffffffffffffffffffffffff",
        16,
        "ffffffffffffffffffffffffffffffff",
        "a1f6258c877d5fcd8964484538bfc92c"
    },
    
    /* Incremental pattern */
    {
        "AES128-INCREMENT",
        "000102030405060708090a0b0c0d0e0f",
        16,
        "00112233445566778899aabbccddeeff",
        "69c4e0d86a7b0430d8cdb78070b4c55a"
    },
    
    /* AES-256 with known weak keys (academic interest) */
    {
        "AES256-PATTERN",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        32,
        "fedcba9876543210fedcba9876543210",
        "0060bffe46834bb8da5cf9a61ff220ae"
    }
};

#define AES_EDGE_VECTOR_COUNT (sizeof(aes_edge_vectors) / sizeof(aes_edge_vectors[0]))

/* Key Schedule Test Vectors */
typedef struct {
    const char* name;
    const char* key;
    size_t key_len;
    const char* first_round_key;
    const char* last_round_key;
    int num_rounds;
} aes_key_schedule_vector_t;

static const aes_key_schedule_vector_t aes_key_schedule_vectors[] = {
    {
        "AES128-KeySchedule",
        "2b7e151628aed2a6abf7158809cf4f3c",
        16,
        "2b7e151628aed2a6abf7158809cf4f3c",  /* Round 0 (original key) */
        "b6630ca6d8ac42d5a73c7df65d6c7c5e",  /* Round 10 */
        10
    },
    {
        "AES192-KeySchedule", 
        "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
        24,
        "8e73b0f7da0e6452c810f32b809079e5",  /* First 16 bytes of round 0 */
        "01002202",                          /* Last 4 bytes of round 12 */
        12
    },
    {
        "AES256-KeySchedule",
        "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
        32,
        "603deb1015ca71be2b73aef0857d7781",  /* First 16 bytes of round 0 */
        "706c631e",                          /* Last 4 bytes of round 14 */
        14
    }
};

#define AES_KEY_SCHEDULE_VECTOR_COUNT (sizeof(aes_key_schedule_vectors) / sizeof(aes_key_schedule_vectors[0]))

#endif /* AES_VECTORS_H */
