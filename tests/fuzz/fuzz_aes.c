/*
 * AES Fuzzing Test
 * ArmAsm-CryptoEngine - Fuzz Testing for AES Implementation
 * 
 * Uses libFuzzer to test AES functions with random inputs
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <assert.h>
#include "armcrypto/aes.h"
#include "armcrypto/ct.h"

/* Minimum input size for meaningful fuzzing */
#define MIN_FUZZ_SIZE 32   /* Key (16) + plaintext (16) */
#define MAX_FUZZ_SIZE 8192 /* Reasonable upper limit */

/*
 * Fuzz input structure
 */
typedef struct {
    uint8_t key_size;       /* 0=128, 1=192, 2=256 */
    uint8_t mode;          /* 0=ECB, 1=CBC, 2=CTR */
    uint8_t operation;     /* 0=encrypt, 1=decrypt, 2=roundtrip */
    uint8_t reserved;      /* Padding */
    uint8_t key[32];       /* AES key (up to 256 bits) */
    uint8_t iv[16];        /* IV for CBC/CTR modes */
    uint8_t data[];        /* Variable length data */
} fuzz_input_t;

/*
 * Validate fuzz input
 */
static int validate_input(const uint8_t* data, size_t size)
{
    if (size < sizeof(fuzz_input_t) + 16) {
        return 0; /* Too small */
    }
    
    if (size > MAX_FUZZ_SIZE) {
        return 0; /* Too large */
    }
    
    const fuzz_input_t* input = (const fuzz_input_t*)data;
    size_t data_len = size - sizeof(fuzz_input_t);
    
    /* Validate key size */
    if (input->key_size > 2) {
        return 0;
    }
    
    /* Validate mode */
    if (input->mode > 2) {
        return 0;
    }
    
    /* Validate operation */
    if (input->operation > 2) {
        return 0;
    }
    
    /* For CBC mode, data must be multiple of 16 bytes */
    if (input->mode == 1 && (data_len % 16) != 0) {
        return 0;
    }
    
    return 1;
}

/*
 * Test AES ECB mode
 */
static void fuzz_aes_ecb(const fuzz_input_t* input, size_t data_len)
{
    arm_aes_ctx ctx;
    uint8_t* output = malloc(data_len);
    uint8_t* verify = malloc(data_len);
    
    if (!output || !verify) {
        free(output);
        free(verify);
        return;
    }
    
    /* Map key size */
    size_t key_bits[] = {128, 192, 256};
    size_t keybits = key_bits[input->key_size];
    
    /* Initialize AES context */
    arm_aes_init(&ctx, input->key, keybits);
    
    if (input->operation == 0 || input->operation == 2) {
        /* Test encryption */
        for (size_t i = 0; i < data_len; i += 16) {
            arm_aes_ecb_encrypt(&ctx, &input->data[i], &output[i]);
        }
        
        /* Verify encrypted data is different (unless all zeros) */
        int all_zero = 1;
        for (size_t i = 0; i < data_len; i++) {
            if (input->data[i] != 0) {
                all_zero = 0;
                break;
            }
        }
        
        if (!all_zero) {
            assert(arm_ct_memcmp(input->data, output, data_len) != 0);
        }
    }
    
    if (input->operation == 1 || input->operation == 2) {
        /* Test decryption */
        const uint8_t* decrypt_input = (input->operation == 2) ? output : input->data;
        
        for (size_t i = 0; i < data_len; i += 16) {
            arm_aes_ecb_decrypt(&ctx, &decrypt_input[i], &verify[i]);
        }
        
        /* For roundtrip, verify we get original data back */
        if (input->operation == 2) {
            assert(arm_ct_memcmp(input->data, verify, data_len) == 0);
        }
    }
    
    /* Test context clearing */
    arm_aes_clear(&ctx);
    
    /* Verify context is cleared */
    uint8_t zero_keys[sizeof(ctx.round_keys)];
    memset(zero_keys, 0, sizeof(zero_keys));
    assert(memcmp(ctx.round_keys, zero_keys, sizeof(zero_keys)) == 0);
    
    free(output);
    free(verify);
}

/*
 * Test AES CBC mode
 */
static void fuzz_aes_cbc(const fuzz_input_t* input, size_t data_len)
{
    arm_aes_ctx ctx;
    uint8_t* output = malloc(data_len);
    uint8_t* verify = malloc(data_len);
    uint8_t iv_encrypt[16], iv_decrypt[16];
    
    if (!output || !verify) {
        free(output);
        free(verify);
        return;
    }
    
    size_t key_bits[] = {128, 192, 256};
    size_t keybits = key_bits[input->key_size];
    
    arm_aes_init(&ctx, input->key, keybits);
    
    if (input->operation == 0 || input->operation == 2) {
        /* Test encryption */
        memcpy(iv_encrypt, input->iv, 16);
        arm_aes_cbc_encrypt(&ctx, iv_encrypt, input->data, output, data_len);
        
        /* Verify encrypted data is different */
        int all_zero = 1;
        for (size_t i = 0; i < data_len; i++) {
            if (input->data[i] != 0) {
                all_zero = 0;
                break;
            }
        }
        
        if (!all_zero) {
            assert(arm_ct_memcmp(input->data, output, data_len) != 0);
        }
    }
    
    if (input->operation == 1 || input->operation == 2) {
        /* Test decryption */
        const uint8_t* decrypt_input = (input->operation == 2) ? output : input->data;
        memcpy(iv_decrypt, input->iv, 16);
        arm_aes_cbc_decrypt(&ctx, iv_decrypt, decrypt_input, verify, data_len);
        
        /* For roundtrip, verify we get original data back */
        if (input->operation == 2) {
            assert(arm_ct_memcmp(input->data, verify, data_len) == 0);
        }
    }
    
    arm_aes_clear(&ctx);
    free(output);
    free(verify);
}

/*
 * Test AES CTR mode
 */
static void fuzz_aes_ctr(const fuzz_input_t* input, size_t data_len)
{
    arm_aes_ctx ctx;
    uint8_t* output = malloc(data_len);
    uint8_t* verify = malloc(data_len);
    uint8_t nonce_encrypt[16], nonce_decrypt[16];
    
    if (!output || !verify) {
        free(output);
        free(verify);
        return;
    }
    
    size_t key_bits[] = {128, 192, 256};
    size_t keybits = key_bits[input->key_size];
    
    arm_aes_init(&ctx, input->key, keybits);
    
    if (input->operation == 0 || input->operation == 2) {
        /* Test encryption */
        memcpy(nonce_encrypt, input->iv, 16);
        arm_aes_ctr_crypt(&ctx, nonce_encrypt, input->data, output, data_len);
        
        /* Verify encrypted data is different (unless all zeros) */
        int all_zero = 1;
        for (size_t i = 0; i < data_len; i++) {
            if (input->data[i] != 0) {
                all_zero = 0;
                break;
            }
        }
        
        if (!all_zero) {
            assert(arm_ct_memcmp(input->data, output, data_len) != 0);
        }
    }
    
    if (input->operation == 1 || input->operation == 2) {
        /* Test decryption (CTR is symmetric) */
        const uint8_t* decrypt_input = (input->operation == 2) ? output : input->data;
        memcpy(nonce_decrypt, input->iv, 16);
        arm_aes_ctr_crypt(&ctx, nonce_decrypt, decrypt_input, verify, data_len);
        
        /* For roundtrip, verify we get original data back */
        if (input->operation == 2) {
            assert(arm_ct_memcmp(input->data, verify, data_len) == 0);
        }
    }
    
    arm_aes_clear(&ctx);
    free(output);
    free(verify);
}

/*
 * Test key schedule specifically
 */
static void fuzz_key_schedule(const fuzz_input_t* input)
{
    uint32_t round_keys1[60];  /* Max for AES-256 */
    uint32_t round_keys2[60];
    
    size_t key_bits[] = {128, 192, 256};
    size_t keybits = key_bits[input->key_size];
    
    /* Test key schedule twice with same key */
    arm_aes_key_schedule(input->key, round_keys1, keybits);
    arm_aes_key_schedule(input->key, round_keys2, keybits);
    
    /* Results should be identical */
    size_t key_words = (keybits == 128) ? 44 : (keybits == 192) ? 52 : 60;
    assert(memcmp(round_keys1, round_keys2, key_words * sizeof(uint32_t)) == 0);
    
    /* First round key should match original key */
    assert(memcmp(round_keys1, input->key, keybits / 8) == 0);
    
    /* Clear sensitive data */
    arm_secure_zero(round_keys1, sizeof(round_keys1));
    arm_secure_zero(round_keys2, sizeof(round_keys2));
}

/*
 * Test block encrypt/decrypt functions directly
 */
static void fuzz_block_functions(const fuzz_input_t* input)
{
    uint32_t round_keys[60];
    uint8_t ciphertext[16], result[16];
    
    size_t key_bits[] = {128, 192, 256};
    size_t keybits = key_bits[input->key_size];
    uint8_t nr = (keybits == 128) ? 10 : (keybits == 192) ? 12 : 14;
    
    /* Generate round keys */
    arm_aes_key_schedule(input->key, round_keys, keybits);
    
    /* Test block functions */
    arm_aes_encrypt_block(round_keys, nr, input->data, ciphertext);
    arm_aes_decrypt_block(round_keys, nr, ciphertext, result);
    
    /* Should get original data back */
    assert(arm_ct_memcmp(input->data, result, 16) == 0);
    
    arm_secure_zero(round_keys, sizeof(round_keys));
}

/*
 * Main fuzzing entry point
 */
int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Validate input */
    if (!validate_input(data, size)) {
        return 0;
    }
    
    const fuzz_input_t* input = (const fuzz_input_t*)data;
    size_t data_len = size - sizeof(fuzz_input_t);
    
    /* Align data length to 16 bytes for block modes */
    if (input->mode == 1) {  /* CBC */
        data_len = (data_len / 16) * 16;
    }
    
    if (data_len == 0) {
        return 0;
    }
    
    /* Test specific key schedule */
    fuzz_key_schedule(input);
    
    /* Test block functions if we have at least one block */
    if (data_len >= 16) {
        fuzz_block_functions(input);
    }
    
    /* Test the requested mode */
    switch (input->mode) {
        case 0: /* ECB */
            if (data_len >= 16) {
                size_t aligned_len = (data_len / 16) * 16;
                fuzz_aes_ecb(input, aligned_len);
            }
            break;
            
        case 1: /* CBC */
            if (data_len >= 16) {
                fuzz_aes_cbc(input, data_len);
            }
            break;
            
        case 2: /* CTR */
            if (data_len > 0) {
                fuzz_aes_ctr(input, data_len);
            }
            break;
    }
    
    return 0;
}

#ifdef FUZZ_STANDALONE
/*
 * Standalone fuzzing for testing without libFuzzer
 */
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main(int argc, char** argv)
{
    if (argc != 2) {
        printf("Usage: %s <test_file>\n", argv[0]);
        return 1;
    }
    
    FILE* fp = fopen(argv[1], "rb");
    if (!fp) {
        perror("Failed to open test file");
        return 1;
    }
    
    fseek(fp, 0, SEEK_END);
    size_t size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    uint8_t* data = malloc(size);
    if (!data) {
        fclose(fp);
        return 1;
    }
    
    size_t read_size = fread(data, 1, size, fp);
    fclose(fp);
    
    if (read_size != size) {
        printf("Failed to read entire file\n");
        free(data);
        return 1;
    }
    
    printf("Testing with %zu bytes of data\n", size);
    int result = LLVMFuzzerTestOneInput(data, size);
    
    free(data);
    printf("Fuzzing test completed successfully\n");
    return result;
}
#endif /* FUZZ_STANDALONE */
