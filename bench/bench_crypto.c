/*
 * Cryptographic Benchmarking Suite
 * ArmAsm-CryptoEngine - Performance measurement and analysis
 * 
 * Comprehensive benchmarking of AES and SHA-256 implementations
 * with cycle-accurate timing and throughput analysis
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>

#include "armcrypto/aes.h"
#include "armcrypto/sha256.h"
#include "armcrypto/ct.h"
#include "platform.h"

/* Benchmark configuration */
#define BENCH_MIN_ITERATIONS 100
#define BENCH_MIN_TIME_MS 1000    /* Minimum benchmark time */
#define BENCH_WARMUP_ITERATIONS 10
#define BENCH_MAX_DATA_SIZE (1024 * 1024)  /* 1 MB max test size */

/* Test data sizes */
static const size_t test_sizes[] = {
    16, 64, 256, 1024, 4096, 16384, 65536, 262144, 1048576
};
static const int num_test_sizes = sizeof(test_sizes) / sizeof(test_sizes[0]);

/* Benchmark results structure */
typedef struct {
    const char* name;
    size_t data_size;
    uint64_t iterations;
    platform_cycles_t cycles_total;
    platform_cycles_t cycles_per_byte;
    double mb_per_sec;
    double operations_per_sec;
} bench_result_t;

/* Global benchmark results */
static bench_result_t bench_results[256];
static int bench_result_count = 0;

/*
 * Add benchmark result
 */
static void add_result(const char* name, size_t data_size, uint64_t iterations, 
                      platform_cycles_t cycles)
{
    if (bench_result_count >= 256) return;
    
    bench_result_t* result = &bench_results[bench_result_count++];
    result->name = name;
    result->data_size = data_size;
    result->iterations = iterations;
    result->cycles_total = cycles;
    
    if (data_size > 0) {
        result->cycles_per_byte = cycles / (iterations * data_size);
        uint32_t clock_freq = platform_get_clock_freq();
        double seconds = (double)cycles / clock_freq;
        double bytes_per_sec = (iterations * data_size) / seconds;
        result->mb_per_sec = bytes_per_sec / (1024.0 * 1024.0);
        result->operations_per_sec = iterations / seconds;
    } else {
        result->cycles_per_byte = 0;
        result->mb_per_sec = 0;
        result->operations_per_sec = 0;
    }
}

/*
 * Benchmark AES key schedule
 */
static void bench_aes_key_schedule(void)
{
    printf("Benchmarking AES Key Schedule...\n");
    
    uint8_t key[32];
    uint32_t round_keys[60];
    size_t key_sizes[] = {128, 192, 256};
    
    /* Fill key with pattern */
    for (int i = 0; i < 32; i++) {
        key[i] = (uint8_t)i;
    }
    
    for (int ks = 0; ks < 3; ks++) {
        size_t keybits = key_sizes[ks];
        char name[64];
        snprintf(name, sizeof(name), "AES%zu-KeySchedule", keybits);
        
        /* Warmup */
        for (int i = 0; i < BENCH_WARMUP_ITERATIONS; i++) {
            arm_aes_key_schedule(key, round_keys, keybits);
        }
        
        /* Benchmark */
        platform_cycles_t start = platform_cycles_get();
        uint64_t iterations = 0;
        
        do {
            for (int i = 0; i < BENCH_MIN_ITERATIONS; i++) {
                arm_aes_key_schedule(key, round_keys, keybits);
                iterations++;
            }
        } while (platform_cycles_to_us(platform_cycles_elapsed(start, platform_cycles_get())) < BENCH_MIN_TIME_MS * 1000);
        
        platform_cycles_t end = platform_cycles_get();
        platform_cycles_t cycles = platform_cycles_elapsed(start, end);
        
        add_result(name, 0, iterations, cycles);
        
        /* Clear sensitive data */
        arm_secure_zero(round_keys, sizeof(round_keys));
    }
}

/*
 * Benchmark AES ECB mode
 */
static void bench_aes_ecb(void)
{
    printf("Benchmarking AES ECB...\n");
    
    arm_aes_ctx ctx;
    uint8_t key[32] = {0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
                       0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                       0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
                       0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
    
    size_t key_sizes[] = {128, 192, 256};
    
    for (int ks = 0; ks < 3; ks++) {
        size_t keybits = key_sizes[ks];
        arm_aes_init(&ctx, key, keybits);
        
        for (int ts = 0; ts < num_test_sizes; ts++) {
            size_t size = test_sizes[ts];
            if (size % 16 != 0) continue;  /* ECB requires block alignment */
            
            uint8_t* plaintext = malloc(size);
            uint8_t* ciphertext = malloc(size);
            
            if (!plaintext || !ciphertext) {
                free(plaintext);
                free(ciphertext);
                continue;
            }
            
            /* Fill with pattern */
            for (size_t i = 0; i < size; i++) {
                plaintext[i] = (uint8_t)(i & 0xFF);
            }
            
            /* Benchmark encryption */
            char name[64];
            snprintf(name, sizeof(name), "AES%zu-ECB-Encrypt", keybits);
            
            /* Warmup */
            for (int i = 0; i < BENCH_WARMUP_ITERATIONS; i++) {
                for (size_t j = 0; j < size; j += 16) {
                    arm_aes_ecb_encrypt(&ctx, &plaintext[j], &ciphertext[j]);
                }
            }
            
            /* Benchmark */
            platform_cycles_t start = platform_cycles_get();
            uint64_t iterations = 0;
            
            do {
                for (int i = 0; i < BENCH_MIN_ITERATIONS; i++) {
                    for (size_t j = 0; j < size; j += 16) {
                        arm_aes_ecb_encrypt(&ctx, &plaintext[j], &ciphertext[j]);
                    }
                    iterations++;
                }
            } while (platform_cycles_to_us(platform_cycles_elapsed(start, platform_cycles_get())) < BENCH_MIN_TIME_MS * 1000);
            
            platform_cycles_t end = platform_cycles_get();
            platform_cycles_t cycles = platform_cycles_elapsed(start, end);
            
            add_result(name, size, iterations, cycles);
            
            /* Benchmark decryption */
            snprintf(name, sizeof(name), "AES%zu-ECB-Decrypt", keybits);
            
            /* Warmup */
            for (int i = 0; i < BENCH_WARMUP_ITERATIONS; i++) {
                for (size_t j = 0; j < size; j += 16) {
                    arm_aes_ecb_decrypt(&ctx, &ciphertext[j], &plaintext[j]);
                }
            }
            
            /* Benchmark */
            start = platform_cycles_get();
            iterations = 0;
            
            do {
                for (int i = 0; i < BENCH_MIN_ITERATIONS; i++) {
                    for (size_t j = 0; j < size; j += 16) {
                        arm_aes_ecb_decrypt(&ctx, &ciphertext[j], &plaintext[j]);
                    }
                    iterations++;
                }
            } while (platform_cycles_to_us(platform_cycles_elapsed(start, platform_cycles_get())) < BENCH_MIN_TIME_MS * 1000);
            
            end = platform_cycles_get();
            cycles = platform_cycles_elapsed(start, end);
            
            add_result(name, size, iterations, cycles);
            
            free(plaintext);
            free(ciphertext);
        }
        
        arm_aes_clear(&ctx);
    }
}

/*
 * Benchmark AES CBC mode
 */
static void bench_aes_cbc(void)
{
    printf("Benchmarking AES CBC...\n");
    
    arm_aes_ctx ctx;
    uint8_t key[32] = {0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
                       0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                       0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
                       0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
    uint8_t iv[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                      0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
    
    arm_aes_init(&ctx, key, 128);  /* Test with AES-128 only for CBC */
    
    for (int ts = 0; ts < num_test_sizes; ts++) {
        size_t size = test_sizes[ts];
        if (size % 16 != 0) continue;  /* CBC requires block alignment */
        
        uint8_t* plaintext = malloc(size);
        uint8_t* ciphertext = malloc(size);
        uint8_t test_iv[16];
        
        if (!plaintext || !ciphertext) {
            free(plaintext);
            free(ciphertext);
            continue;
        }
        
        /* Fill with pattern */
        for (size_t i = 0; i < size; i++) {
            plaintext[i] = (uint8_t)(i & 0xFF);
        }
        
        /* Benchmark encryption */
        memcpy(test_iv, iv, 16);
        
        /* Warmup */
        for (int i = 0; i < BENCH_WARMUP_ITERATIONS; i++) {
            memcpy(test_iv, iv, 16);
            arm_aes_cbc_encrypt(&ctx, test_iv, plaintext, ciphertext, size);
        }
        
        /* Benchmark */
        platform_cycles_t start = platform_cycles_get();
        uint64_t iterations = 0;
        
        do {
            for (int i = 0; i < BENCH_MIN_ITERATIONS; i++) {
                memcpy(test_iv, iv, 16);
                arm_aes_cbc_encrypt(&ctx, test_iv, plaintext, ciphertext, size);
                iterations++;
            }
        } while (platform_cycles_to_us(platform_cycles_elapsed(start, platform_cycles_get())) < BENCH_MIN_TIME_MS * 1000);
        
        platform_cycles_t end = platform_cycles_get();
        platform_cycles_t cycles = platform_cycles_elapsed(start, end);
        
        add_result("AES128-CBC-Encrypt", size, iterations, cycles);
        
        /* Benchmark decryption */
        start = platform_cycles_get();
        iterations = 0;
        
        do {
            for (int i = 0; i < BENCH_MIN_ITERATIONS; i++) {
                memcpy(test_iv, iv, 16);
                arm_aes_cbc_decrypt(&ctx, test_iv, ciphertext, plaintext, size);
                iterations++;
            }
        } while (platform_cycles_to_us(platform_cycles_elapsed(start, platform_cycles_get())) < BENCH_MIN_TIME_MS * 1000);
        
        end = platform_cycles_get();
        cycles = platform_cycles_elapsed(start, end);
        
        add_result("AES128-CBC-Decrypt", size, iterations, cycles);
        
        free(plaintext);
        free(ciphertext);
    }
    
    arm_aes_clear(&ctx);
}

/*
 * Benchmark AES CTR mode
 */
static void bench_aes_ctr(void)
{
    printf("Benchmarking AES CTR...\n");
    
    arm_aes_ctx ctx;
    uint8_t key[32] = {0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
                       0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                       0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
                       0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
    uint8_t nonce[16] = {0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7,
                         0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF};
    
    arm_aes_init(&ctx, key, 128);  /* Test with AES-128 only for CTR */
    
    for (int ts = 0; ts < num_test_sizes; ts++) {
        size_t size = test_sizes[ts];
        
        uint8_t* plaintext = malloc(size);
        uint8_t* ciphertext = malloc(size);
        uint8_t test_nonce[16];
        
        if (!plaintext || !ciphertext) {
            free(plaintext);
            free(ciphertext);
            continue;
        }
        
        /* Fill with pattern */
        for (size_t i = 0; i < size; i++) {
            plaintext[i] = (uint8_t)(i & 0xFF);
        }
        
        /* Warmup */
        for (int i = 0; i < BENCH_WARMUP_ITERATIONS; i++) {
            memcpy(test_nonce, nonce, 16);
            arm_aes_ctr_crypt(&ctx, test_nonce, plaintext, ciphertext, size);
        }
        
        /* Benchmark */
        platform_cycles_t start = platform_cycles_get();
        uint64_t iterations = 0;
        
        do {
            for (int i = 0; i < BENCH_MIN_ITERATIONS; i++) {
                memcpy(test_nonce, nonce, 16);
                arm_aes_ctr_crypt(&ctx, test_nonce, plaintext, ciphertext, size);
                iterations++;
            }
        } while (platform_cycles_to_us(platform_cycles_elapsed(start, platform_cycles_get())) < BENCH_MIN_TIME_MS * 1000);
        
        platform_cycles_t end = platform_cycles_get();
        platform_cycles_t cycles = platform_cycles_elapsed(start, end);
        
        add_result("AES128-CTR-Crypt", size, iterations, cycles);
        
        free(plaintext);
        free(ciphertext);
    }
    
    arm_aes_clear(&ctx);
}

/*
 * Benchmark SHA-256
 */
static void bench_sha256(void)
{
    printf("Benchmarking SHA-256...\n");
    
    for (int ts = 0; ts < num_test_sizes; ts++) {
        size_t size = test_sizes[ts];
        
        uint8_t* data = malloc(size);
        uint8_t hash[32];
        
        if (!data) continue;
        
        /* Fill with pattern */
        for (size_t i = 0; i < size; i++) {
            data[i] = (uint8_t)(i & 0xFF);
        }
        
        /* Warmup */
        for (int i = 0; i < BENCH_WARMUP_ITERATIONS; i++) {
            arm_sha256_hash(data, size, hash);
        }
        
        /* Benchmark */
        platform_cycles_t start = platform_cycles_get();
        uint64_t iterations = 0;
        
        do {
            for (int i = 0; i < BENCH_MIN_ITERATIONS; i++) {
                arm_sha256_hash(data, size, hash);
                iterations++;
            }
        } while (platform_cycles_to_us(platform_cycles_elapsed(start, platform_cycles_get())) < BENCH_MIN_TIME_MS * 1000);
        
        platform_cycles_t end = platform_cycles_get();
        platform_cycles_t cycles = platform_cycles_elapsed(start, end);
        
        add_result("SHA256", size, iterations, cycles);
        
        free(data);
    }
}

/*
 * Benchmark HMAC-SHA256
 */
static void bench_hmac_sha256(void)
{
    printf("Benchmarking HMAC-SHA256...\n");
    
    uint8_t key[32] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                       0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
                       0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
                       0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20};
    
    for (int ts = 0; ts < num_test_sizes; ts++) {
        size_t size = test_sizes[ts];
        
        uint8_t* data = malloc(size);
        uint8_t mac[32];
        
        if (!data) continue;
        
        /* Fill with pattern */
        for (size_t i = 0; i < size; i++) {
            data[i] = (uint8_t)(i & 0xFF);
        }
        
        /* Warmup */
        for (int i = 0; i < BENCH_WARMUP_ITERATIONS; i++) {
            arm_hmac_sha256(key, 32, data, size, mac);
        }
        
        /* Benchmark */
        platform_cycles_t start = platform_cycles_get();
        uint64_t iterations = 0;
        
        do {
            for (int i = 0; i < BENCH_MIN_ITERATIONS; i++) {
                arm_hmac_sha256(key, 32, data, size, mac);
                iterations++;
            }
        } while (platform_cycles_to_us(platform_cycles_elapsed(start, platform_cycles_get())) < BENCH_MIN_TIME_MS * 1000);
        
        platform_cycles_t end = platform_cycles_get();
        platform_cycles_t cycles = platform_cycles_elapsed(start, end);
        
        add_result("HMAC-SHA256", size, iterations, cycles);
        
        free(data);
    }
}

/*
 * Print benchmark results
 */
static void print_results(void)
{
    printf("\n=== Benchmark Results ===\n");
    printf("Platform: %s\n", platform_get_info_string());
    printf("Clock Frequency: %u MHz\n", platform_get_clock_freq() / 1000000);
    printf("\n");
    
    printf("%-25s %8s %12s %12s %12s %15s\n", 
           "Operation", "Size", "Iterations", "Cycles/Byte", "MB/s", "Ops/s");
    printf("%-25s %8s %12s %12s %12s %15s\n",
           "-------------------------", "--------", "------------", "------------", "------------", "---------------");
    
    for (int i = 0; i < bench_result_count; i++) {
        bench_result_t* r = &bench_results[i];
        
        if (r->data_size > 0) {
            printf("%-25s %8zu %12llu %12llu %12.2f %15.0f\n",
                   r->name, r->data_size, (unsigned long long)r->iterations,
                   (unsigned long long)r->cycles_per_byte, r->mb_per_sec, r->operations_per_sec);
        } else {
            printf("%-25s %8s %12llu %12s %12s %15.0f\n",
                   r->name, "N/A", (unsigned long long)r->iterations,
                   "N/A", "N/A", r->operations_per_sec);
        }
    }
    
    printf("\n");
}

/*
 * Generate performance report
 */
static void generate_report(void)
{
    FILE* fp = fopen("benchmark_report.csv", "w");
    if (!fp) {
        printf("Failed to create benchmark report file\n");
        return;
    }
    
    fprintf(fp, "Operation,Size,Iterations,Total_Cycles,Cycles_Per_Byte,MB_Per_Sec,Ops_Per_Sec\n");
    
    for (int i = 0; i < bench_result_count; i++) {
        bench_result_t* r = &bench_results[i];
        fprintf(fp, "%s,%zu,%llu,%llu,%llu,%.2f,%.0f\n",
                r->name, r->data_size, (unsigned long long)r->iterations,
                (unsigned long long)r->cycles_total,
                (unsigned long long)r->cycles_per_byte,
                r->mb_per_sec, r->operations_per_sec);
    }
    
    fclose(fp);
    printf("Benchmark report saved to benchmark_report.csv\n");
}

/*
 * Main benchmark function
 */
int main(int argc, char** argv)
{
    printf("ArmAsm-CryptoEngine Benchmark Suite\n");
    printf("====================================\n\n");
    
    /* Initialize platform */
    if (platform_init() != PLATFORM_SUCCESS) {
        printf("Failed to initialize platform\n");
        return 1;
    }
    
    /* Initialize cycle counter */
    if (platform_cycles_init() != PLATFORM_SUCCESS) {
        printf("Failed to initialize cycle counter\n");
        return 1;
    }
    
    printf("Initializing benchmarks...\n");
    printf("Minimum benchmark time: %d ms\n", BENCH_MIN_TIME_MS);
    printf("Warmup iterations: %d\n\n", BENCH_WARMUP_ITERATIONS);
    
    /* Run benchmarks */
    bench_aes_key_schedule();
    bench_aes_ecb();
    bench_aes_cbc();
    bench_aes_ctr();
    bench_sha256();
    bench_hmac_sha256();
    
    /* Print and save results */
    print_results();
    generate_report();
    
    printf("Benchmark completed successfully!\n");
    
    /* Cleanup */
#ifdef PLATFORM_RPI
    platform_cleanup();
#endif
    
    return 0;
}
