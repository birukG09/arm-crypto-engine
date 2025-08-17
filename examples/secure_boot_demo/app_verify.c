/*
 * Application Verification Implementation
 * ArmAsm-CryptoEngine - Secure Boot Application Verification
 */

#include "app_verify.h"
#include "armcrypto/sha256.h"
#include "armcrypto/ct.h"
#include "platform.h"
#include <string.h>

/* Global HMAC key for verification */
static uint8_t g_hmac_key[APP_VERIFY_KEY_SIZE];
static int g_initialized = 0;

/* Platform-specific memory regions */
#ifdef STM32F4
#define FLASH_BASE_ADDR     0x08000000
#define FLASH_SIZE          (1024 * 1024)
#define SRAM_BASE_ADDR      0x20000000
#define SRAM_SIZE           (128 * 1024)
#define VALID_ENTRY_MASK    0x00000001  /* Thumb mode bit */
#else
/* Generic ARM settings */
#define FLASH_BASE_ADDR     0x00000000
#define FLASH_SIZE          (16 * 1024 * 1024)
#define SRAM_BASE_ADDR      0x10000000
#define SRAM_SIZE           (1024 * 1024)
#define VALID_ENTRY_MASK    0x00000001
#endif

/*
 * Initialize application verification system
 */
app_verify_result_t app_verify_init(const uint8_t hmac_key[32])
{
    if (!hmac_key) {
        return APP_VERIFY_ERROR_INVALID_PARAM;
    }
    
    /* Copy HMAC key */
    memcpy(g_hmac_key, hmac_key, APP_VERIFY_KEY_SIZE);
    g_initialized = 1;
    
    return APP_VERIFY_SUCCESS;
}

/*
 * Cleanup verification system
 */
void app_verify_cleanup(void)
{
    if (g_initialized) {
        arm_secure_zero(g_hmac_key, sizeof(g_hmac_key));
        g_initialized = 0;
    }
}

/*
 * Validate application header
 */
app_verify_result_t app_verify_validate_header(const app_header_t* header)
{
    if (!header) {
        return APP_VERIFY_ERROR_INVALID_PARAM;
    }
    
    /* Check magic bytes */
    if (memcmp(header->magic, APP_VERIFY_MAGIC, 7) != 0 || header->magic[7] != 0) {
        return APP_VERIFY_ERROR_INVALID_HEADER;
    }
    
    /* Check version */
    if (header->version != APP_VERIFY_VERSION) {
        return APP_VERIFY_ERROR_INVALID_HEADER;
    }
    
    /* Check application size */
    if (header->app_size == 0 || header->app_size > APP_VERIFY_MAX_APP_SIZE) {
        return APP_VERIFY_ERROR_INVALID_SIZE;
    }
    
    /* Validate memory regions */
    if (!app_verify_is_valid_load_region(header->load_address, header->app_size)) {
        return APP_VERIFY_ERROR_INVALID_HEADER;
    }
    
    if (!app_verify_is_valid_entry_point(header->app_entry)) {
        return APP_VERIFY_ERROR_INVALID_HEADER;
    }
    
    return APP_VERIFY_SUCCESS;
}

/*
 * Calculate application signature
 */
void app_verify_calculate_signature(const app_header_t* header,
                                   const uint8_t* app_data,
                                   size_t app_size,
                                   uint8_t signature[32])
{
    arm_hmac_sha256_ctx hmac_ctx;
    
    /* Initialize HMAC with global key */
    arm_hmac_sha256_init(&hmac_ctx, g_hmac_key, APP_VERIFY_KEY_SIZE);
    
    /* Include header fields (excluding signature) */
    arm_hmac_sha256_update(&hmac_ctx, (const uint8_t*)header->magic, 8);
    arm_hmac_sha256_update(&hmac_ctx, (const uint8_t*)&header->version, 4);
    arm_hmac_sha256_update(&hmac_ctx, (const uint8_t*)&header->app_size, 4);
    arm_hmac_sha256_update(&hmac_ctx, (const uint8_t*)&header->app_entry, 4);
    arm_hmac_sha256_update(&hmac_ctx, (const uint8_t*)&header->load_address, 4);
    arm_hmac_sha256_update(&hmac_ctx, (const uint8_t*)&header->flags, 4);
    
    /* Include application data */
    arm_hmac_sha256_update(&hmac_ctx, app_data, app_size);
    
    /* Finalize signature */
    arm_hmac_sha256_final(&hmac_ctx, signature);
    arm_hmac_sha256_clear(&hmac_ctx);
}

/*
 * Verify application image in memory
 */
app_verify_result_t app_verify_image(const uint8_t* app_image, 
                                    size_t image_size,
                                    app_info_t* app_info)
{
    if (!g_initialized) {
        return APP_VERIFY_ERROR_INVALID_PARAM;
    }
    
    if (!app_image || image_size < sizeof(app_header_t)) {
        return APP_VERIFY_ERROR_INVALID_PARAM;
    }
    
    /* Extract header */
    const app_header_t* header = (const app_header_t*)app_image;
    
    /* Validate header */
    app_verify_result_t result = app_verify_validate_header(header);
    if (result != APP_VERIFY_SUCCESS) {
        return result;
    }
    
    /* Check total image size */
    size_t expected_size = sizeof(app_header_t) + header->app_size;
    if (image_size < expected_size) {
        return APP_VERIFY_ERROR_INVALID_SIZE;
    }
    
    /* Extract application data */
    const uint8_t* app_data = app_image + sizeof(app_header_t);
    
    /* Calculate signature */
    uint8_t calculated_signature[APP_VERIFY_SIGNATURE_SIZE];
    app_verify_calculate_signature(header, app_data, header->app_size, calculated_signature);
    
    /* Verify signature */
    if (arm_ct_memcmp(header->signature, calculated_signature, APP_VERIFY_SIGNATURE_SIZE) != 0) {
        arm_secure_zero(calculated_signature, sizeof(calculated_signature));
        return APP_VERIFY_ERROR_SIGNATURE_MISMATCH;
    }
    
    /* Clear calculated signature */
    arm_secure_zero(calculated_signature, sizeof(calculated_signature));
    
    /* Fill application info if requested */
    if (app_info) {
        app_info->entry_point = header->app_entry;
        app_info->load_address = header->load_address;
        app_info->size = header->app_size;
        app_info->flags = header->flags;
    }
    
    return APP_VERIFY_SUCCESS;
}

/*
 * Verify application from flash memory
 */
app_verify_result_t app_verify_from_flash(uint32_t flash_address,
                                         size_t max_size,
                                         app_info_t* app_info)
{
    if (!g_initialized) {
        return APP_VERIFY_ERROR_INVALID_PARAM;
    }
    
    if (max_size < sizeof(app_header_t)) {
        return APP_VERIFY_ERROR_INVALID_SIZE;
    }
    
    /* Read header from flash */
    app_header_t header;
    memcpy(&header, (const void*)flash_address, sizeof(app_header_t));
    
    /* Validate header */
    app_verify_result_t result = app_verify_validate_header(&header);
    if (result != APP_VERIFY_SUCCESS) {
        return result;
    }
    
    /* Check if we can read the entire application */
    size_t total_size = sizeof(app_header_t) + header.app_size;
    if (total_size > max_size) {
        return APP_VERIFY_ERROR_INVALID_SIZE;
    }
    
    /* Point to application data in flash */
    const uint8_t* app_data = (const uint8_t*)(flash_address + sizeof(app_header_t));
    
    /* Calculate signature */
    uint8_t calculated_signature[APP_VERIFY_SIGNATURE_SIZE];
    app_verify_calculate_signature(&header, app_data, header.app_size, calculated_signature);
    
    /* Verify signature */
    if (arm_ct_memcmp(header.signature, calculated_signature, APP_VERIFY_SIGNATURE_SIZE) != 0) {
        arm_secure_zero(calculated_signature, sizeof(calculated_signature));
        return APP_VERIFY_ERROR_SIGNATURE_MISMATCH;
    }
    
    /* Clear calculated signature */
    arm_secure_zero(calculated_signature, sizeof(calculated_signature));
    
    /* Fill application info if requested */
    if (app_info) {
        app_info->entry_point = header.app_entry;
        app_info->load_address = header.load_address;
        app_info->size = header.app_size;
        app_info->flags = header.flags;
    }
    
    return APP_VERIFY_SUCCESS;
}

/*
 * Sign application image (for development/deployment tools)
 */
app_verify_result_t app_verify_sign_image(const uint8_t* app_data,
                                         size_t app_size,
                                         uint32_t entry_point,
                                         uint32_t load_address,
                                         uint32_t flags,
                                         uint8_t* signed_image,
                                         size_t* signed_size)
{
    if (!g_initialized || !app_data || !signed_image || !signed_size) {
        return APP_VERIFY_ERROR_INVALID_PARAM;
    }
    
    if (app_size == 0 || app_size > APP_VERIFY_MAX_APP_SIZE) {
        return APP_VERIFY_ERROR_INVALID_SIZE;
    }
    
    size_t total_size = sizeof(app_header_t) + app_size;
    if (*signed_size < total_size) {
        *signed_size = total_size;
        return APP_VERIFY_ERROR_INVALID_SIZE;
    }
    
    /* Create header */
    app_header_t header;
    memset(&header, 0, sizeof(header));
    
    memcpy(header.magic, APP_VERIFY_MAGIC, 7);
    header.magic[7] = 0;
    header.version = APP_VERIFY_VERSION;
    header.app_size = app_size;
    header.app_entry = entry_point;
    header.load_address = load_address;
    header.flags = flags;
    
    /* Calculate signature */
    app_verify_calculate_signature(&header, app_data, app_size, header.signature);
    
    /* Assemble signed image */
    memcpy(signed_image, &header, sizeof(header));
    memcpy(signed_image + sizeof(header), app_data, app_size);
    
    *signed_size = total_size;
    return APP_VERIFY_SUCCESS;
}

/*
 * Check if memory region is valid for application loading
 */
int app_verify_is_valid_load_region(uint32_t address, size_t size)
{
    /* Check SRAM region */
    if (address >= SRAM_BASE_ADDR && 
        address + size <= SRAM_BASE_ADDR + SRAM_SIZE) {
        return 1;
    }
    
    /* Check if loading to flash region (for XIP applications) */
    if (address >= FLASH_BASE_ADDR && 
        address + size <= FLASH_BASE_ADDR + FLASH_SIZE) {
        return 1;
    }
    
    /* Add other valid regions as needed */
    return 0;
}

/*
 * Check if address is a valid entry point
 */
int app_verify_is_valid_entry_point(uint32_t address)
{
    /* Entry point must be in valid memory region */
    if (!app_verify_is_valid_load_region(address, 4)) {
        return 0;
    }
    
    /* For ARM Cortex-M, entry point must have Thumb bit set */
#ifdef STM32F4
    if ((address & VALID_ENTRY_MASK) == 0) {
        return 0;
    }
#endif
    
    /* Entry point must be aligned */
    if ((address & 0x1) != 1) {  /* Thumb mode requires odd address */
        return 0;
    }
    
    return 1;
}

/*
 * Get error string for result code
 */
const char* app_verify_get_error_string(app_verify_result_t result)
{
    switch (result) {
        case APP_VERIFY_SUCCESS:
            return "Success";
        case APP_VERIFY_ERROR_INVALID_PARAM:
            return "Invalid parameter";
        case APP_VERIFY_ERROR_INVALID_HEADER:
            return "Invalid application header";
        case APP_VERIFY_ERROR_INVALID_SIZE:
            return "Invalid application size";
        case APP_VERIFY_ERROR_SIGNATURE_MISMATCH:
            return "Signature verification failed";
        case APP_VERIFY_ERROR_MEMORY_ERROR:
            return "Memory allocation error";
        case APP_VERIFY_ERROR_IO_ERROR:
            return "I/O error";
        default:
            return "Unknown error";
    }
}
