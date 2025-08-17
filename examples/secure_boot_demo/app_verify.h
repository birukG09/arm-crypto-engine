/*
 * Application Verification Header
 * ArmAsm-CryptoEngine - Secure Boot Application Verification
 * 
 * Provides functionality to verify application images using HMAC-SHA256
 */

#ifndef APP_VERIFY_H
#define APP_VERIFY_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Configuration constants */
#define APP_VERIFY_SIGNATURE_SIZE 32    /* HMAC-SHA256 output size */
#define APP_VERIFY_KEY_SIZE 32          /* HMAC key size */
#define APP_VERIFY_MAGIC "ARMBOOT"      /* Application header magic */
#define APP_VERIFY_VERSION 1            /* Header version */

/* Maximum application size (1 MB) */
#define APP_VERIFY_MAX_APP_SIZE (1024 * 1024)

/* Error codes */
typedef enum {
    APP_VERIFY_SUCCESS = 0,
    APP_VERIFY_ERROR_INVALID_PARAM = -1,
    APP_VERIFY_ERROR_INVALID_HEADER = -2,
    APP_VERIFY_ERROR_INVALID_SIZE = -3,
    APP_VERIFY_ERROR_SIGNATURE_MISMATCH = -4,
    APP_VERIFY_ERROR_MEMORY_ERROR = -5,
    APP_VERIFY_ERROR_IO_ERROR = -6
} app_verify_result_t;

/* Application header structure */
typedef struct {
    char magic[8];              /* Magic bytes "ARMBOOT\0" */
    uint32_t version;           /* Header version */
    uint32_t app_size;          /* Application size in bytes */
    uint32_t app_entry;         /* Application entry point address */
    uint32_t load_address;      /* Load address in memory */
    uint32_t flags;             /* Application flags */
    uint8_t signature[APP_VERIFY_SIGNATURE_SIZE];   /* HMAC-SHA256 signature */
    uint8_t reserved[32];       /* Reserved for future use */
} __attribute__((packed)) app_header_t;

/* Application info structure */
typedef struct {
    uint32_t entry_point;       /* Application entry point */
    uint32_t load_address;      /* Load address */
    uint32_t size;              /* Application size */
    uint32_t flags;             /* Application flags */
} app_info_t;

/*
 * Initialize application verification system
 * 
 * @param hmac_key HMAC key for signature verification (32 bytes)
 * @return APP_VERIFY_SUCCESS on success, error code on failure
 */
app_verify_result_t app_verify_init(const uint8_t hmac_key[32]);

/*
 * Verify application image in memory
 * 
 * @param app_image Pointer to application image in memory
 * @param image_size Size of the application image
 * @param app_info Output application information (optional)
 * @return APP_VERIFY_SUCCESS if valid, error code if invalid
 */
app_verify_result_t app_verify_image(const uint8_t* app_image, 
                                    size_t image_size,
                                    app_info_t* app_info);

/*
 * Verify application from flash memory
 * 
 * @param flash_address Flash address where application is stored
 * @param max_size Maximum size to read from flash
 * @param app_info Output application information (optional)
 * @return APP_VERIFY_SUCCESS if valid, error code if invalid
 */
app_verify_result_t app_verify_from_flash(uint32_t flash_address,
                                         size_t max_size,
                                         app_info_t* app_info);

/*
 * Sign application image (for development/deployment tools)
 * 
 * @param app_data Application binary data
 * @param app_size Size of application data
 * @param entry_point Application entry point address
 * @param load_address Load address in memory
 * @param flags Application flags
 * @param signed_image Output buffer for signed image
 * @param signed_size Output size of signed image
 * @return APP_VERIFY_SUCCESS on success, error code on failure
 */
app_verify_result_t app_verify_sign_image(const uint8_t* app_data,
                                         size_t app_size,
                                         uint32_t entry_point,
                                         uint32_t load_address,
                                         uint32_t flags,
                                         uint8_t* signed_image,
                                         size_t* signed_size);

/*
 * Calculate application signature
 * 
 * @param header Application header (signature field will be ignored)
 * @param app_data Application data
 * @param app_size Size of application data
 * @param signature Output signature (32 bytes)
 */
void app_verify_calculate_signature(const app_header_t* header,
                                   const uint8_t* app_data,
                                   size_t app_size,
                                   uint8_t signature[32]);

/*
 * Validate application header
 * 
 * @param header Application header to validate
 * @return APP_VERIFY_SUCCESS if valid, error code if invalid
 */
app_verify_result_t app_verify_validate_header(const app_header_t* header);

/*
 * Get error string for result code
 * 
 * @param result Error code
 * @return Human-readable error string
 */
const char* app_verify_get_error_string(app_verify_result_t result);

/*
 * Cleanup verification system
 */
void app_verify_cleanup(void);

/* Memory protection functions (platform-specific) */

/*
 * Check if memory region is valid for application loading
 * 
 * @param address Start address
 * @param size Size of region
 * @return 1 if valid, 0 if invalid
 */
int app_verify_is_valid_load_region(uint32_t address, size_t size);

/*
 * Check if address is a valid entry point
 * 
 * @param address Entry point address
 * @return 1 if valid, 0 if invalid
 */
int app_verify_is_valid_entry_point(uint32_t address);

/* Application flags */
#define APP_FLAG_ENCRYPTED          0x00000001  /* Application is encrypted */
#define APP_FLAG_COMPRESSED         0x00000002  /* Application is compressed */
#define APP_FLAG_DEBUG_ENABLED      0x00000004  /* Debug features enabled */
#define APP_FLAG_SECURE_MODE        0x00000008  /* Requires secure mode */

#ifdef __cplusplus
}
#endif

#endif /* APP_VERIFY_H */
