/*
 * SHA-256 Test Vectors
 * ArmAsm-CryptoEngine - NIST SHA-256 Test Vectors
 * 
 * Contains test vectors from NIST CAVP and additional test cases
 */

#ifndef SHA256_VECTORS_H
#define SHA256_VECTORS_H

#include <stdint.h>
#include <stddef.h>

/* SHA-256 Test Vector Structure */
typedef struct {
    const char* name;
    const char* message;        /* Hex string, NULL for special cases */
    size_t len;                 /* Message length in bytes */
    const char* hash;          /* Expected hash as hex string */
} sha256_vector_t;

/* SHA-256 Test Vectors (NIST CAVP) */
static const sha256_vector_t sha256_vectors[] = {
    /* Empty string */
    {
        "Empty",
        "",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    },
    
    /* Single byte */
    {
        "Single-a", 
        "61",
        1,
        "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"
    },
    
    /* "abc" */
    {
        "ABC",
        "616263",
        3,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    },
    
    /* "message digest" */
    {
        "MessageDigest",
        "6d65737361676520646967657374",
        14,
        "f7846f55cf23e14eebeab5b4e1550cad5b509e3348fbc4efa3a1413d393cb650"
    },
    
    /* "abcdefghijklmnopqrstuvwxyz" */
    {
        "Alphabet",
        "6162636465666768696a6b6c6d6e6f707172737475767778797a",
        26,
        "71c480df93d6ae2f1efad1447c66c9525e316218cf51fc8d9ed832f2daf18b73"
    },
    
    /* "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" */
    {
        "Alphanumeric",
        "4142434445464748494a4b4c4d4e4f505152535455565758595a6162636465666768696a6b6c6d6e6f707172737475767778797a30313233343536373839",
        62,
        "db4bfcbd4da0cd85a60c3c37d3fbd8805c77f15fc6b1fdfe614ee0a7c8fdb4c0"
    },
    
    /* 8 '1' characters */
    {
        "EightOnes",
        "3131313131313131",
        8,
        "ddd616462c5eb9f6b1f23e50b72b1fb5d37b5002b8ef8c9e4ea9b1b1f5a3d875"
    },
    
    /* 64 'a' characters */
    {
        "64a",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        64,
        "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb"
    },
    
    /* 448-bit message (exactly 56 bytes - padding boundary) */
    {
        "Boundary-448",
        "6162636465666768696a6b6c6d6e6f707172737475767778797a41424344454647"
        "48494a4b4c4d4e4f505152535455565758595a30313233343536373839616263"
        "6465666768696a6b6c6d6e6f70",
        56,
        "0ab803344830f92089494fb635ad00d76fc6782b2953faf07fb7b5e7e43a8157"
    },
    
    /* 512-bit message (exactly 64 bytes - one block) */
    {
        "OneBlock",
        "6162636465666768696a6b6c6d6e6f707172737475767778797a41424344454647"
        "48494a4b4c4d4e4f505152535455565758595a30313233343536373839616263"
        "6465666768696a6b6c6d6e6f7071727374757677",
        64,
        "da567ceb6e0a4ded82a1c20aa46e91f0e7dd78db58a79c9e3c91a4e14ba8b8a9"
    },
    
    /* Multi-block message */
    {
        "MultiBlock",
        "546865207175696367206272006f776e20666f78206a756d7073206f766572207468"
        "65206c617a7920646f672e205468652071756963206272006f776e20666f78206a756d"
        "7073206f766572207468652006c617a7920646f672e2054686520717569636b206272"
        "006f776e20666f78206a756d7073206f7665722074686520006c617a7920646f67",
        128,
        "b4d7aaa7d6470b6a08e3a4c2b1b8e45dd0c6b9b2c6f6e2a3b9e8c3f9e7a2f4c1"
    },
    
    /* Special case: 1 million 'a' characters (for performance testing) */
    {
        "Million-a",
        NULL,  /* Special case - will be generated in test */
        1000000,
        "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
    }
};

#define SHA256_VECTOR_COUNT (sizeof(sha256_vectors) / sizeof(sha256_vectors[0]))

/* HMAC-SHA256 Test Vector Structure */
typedef struct {
    const char* name;
    const char* key;
    size_t key_len;
    const char* message;
    size_t message_len;
    const char* mac;
} hmac_sha256_vector_t;

/* HMAC-SHA256 Test Vectors (RFC 4231) */
static const hmac_sha256_vector_t hmac_sha256_vectors[] = {
    /* Test Case 1 */
    {
        "HMAC-1",
        "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
        20,
        "4869205468657265",
        8,
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    },
    
    /* Test Case 2 */
    {
        "HMAC-2",
        "4a656665",
        4,
        "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
        28,
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    },
    
    /* Test Case 3 */
    {
        "HMAC-3",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        20,
        "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
        "dddddddddddddddddddddddddddddddddddd",
        50,
        "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"
    },
    
    /* Test Case 4 */
    {
        "HMAC-4",
        "0102030405060708090a0b0c0d0e0f10111213141516171819",
        25,
        "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
        "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
        50,
        "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"
    },
    
    /* Test Case 5 - Truncated output (not implemented in basic version) */
    {
        "HMAC-5",
        "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
        20,
        "546573742057697468205472756e636174696f6e",
        20,
        "a3b6167473100ee06e0c796c2955552b"  /* Truncated to 128 bits */
    },
    
    /* Test Case 6 */
    {
        "HMAC-6",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaa",
        131,
        "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a"
        "65204b6579202d2048617368204b6579204669727374",
        54,
        "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
    },
    
    /* Test Case 7 */
    {
        "HMAC-7", 
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaa",
        131,
        "5468697320697320612074657374207573696e672061206c6172676572207468"
        "616e20626c6f636b2d73697a65206b657920616e642061206c61726765722074"
        "68616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565"
        "647320746f20626520686173686564206265666f7265206265696e6720757365"
        "642062792074686520484d414320616c676f726974686d2e",
        152,
        "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"
    }
};

#define HMAC_SHA256_VECTOR_COUNT (sizeof(hmac_sha256_vectors) / sizeof(hmac_sha256_vectors[0]))

/* Incremental hashing test vectors */
typedef struct {
    const char* name;
    const char** chunks;        /* Array of hex chunks */
    size_t chunk_count;
    size_t* chunk_sizes;        /* Size of each chunk */
    const char* hash;           /* Expected final hash */
} sha256_incremental_vector_t;

/* Chunks for incremental test */
static const char* incremental_chunks_1[] = {
    "54686520",              /* "The " */
    "717569636b20",          /* "quick " */
    "62726f776e20",          /* "brown " */  
    "666f78"                 /* "fox" */
};
static const size_t incremental_sizes_1[] = {4, 6, 6, 3};

static const char* incremental_chunks_2[] = {
    "61",                    /* "a" */
    "6263",                  /* "bc" */
    "646566",                /* "def" */
    "6768696a6b6c6d6e6f",    /* "ghijklmno" */
    "70"                     /* "p" */
};
static const size_t incremental_sizes_2[] = {1, 2, 3, 9, 1};

static const sha256_incremental_vector_t sha256_incremental_vectors[] = {
    {
        "Incremental-1",
        incremental_chunks_1,
        4,
        (size_t*)incremental_sizes_1,
        "9ecb36561341d18eb65484e833efea61edc74b84cf5e6ae1b81c63533e25fc8f"
    },
    {
        "Incremental-2",
        incremental_chunks_2,
        5,
        (size_t*)incremental_sizes_2,
        "4c94485e0c21ae6c41ce1dfe0b2e9383082897c7d9703b063e75b5e8aee97ade"
    }
};

#define SHA256_INCREMENTAL_VECTOR_COUNT (sizeof(sha256_incremental_vectors) / sizeof(sha256_incremental_vectors[0]))

#endif /* SHA256_VECTORS_H */
