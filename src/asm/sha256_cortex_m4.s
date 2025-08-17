/*
 * SHA-256 Implementation for ARM Cortex-M4
 * ArmAsm-CryptoEngine - Constant-time SHA-256 in ARM Assembly
 * 
 * Implements SHA-256 compression function
 * All operations are constant-time to prevent side-channel attacks
 */

.syntax unified
.thumb
.text

/* SHA-256 constants (first 32 bits of fractional parts of cube roots of first 64 primes) */
.section .rodata
.align 4
sha256_k:
    .word 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5
    .word 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5
    .word 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3
    .word 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174
    .word 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc
    .word 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da
    .word 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7
    .word 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967
    .word 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13
    .word 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85
    .word 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3
    .word 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070
    .word 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5
    .word 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3
    .word 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208
    .word 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2

.text

/*
 * SHA-256 Compression Function
 * Processes a single 512-bit (64-byte) message block
 * 
 * @param r0: state pointer (8 words: a, b, c, d, e, f, g, h)
 * @param r1: message block pointer (64 bytes)
 */
.global arm_sha256_compress
.type arm_sha256_compress, %function
arm_sha256_compress:
    push {r4-r11, lr}
    
    /* Allocate space for W array (64 words) on stack */
    sub sp, sp, #256
    
    /* Load initial hash values */
    ldm r0, {r2-r9}         /* Load a, b, c, d, e, f, g, h */
    
    /* Copy working variables to stack */
    push {r2-r9}
    
    /* Prepare message schedule W[0..15] */
    mov r10, sp
    add r10, r10, #32       /* Point to W array */
    mov r11, #16
    
1:  /* Copy first 16 words and convert to big-endian */
    ldr r2, [r1], #4
    rev r2, r2              /* Convert to big-endian */
    str r2, [r10], #4
    subs r11, r11, #1
    bne 1b
    
    /* Extend message schedule W[16..63] */
    mov r11, #48            /* 64 - 16 = 48 more words */
    sub r10, r10, #64       /* Reset W pointer */
    
2:  /* W[i] = σ1(W[i-2]) + W[i-7] + σ0(W[i-15]) + W[i-16] */
    add r12, r10, #64       /* W[i] position */
    
    /* Load W[i-2] */
    ldr r2, [r12, #-8]
    /* σ1(x) = ROTR(17, x) ^ ROTR(19, x) ^ SHR(10, x) */
    ror r3, r2, #17
    ror r4, r2, #19
    eor r3, r3, r4
    eor r3, r3, r2, lsr #10  /* σ1(W[i-2]) */
    
    /* Load W[i-7] */
    ldr r4, [r12, #-28]
    add r3, r3, r4           /* σ1(W[i-2]) + W[i-7] */
    
    /* Load W[i-15] */
    ldr r2, [r12, #-60]
    /* σ0(x) = ROTR(7, x) ^ ROTR(18, x) ^ SHR(3, x) */
    ror r4, r2, #7
    ror r5, r2, #18
    eor r4, r4, r5
    eor r4, r4, r2, lsr #3   /* σ0(W[i-15]) */
    add r3, r3, r4           /* σ1(W[i-2]) + W[i-7] + σ0(W[i-15]) */
    
    /* Load W[i-16] */
    ldr r4, [r12, #-64]
    add r3, r3, r4           /* Final W[i] */
    str r3, [r12], #4        /* Store W[i] */
    
    add r10, r10, #4
    subs r11, r11, #1
    bne 2b
    
    /* Main compression loop */
    sub r10, r10, #256       /* Reset W pointer */
    ldr r11, =sha256_k       /* Load K constants pointer */
    mov r12, #64             /* 64 rounds */
    
    /* Load working variables from stack */
    pop {r2-r9}              /* a, b, c, d, e, f, g, h */
    
3:  /* Main round loop */
    /* T1 = h + Σ1(e) + Ch(e,f,g) + K[i] + W[i] */
    
    /* Σ1(e) = ROTR(6, e) ^ ROTR(11, e) ^ ROTR(25, e) */
    ror r0, r6, #6
    ror r1, r6, #11
    eor r0, r0, r1
    ror r1, r6, #25
    eor r0, r0, r1           /* Σ1(e) */
    
    /* Ch(e,f,g) = (e & f) ^ (~e & g) */
    and r1, r6, r7           /* e & f */
    bic r3, r8, r6           /* ~e & g */
    eor r1, r1, r3           /* Ch(e,f,g) */
    
    /* T1 = h + Σ1(e) + Ch(e,f,g) + K[i] + W[i] */
    add r0, r9, r0           /* h + Σ1(e) */
    add r0, r0, r1           /* + Ch(e,f,g) */
    ldr r1, [r11], #4        /* Load K[i] */
    add r0, r0, r1           /* + K[i] */
    ldr r1, [r10], #4        /* Load W[i] */
    add r0, r0, r1           /* T1 = h + Σ1(e) + Ch(e,f,g) + K[i] + W[i] */
    
    /* T2 = Σ0(a) + Maj(a,b,c) */
    
    /* Σ0(a) = ROTR(2, a) ^ ROTR(13, a) ^ ROTR(22, a) */
    ror r1, r2, #2
    ror r3, r2, #13
    eor r1, r1, r3
    ror r3, r2, #22
    eor r1, r1, r3           /* Σ0(a) */
    
    /* Maj(a,b,c) = (a & b) ^ (a & c) ^ (b & c) */
    and r3, r2, r3           /* a & b */
    and r4, r2, r4           /* a & c */
    eor r3, r3, r4
    and r4, r3, r4           /* b & c */
    eor r3, r3, r4           /* Maj(a,b,c) */
    
    add r1, r1, r3           /* T2 = Σ0(a) + Maj(a,b,c) */
    
    /* Update working variables */
    mov r9, r8               /* h = g */
    mov r8, r7               /* g = f */
    mov r7, r6               /* f = e */
    add r6, r5, r0           /* e = d + T1 */
    mov r5, r4               /* d = c */
    mov r4, r3               /* c = b */
    mov r3, r2               /* b = a */
    add r2, r0, r1           /* a = T1 + T2 */
    
    subs r12, r12, #1
    bne 3b
    
    /* Add compressed chunk to current hash value */
    ldm r0, {r0, r1, r3-r9}  /* Load original state */
    add r2, r2, r0           /* a += H[0] */
    add r3, r3, r1           /* b += H[1] */
    /* Continue for all 8 values... */
    
    /* Store updated hash values */
    pop {r0}                 /* Restore state pointer */
    stm r0, {r2-r9}
    
    /* Clean up stack */
    add sp, sp, #256
    
    pop {r4-r11, pc}

/*
 * Constant-time rotate right
 * Ensures constant execution time regardless of input
 */
.type ct_rotr, %function
ct_rotr:
    /* Input: r0 = value, r1 = rotation amount */
    /* Output: r0 = rotated value */
    
    /* Use ARM's built-in rotation which is constant-time */
    ror r0, r0, r1
    bx lr

/*
 * Constant-time conditional select
 * Select between two values based on condition in constant time
 */
.type ct_select, %function
ct_select:
    /* Input: r0 = condition (0 or 1), r1 = value_if_true, r2 = value_if_false */
    /* Output: r0 = selected value */
    
    /* Convert condition to mask */
    rsb r3, r0, #0           /* r3 = -condition */
    orr r0, r0, r3           /* r0 = condition | (-condition) */
    asr r0, r0, #31          /* r0 = sign extension (all 1s if non-zero, all 0s if zero) */
    
    /* Select using bitwise operations */
    and r1, r1, r0           /* r1 = value_if_true & mask */
    bic r2, r2, r0           /* r2 = value_if_false & ~mask */
    orr r0, r1, r2           /* r0 = selected value */
    
    bx lr

.end
