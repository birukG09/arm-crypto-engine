# Constant-Time Implementation Checklist

## Overview

This document provides a comprehensive checklist for verifying constant-time implementation in the ArmAsm-CryptoEngine cryptographic library. Constant-time operation is critical for preventing timing-based side-channel attacks that could reveal cryptographic secrets.

## General Principles

### ✅ Constant-Time Definition
- [ ] **No secret-dependent branches**: Control flow must not depend on secret data
- [ ] **No secret-dependent memory access**: Memory access patterns must not depend on secret data  
- [ ] **No secret-dependent instruction timing**: Instruction execution time must not depend on secret data
- [ ] **Consistent resource usage**: CPU cycles, cache usage, and power consumption should be consistent

### ✅ Secret Data Classification
- [ ] **Cryptographic keys**: AES keys, HMAC keys, derived keys
- [ ] **Intermediate values**: Round keys, state during encryption/decryption
- [ ] **Plaintext data**: Data being encrypted (context-dependent)
- [ ] **Random values**: Nonces, salts, initialization vectors (when used as keys)

## Assembly Implementation Checklist

### ✅ Instruction Selection
- [ ] **Avoid conditional instructions**: No conditional branches on secret data
- [ ] **Use constant-time instructions**: Prefer arithmetic over conditional operations
- [ ] **Avoid variable-time multiplications**: Use fixed-time multiplication instructions
- [ ] **Consistent instruction sequences**: Same instruction pattern regardless of input

### ✅ Branch Instructions
```assembly
# ❌ BAD: Secret-dependent branch
cmp r0, #0          ; r0 contains secret data
bne skip_operation  ; Branch depends on secret
# ... operation ...
skip_operation:

# ✅ GOOD: Conditional execution without branching
cmp r0, #0          ; r0 contains secret data
movne r1, #0        ; Conditional move, no branch
moveq r1, #1        ; Always executes same number of cycles
