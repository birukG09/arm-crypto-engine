   ______                  ___            _                 ____                 _             
  / ____/___  ____  _____ /   |  ____ ___( )_____  ______  / __ \___  ____ _____(_)___  ____ _
 / /   / __ \/ __ \/ ___// /| | / __ `__ \/ / ___/ / ___/ / / / / _ \/ __ `/ ___/ / __ \/ __ `/
/ /___/ /_/ / /_/ (__  )/ ___ |/ / / / / / (__  ) (__  ) / /_/ /  __/ /_/ (__  ) / / / / /_/ / 
\____/\____/\____/____//_/  |_/_/ /_/ /_/_/____/ /____/ /_____/\___/\__,_/____/_/_/ /_/\__, /  
            ARM Assembly • AES • SHA-256 • Constant-Time                                     /_/   

████╗  █████╗ ██████╗     ██████╗ ██████╗ ██████╗ ███████╗
██╔══██╗██╔══██╗██╔══██╗   ██╔══██╗██╔══██╗██╔══██╗██╔════╝
███████║███████║██████╔╝   ██████╔╝██████╔╝██████╔╝█████╗  
██╔══██║██╔══██║██╔═══╝    ██╔═══╝ ██╔═══╝ ██╔═══╝ ██╔══╝  
██║  ██║██║  ██║██║        ██║     ██║     ██║     ███████╗
╚═╝  ╚═╝╚═╝  ╚═╝╚═╝        ╚═╝     ╚═╝     ╚═╝     ╚══════╝

# ARM Assembly Cryptography Engine

**Repository:** [https://github.com/birukG09/arm-crypto-engine](https://github.com/birukG09/arm-crypto-engine)
            _____________
           / ___________ \          _________
          / /  ARM ASM  \ \        |  ___  _|      _________
         / /   CRYPTO    \ \       | |__ \ \      /  _____  \
        / /_______________\ \      |  __) | |    /  / ___ \  \
        \___________________/      | |___/ /    /  / / _ \ \  \
          |  |  |  |  |  |         |______/    /__/ / (_) \ \__\
          |  |  |  |  |  |                      ___/  ___  \___
          |__|__|__|__|__|          _______    /___  / _ \  ___\
         [==== MICRO ====]         /  ___  \       \/ (_) \/ 
         |  ___      ___ |        |  / _ \  |       \  _  /
         | | _ \____/ _ ||   ____ | | (_) | | ____   | | |
         | ||_)/ __ \| ||  / __ \|  \___/  |/ __ \  | | |
         | | _ <\__/ /| ||| /__/ / \______/ \__/ /__| | |__
         |_|_| \____/ |_||| \___/                 |____|____|
                [ AES | SHA-256 | HMAC | CTR | CBC ]
+------------------ AES ROUND -------------------+
| State ⊕ RoundKey → SubBytes → ShiftRows →     |
|                     MixColumns → ⊕ RoundKey   |
+-----------------------------------------------+
   ^             ^            ^            ^
   |             |            |            |
  CT             S-box       rotation    GF(2^8)
 (constant-time) (bitsliced) (row perm)  multiply
   SHA-256 COMPRESS(block)
   ┌───────────────────────────────────────────┐
   │ a b c d e f g h  ←  IV / previous state  │
   └┬─────────────────────────────────────────┬┘
    │   64 rounds:                           │
    │   T1 = h + Σ1(e) + Ch(e,f,g) + Kt + Wt │
    │   T2 = Σ0(a) + Maj(a,b,c)              │
    │   h g f e d c b a ← g f e d (c) (b)    │
    └─────────────────────────────────────────┘
         Σ/Ch/Maj in ARM Thumb-2 bitwise ops
            (ROR, EOR, AND, BIC) — no tables
[ SECURE BOOT DEMO ]
ROM → HMAC-VERIFY(app.bin) ✓ → JUMP
           |
           └── on fail → UART RECOVERY
┌─────────────────────────────┐
│  CONSTANT-TIME PRIMITIVES   │
│  • no secret-branching      │
│  • no secret-indexing       │
│  • bitsliced S-box          │
└─────────────────────────────┘
┌───────── BENCHMARKS (cycles/byte) ─────────┐
│ AES-128 CTR (Cortex-M4 @168MHz) :   ≤ 200  │
│ SHA-256 (Cortex-M4 @168MHz)      :   ≤  90 │
│ AES-128 CTR (A53 NEON)           :   ≤  20 │
│ SHA-256 (A53 NEON)               :   ≤  12 │
└────────────────────────────────────────────┘
ArmAsm-CryptoEngine
> AES | SHA-256 | HMAC | CTR | CBC
Ready. Type 'help' or 'bench'.

---

## Description

This project is an **ARM Assembly-based cryptography engine** designed to implement and explore fundamental cryptographic primitives directly in low-level assembly.  
It is ideal for embedded systems, IoT devices, or educational purposes where low-level optimization and understanding of cryptographic algorithms matter.

The engine currently supports:

- AES (Advanced Encryption Standard)
- SHA-256 hashing
- Modular arithmetic routines
- PRNG (Pseudo-Random Number Generator)
- Simple RSA encryption/decryption routines (optional)

This project demonstrates both **performance-focused low-level coding** and **practical cryptography** in a lightweight environment.

---

## Features

- Pure **ARM Assembly implementation**.
- Optimized routines for speed and memory efficiency.
- Educational reference for ARM Assembly programmers learning cryptography.
- Can be extended to support additional crypto algorithms.
- Works on ARM-based development boards or emulators.

---

## Requirements

- ARM-based processor or emulator (e.g., QEMU)
- ARM Assembly toolchain (`as`, `ld`, `gcc` for ARM)
- Linux/Unix environment recommended
- Optional: Debugger like `gdb` or `qemu-system-arm` for testing

---

## Installation

Clone this repository:

```bash
git clone https://github.com/birukG09/arm-crypto-engine.git
cd arm-crypto-engine
as -o main.o main.s       # Assemble
ld -o crypto main.o       # Link
./crypto
Usage

Explore individual cryptographic routines in src/ or routines/ folder.

Modify the input/output buffers in assembly for experimentation.

Integrate routines into embedded firmware projects.

Contribution

Contributions are welcome!
Feel free to:

Add new cryptographic primitives

Optimize existing routines

Add test scripts or benchmark performance

Improve documentation

License

MIT License © 2025 Biruk G.
       ________________________________________________________
      /                                                        \
     |    _    _ ___ __  __ _  ___ ___     ___ _ __ ___  ___    |
     |   | |  | / __|  \/  | |/ __/ _ \   / __| '__/ _ \/ _ \   |
     |   | |__| \__ \ |\/| | | (_|  __/  | (__| | |  __/  __/   |
     |    \____/|___/_|  |_|_|\___\___|   \___|_|  \___|\___|   |
     |                                                          |
     |       ARM Assembly • AES • SHA-256 • SHA-3 • HKDF        |
     |      Secure Boot | IoT Encryption | ChaCha20-Poly1305    |
      \________________________________________________________/
       \______________________________________________________/
          \_______________________________________________/
