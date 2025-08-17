      ________________________________________________________________________
     /                                                                        \
    |  █████╗ ██████╗ ██████╗ ██████╗     ██████╗ ██████╗ ███╗   ███╗         |
    | ██╔══██╗██╔══██╗██╔══██╗██╔══██╗   ██╔═══██╗██╔══██╗████╗ ████║         |
    | ███████║██████╔╝██████╔╝██║  ██║   ██║   ██║██████╔╝██╔████╔██║         |
    | ██╔══██║██╔═══╝ ██╔═══╝ ██║  ██║   ██║   ██║██╔═══╝ ██║╚██╔╝██║         |
    | ██║  ██║██║     ██║     ██████╔╝   ╚██████╔╝██║     ██║ ╚═╝ ██║         |
    | ╚═╝  ╚═╝╚═╝     ╚═╝     ╚═════╝     ╚═════╝ ╚═╝     ╚═╝     ╚═╝         |
    |                                                                        |
    | ARM Assembly Cryptography Engine • birukG09                             |
    | AES-128/256 • AES-GCM/CCM • SHA-256 • SHA-3 • ChaCha20-Poly1305 • HKDF |
    | Secure Boot • IoT • Firmware Verification                                |
     \______________________________________________________________________/
      \____________________________________________________________________/
         \________________________________________________________________/
  
            ARM Assembly • AES • SHA-256 • Constant-Time                                     /_/   
 
                                                                       
         AES-GCM | SHA-256 | SHA-3 | HKDF | ChaCha20-Poly1305
                Secure Boot | IoT | Embedded ARM
 
# ARM Assembly Cryptography Engine

**Repository:** [https://github.com/birukG09/arm-crypto-engine](https://github.com/birukG09/arm-crypto-engine)
            _____________
             
                                                                                  
 AES • SHA-256 • SHA-3 • HKDF • ChaCha20-Poly1305 • Secure Boot • IoT • Embedded ARM


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
