/*
 * UART CLI Commands Header
 * ArmAsm-CryptoEngine - Command declarations for UART CLI
 */

#ifndef COMMANDS_H
#define COMMANDS_H

#ifdef __cplusplus
extern "C" {
#endif

/* Command system initialization */
int cmd_init(void);
void cmd_cleanup(void);

/* General commands */
void cmd_help(int argc, char** argv);
void cmd_version(int argc, char** argv);
void cmd_status(int argc, char** argv);
void cmd_clear(int argc, char** argv);
void cmd_exit(int argc, char** argv);

/* AES commands */
void cmd_aes_encrypt(int argc, char** argv);
void cmd_aes_decrypt(int argc, char** argv);
void cmd_aes_keygen(int argc, char** argv);

/* SHA-256 commands */
void cmd_sha256(int argc, char** argv);
void cmd_hmac(int argc, char** argv);

/* Utility commands */
void cmd_hex2bin(int argc, char** argv);
void cmd_bin2hex(int argc, char** argv);
void cmd_base64_encode(int argc, char** argv);
void cmd_base64_decode(int argc, char** argv);
void cmd_random(int argc, char** argv);

/* Test commands */
void cmd_test_aes(int argc, char** argv);
void cmd_test_sha256(int argc, char** argv);
void cmd_test_all(int argc, char** argv);

/* Benchmark commands */
void cmd_bench_aes(int argc, char** argv);
void cmd_bench_sha256(int argc, char** argv);
void cmd_bench_all(int argc, char** argv);

#ifdef __cplusplus
}
#endif

#endif /* COMMANDS_H */
