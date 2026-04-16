/*
 * station.c — "Mutation Station"
 *
 * CAPEC-28 Fuzzing CTF challenge, IT&C 266.
 *
 * A toy binary protocol:
 *
 *     +--------+--------+--------+--------+--------+--------+--------+--------+
 *     |  'F'   |  'U'   |  'Z'   |  'Z'   |  'M'   |  'E'   |  0x00  |  0x01  |
 *     +--------+--------+--------+--------+--------+--------+--------+--------+
 *     |  len_lo  |  len_hi  |  ...  len bytes of payload  ...                 |
 *     +----------+----------+------------------------------------------------+
 *
 * Header passes? Payload gets processed. The processor has a flaw.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <stdint.h>
#include <unistd.h>

/* -------- XOR-obfuscated flag (so `strings` won't hand it over) -------- */
#define KEY 0xAA
static const unsigned char enc_flag[] = {
    0xC3, 0xDE, 0xC9, 0x98, 0x9C, 0x9C, 0xD1, 0xC7, 0xDF, 0xDE, 0x9E, 0xDE,
    0x9B, 0x9A, 0xC4, 0xF5, 0xD9, 0xDE, 0x9E, 0xDE, 0x9B, 0x9A, 0xC4, 0xF5,
    0xC9, 0xC6, 0xCF, 0x9E, 0xD8, 0xCF, 0xCE, 0xD7,
};

/* -------- Signal handler: fires on SIGSEGV / SIGBUS / SIGABRT -------- */
static void crash_handler(int sig) {
    (void)sig;
    static const char banner[] =
        "\n[!] SIGSEGV — memory corruption detected inside payload processor.\n"
        "[+] You fuzzed past the protocol validator. Flag:\n";
    write(2, banner, sizeof(banner) - 1);

    char out[sizeof(enc_flag) + 1];
    for (size_t i = 0; i < sizeof(enc_flag); i++) {
        out[i] = (char)(enc_flag[i] ^ KEY);
    }
    out[sizeof(enc_flag)] = '\n';
    write(1, out, sizeof(enc_flag) + 1);
    _exit(0);
}

static void reject(const char *msg) {
    fprintf(stderr, "rejected: %s\n", msg);
    exit(1);
}

/* -------- The vulnerable part --------
 * `len` is trusted from the header. `buf` is 64 bytes. No bounds check.
 * A payload > 64 bytes smashes the stack on return.
 */
static void process_payload(const unsigned char *p, uint16_t len) {
    char buf[64];
    memcpy(buf, p, len);
    if (len < sizeof(buf)) buf[len] = '\0';
    printf("accepted record (%u bytes)\n", len);
}

int main(int argc, char **argv) {
    signal(SIGSEGV, crash_handler);
    signal(SIGBUS,  crash_handler);
    signal(SIGABRT, crash_handler);

    if (argc < 2) {
        fprintf(stderr, "usage: %s <input_file>\n", argv[0]);
        return 1;
    }

    FILE *f = fopen(argv[1], "rb");
    if (!f) { perror("fopen"); return 1; }

    unsigned char raw[4096];
    size_t n = fread(raw, 1, sizeof(raw), f);
    fclose(f);

    if (n < 10) reject("short header");

    static const unsigned char magic[8] = {
        'F','U','Z','Z','M','E', 0x00, 0x01
    };
    if (memcmp(raw, magic, 8) != 0) reject("bad magic");

    uint16_t len = (uint16_t)raw[8] | ((uint16_t)raw[9] << 8);
    if (10 + (size_t)len > n) reject("truncated payload");

    process_payload(raw + 10, len);
    return 0;
}
