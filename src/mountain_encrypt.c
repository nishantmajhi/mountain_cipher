/* ===========================================================================
 * mountain_encrypt.c
 *
 * Command-line encryption tool implementing Phases 1-3 of the Mountain
 * Cipher algorithm (see mountain_cipher_algorithm.md and README.md).
 *
 * Usage:
 *   mountain_encrypt <input_file> <output_file> [n]
 *
 * Container file format written to <output_file>:
 *
 *   [4 bytes]  magic "MTNC"
 *   [1 byte]   format version
 *   [1 byte]   n (key matrix dimension)
 *   [8 bytes]  num_blocks, little-endian uint64
 *   [32 bytes] file_hash_plaintext  (SHA-256 of the ORIGINAL input file)
 *   [32 bytes] file_hash_ciphertext (SHA-256 of the raw ciphertext blocks)
 *   [num_blocks * n * n * 8 bytes]  ciphertext blocks, each entry an
 *                                   int64 stored little-endian
 *
 * Only the ciphertext is covered by a hash. The header is not: see
 * README.md "Known Limitations" for what that does and does not mean.
 *
 * This is a student proof-of-concept (see README.md "Known
 * Limitations"). Do not use it to protect anything you actually care
 * about.
 * ===========================================================================
 */

#include "mountain_cipher.h"
#include "cli_util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static void write_u64_le(uint8_t *out, uint64_t v) {
    for (int i = 0; i < 8; i++) out[i] = (uint8_t)(v >> (8 * i));
}

/* Parses the optional n argument. atoi() was used here originally, which
 * returns 0 for text that is not a number at all and silently ignores
 * trailing garbage - so "banana" was reported as being out of range
 * rather than as not being a number, and "4abc" and "4.9" were both
 * quietly accepted as 4. Returns 0 and sets *ok to 0 on a malformed
 * argument; range checking stays with the caller. */
static int parse_dimension(const char *text, int *ok) {
    char *end = NULL;
    long value;

    *ok = 0;
    if (!text || *text == '\0') return 0;
    value = strtol(text, &end, 10);
    if (end == text || *end != '\0') return 0;
    /* Clamp well inside int range so the caller's own 2..MC_MAX_N check
     * does the rejecting, and a huge argument cannot wrap on the way. */
    if (value < 0) value = -1;
    if (value > 1000000L) value = 1000000L;
    *ok = 1;
    return (int)value;
}

int main(int argc, char **argv) {
    if (argc < 3 || argc > 4) {
        fprintf(stderr, "Usage: %s <input_file> <output_file> [n]\n", argv[0]);
        fprintf(stderr, "  n = key matrix dimension, default 4 (keep <= 6, see README)\n");
        return 1;
    }
    const char *input_path = argv[1];
    const char *output_path = argv[2];

    int n = 4;
    if (argc == 4) {
        int ok = 0;
        n = parse_dimension(argv[3], &ok);
        if (!ok) {
            fprintf(stderr, "Error: n must be a whole number, got '%s'\n", argv[3]);
            return 1;
        }
    }

    if (n <= 1 || n > MC_MAX_N) {
        fprintf(stderr, "Error: n must be between 2 and %d\n", MC_MAX_N);
        return 1;
    }

    /* ---- Step 1.1: hash the plaintext file ---- */
    uint8_t file_hash_plaintext[MC_HASH_SIZE];
    if (mc_sha256_file(input_path, file_hash_plaintext) != MC_OK) {
        fprintf(stderr, "Error: could not read/hash input file '%s'\n", input_path);
        return 1;
    }

    size_t plaintext_len = 0;
    uint8_t *plaintext = cli_read_file(input_path, &plaintext_len);
    if (!plaintext) {
        fprintf(stderr, "Error: could not read input file '%s'\n", input_path);
        return 1;
    }

    char *password = cli_read_password("Password: ");
    if (!password) {
        fprintf(stderr, "Error: could not read password (see the message above)\n");
        free(plaintext);
        return 1;
    }

    /* ---- Step 1.2: derive key seed via Argon2id ---- */
    uint8_t key_seed[MC_SEED_SIZE];
    mc_status_t derive_st = mc_derive_key_seed(password, file_hash_plaintext, key_seed);
    mc_secure_wipe(password, strlen(password));
    free(password);
    if (derive_st != MC_OK) {
        fprintf(stderr, "Error: Argon2id key derivation failed\n");
        mc_secure_wipe(key_seed, sizeof(key_seed));
        free(plaintext);
        return 1;
    }

    /* ---- Step 1.3: generate the key matrix (once, for the whole file) ----
     * `key` is fixed from here on. It is never overwritten or mutated in
     * place; each block below derives a disposable `work_key` copy from
     * it instead. */
    mc_matrix_t key;
    mc_status_t gen_st = mc_generate_key_matrix(n, key_seed, &key);
    mc_secure_wipe(key_seed, sizeof(key_seed));
    if (gen_st != MC_OK) {
        fprintf(stderr, "Error: key matrix generation failed: %s\n", mc_strerror(gen_st));
        free(plaintext);
        return 1;
    }

    /* ---- Step 1.4: pad and split plaintext into n x n blocks ---- */
    size_t block_bytes = (size_t)n * (size_t)n;
    size_t padded_len = 0;
    uint8_t *padded = mc_pkcs7_pad(plaintext, plaintext_len, block_bytes, &padded_len);
    free(plaintext);
    if (!padded) {
        fprintf(stderr, "Error: padding failed\n");
        mc_matrix_free(&key);
        return 1;
    }
    uint64_t num_blocks = padded_len / block_bytes;

    /* ---- Phase 2: encrypt every block ---- */
    size_t ct_int_count = (size_t)num_blocks * block_bytes;
    int64_t *ct = (int64_t *)malloc(ct_int_count * sizeof(int64_t));
    if (!ct) {
        fprintf(stderr, "Error: allocation failed\n");
        free(padded); mc_matrix_free(&key);
        return 1;
    }

    mc_status_t st = mc_encrypt_blocks(&key, padded, padded_len, ct);
    if (st != MC_OK) {
        fprintf(stderr, "Error: encryption failed: %s\n", mc_strerror(st));
        free(ct); free(padded); mc_matrix_free(&key);
        return 1;
    }

    /* ---- Confirm the result can actually be decrypted again ----
     * Encryption and decryption do not fail together: encryption stays
     * inside int64 comfortably, while decryption multiplies by the
     * adjugate, whose entries grow factorially with n. Without this check
     * n=8 wrote a container that could never be opened for about a
     * quarter of keys, and n=9 for every key, reporting success each
     * time - so the user found out only after deleting the original.
     * This costs one decryption; a lost file costs the file. */
    st = mc_encrypt_is_recoverable(&key, padded, padded_len, ct);
    mc_matrix_free(&key);
    if (st != MC_OK) {
        fprintf(stderr,
                "Error: this file and key produce a ciphertext that cannot be "
                "decrypted (%s).\n"
                "       Nothing was written to '%s'. Try a smaller n "
                "(n=%d was requested).\n",
                mc_strerror(st), output_path, n);
        mc_secure_wipe(padded, padded_len);
        free(ct); free(padded);
        return 1;
    }
    mc_secure_wipe(padded, padded_len);
    free(padded);

    /* ---- Step 2.5 / 3.1: serialise the blocks, then hash them ---- */
    uint8_t *ct_bytes = (uint8_t *)malloc(ct_int_count * 8);
    if (!ct_bytes) {
        fprintf(stderr, "Error: allocation failed\n");
        free(ct);
        return 1;
    }
    for (size_t idx = 0; idx < ct_int_count; idx++) {
        write_u64_le(ct_bytes + idx * 8, (uint64_t)ct[idx]);
    }
    free(ct);

    uint8_t file_hash_ciphertext[MC_HASH_SIZE];
    if (mc_sha256_buffer(ct_bytes, ct_int_count * 8, file_hash_ciphertext) != MC_OK) {
        fprintf(stderr, "Error: hashing ciphertext failed\n");
        free(ct_bytes);
        return 1;
    }

    /* ---- Step 3.2: assemble and write the transmitted package ---- */
    size_t header_len = 4 + 1 + 1 + 8 + MC_HASH_SIZE + MC_HASH_SIZE;
    size_t total_len = header_len + ct_int_count * 8;
    uint8_t *package = (uint8_t *)malloc(total_len);
    if (!package) {
        fprintf(stderr, "Error: allocation failed\n");
        free(ct_bytes);
        return 1;
    }
    size_t off = 0;
    memcpy(package + off, MC_MAGIC, 4); off += 4;
    package[off++] = (uint8_t)MC_FORMAT_VERSION;
    package[off++] = (uint8_t)n;
    write_u64_le(package + off, num_blocks); off += 8;
    memcpy(package + off, file_hash_plaintext, MC_HASH_SIZE); off += MC_HASH_SIZE;
    memcpy(package + off, file_hash_ciphertext, MC_HASH_SIZE); off += MC_HASH_SIZE;
    memcpy(package + off, ct_bytes, ct_int_count * 8); off += ct_int_count * 8;
    free(ct_bytes);

    if (cli_write_file(output_path, package, total_len) != 0) {
        fprintf(stderr, "Error: could not write output file '%s'\n", output_path);
        free(package);
        return 1;
    }
    free(package);

    fprintf(stderr, "Encrypted '%s' -> '%s' (n=%d, %llu block(s))\n",
            input_path, output_path, n, (unsigned long long)num_blocks);
    return 0;
}
