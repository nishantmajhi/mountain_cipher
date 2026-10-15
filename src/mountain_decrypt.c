/* ===========================================================================
 * mountain_decrypt.c
 *
 * Command-line decryption tool implementing Phases 4-6 of the Mountain
 * Cipher algorithm (see mountain_cipher_algorithm.md and README.md).
 *
 * Reads the container format written by mountain_encrypt (see comment
 * at the top of mountain_encrypt.c for the byte layout).
 *
 * Usage:
 *   mountain_decrypt <input_file> <output_file>
 * ===========================================================================
 */

#include "mountain_cipher.h"
#include "cli_util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static uint64_t read_u64_le(const uint8_t *in) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v |= ((uint64_t)in[i]) << (8 * i);
    return v;
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <input_file> <output_file>\n", argv[0]);
        return 1;
    }
    const char *input_path = argv[1];
    const char *output_path = argv[2];

    size_t file_len = 0;
    uint8_t *package = cli_read_file(input_path, &file_len);
    if (!package) {
        fprintf(stderr, "Error: could not read input file '%s'\n", input_path);
        return 1;
    }

    size_t header_len = 4 + 1 + 1 + 8 + MC_HASH_SIZE + MC_HASH_SIZE;
    if (file_len < header_len || memcmp(package, MC_MAGIC, 4) != 0) {
        fprintf(stderr, "Error: not a valid Mountain Cipher file (bad magic/size)\n");
        free(package);
        return 1;
    }

    size_t off = 4;
    uint8_t version = package[off++];
    if (version != MC_FORMAT_VERSION) {
        fprintf(stderr, "Error: unsupported format version %u\n", version);
        free(package);
        return 1;
    }
    int n = package[off++];
    uint64_t num_blocks = read_u64_le(package + off); off += 8;
    uint8_t file_hash_plaintext[MC_HASH_SIZE];
    memcpy(file_hash_plaintext, package + off, MC_HASH_SIZE); off += MC_HASH_SIZE;
    uint8_t file_hash_ciphertext[MC_HASH_SIZE];
    memcpy(file_hash_ciphertext, package + off, MC_HASH_SIZE); off += MC_HASH_SIZE;

    if (n <= 1 || n > MC_MAX_N) {
        fprintf(stderr, "Error: corrupt file, invalid n=%d\n", n);
        free(package);
        return 1;
    }
    size_t block_bytes = (size_t)n * (size_t)n;

    /* num_blocks comes straight off disk, so it is attacker-controlled.
     * Reject values that cannot describe a real file before doing any
     * arithmetic with them: the encryptor always pads, so it never emits
     * zero blocks, and anything large enough to wrap num_blocks *
     * block_bytes * 8 would otherwise be caught only by a very large
     * malloc happening to fail. */
    if (num_blocks == 0) {
        fprintf(stderr, "Error: corrupt file, no ciphertext blocks\n");
        free(package);
        return 1;
    }
    if (num_blocks > (UINT64_MAX / 8) / (uint64_t)block_bytes ||
        (uint64_t)num_blocks * (uint64_t)block_bytes * 8u >
            (uint64_t)(SIZE_MAX - header_len)) {
        fprintf(stderr, "Error: corrupt file, implausible block count\n");
        free(package);
        return 1;
    }

    size_t ct_int_count = (size_t)num_blocks * block_bytes;
    size_t expected_len = header_len + ct_int_count * 8;
    if (file_len != expected_len) {
        fprintf(stderr, "Error: corrupt file, size mismatch\n");
        free(package);
        return 1;
    }
    const uint8_t *ct_bytes = package + off;

    /* ---- Step 4.1: verify ciphertext integrity BEFORE touching the key ---- */
    uint8_t computed_ct_hash[MC_HASH_SIZE];
    if (mc_sha256_buffer(ct_bytes, ct_int_count * 8, computed_ct_hash) != MC_OK) {
        fprintf(stderr, "Error: hashing ciphertext failed\n");
        free(package);
        return 1;
    }
    if (memcmp(computed_ct_hash, file_hash_ciphertext, MC_HASH_SIZE) != 0) {
        fprintf(stderr, "Error: ciphertext integrity check FAILED - file was tampered with or corrupted. Aborting.\n");
        free(package);
        return 1;
    }

    /* ---- Step 4.3: read the ciphertext blocks into int64 entries ---- */
    int64_t *ct = (int64_t *)malloc(ct_int_count * sizeof(int64_t));
    if (!ct) {
        fprintf(stderr, "Error: allocation failed\n");
        free(package);
        return 1;
    }
    for (size_t idx = 0; idx < ct_int_count; idx++) {
        ct[idx] = (int64_t)read_u64_le(ct_bytes + idx * 8);
    }

    char *password = cli_read_password("Password: ");
    if (!password) {
        fprintf(stderr, "Error: could not read password (see the message above)\n");
        free(ct); free(package);
        return 1;
    }

    /* ---- Step 4.2: regenerate the key ---- */
    uint8_t key_seed[MC_SEED_SIZE];
    mc_status_t derive_st = mc_derive_key_seed(password, file_hash_plaintext, key_seed);
    mc_secure_wipe(password, strlen(password));
    free(password);
    if (derive_st != MC_OK) {
        fprintf(stderr, "Error: Argon2id key derivation failed\n");
        mc_secure_wipe(key_seed, sizeof(key_seed));
        free(ct); free(package);
        return 1;
    }

    /* `key` is fixed from here on - it is never overwritten or mutated in
     * place; each block derives a disposable `work_key` copy from it
     * instead, exactly mirroring encryption's Step 2.2. */
    mc_matrix_t key;
    mc_status_t gen_st = mc_generate_key_matrix(n, key_seed, &key);
    mc_secure_wipe(key_seed, sizeof(key_seed));
    if (gen_st != MC_OK) {
        fprintf(stderr, "Error: key matrix generation failed: %s\n", mc_strerror(gen_st));
        free(ct); free(package);
        return 1;
    }

    /* ---- Phase 5: decrypt every block ---- */
    uint8_t *plaintext_padded = (uint8_t *)malloc(ct_int_count);
    if (!plaintext_padded) {
        fprintf(stderr, "Error: allocation failed\n");
        mc_matrix_free(&key);
        free(ct); free(package);
        return 1;
    }

    mc_status_t st = mc_decrypt_blocks(&key, ct, (size_t)num_blocks, plaintext_padded);
    mc_matrix_free(&key);
    free(ct);
    free(package);
    if (st != MC_OK) {
        fprintf(stderr, "Error: decryption failed: %s\n", mc_strerror(st));
        mc_secure_wipe(plaintext_padded, ct_int_count);
        free(plaintext_padded);
        return 1;
    }

    /* ---- Phase 6: reassemble, strip padding, verify ---- */
    long unpadded_len = mc_pkcs7_unpad_len(plaintext_padded, ct_int_count, block_bytes);
    if (unpadded_len < 0) {
        fprintf(stderr, "Error: padding invalid - wrong password or corrupted data.\n");
        mc_secure_wipe(plaintext_padded, ct_int_count);
        free(plaintext_padded);
        return 1;
    }

    uint8_t computed_pt_hash[MC_HASH_SIZE];
    if (mc_sha256_buffer(plaintext_padded, (size_t)unpadded_len, computed_pt_hash) != MC_OK) {
        fprintf(stderr, "Error: hashing plaintext failed\n");
        mc_secure_wipe(plaintext_padded, ct_int_count);
        free(plaintext_padded);
        return 1;
    }
    if (memcmp(computed_pt_hash, file_hash_plaintext, MC_HASH_SIZE) != 0) {
        fprintf(stderr, "Error: plaintext integrity check FAILED - wrong password or corrupted data.\n");
        mc_secure_wipe(plaintext_padded, ct_int_count);
        free(plaintext_padded);
        return 1;
    }

    if (cli_write_file(output_path, plaintext_padded, (size_t)unpadded_len) != 0) {
        fprintf(stderr, "Error: could not write output file '%s'\n", output_path);
        mc_secure_wipe(plaintext_padded, ct_int_count);
        free(plaintext_padded);
        return 1;
    }
    mc_secure_wipe(plaintext_padded, ct_int_count);
    free(plaintext_padded);

    fprintf(stderr, "Decrypted '%s' -> '%s' (integrity verified)\n", input_path, output_path);
    return 0;
}
