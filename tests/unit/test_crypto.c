/* ===========================================================================
 * test_crypto.c - unit tests for hashing and key derivation:
 * SHA-256, Argon2id-based key seed derivation, and SHAKE-256-based key
 * matrix generation.
 * ===========================================================================
 */

#include "test_framework.h"
#include "mountain_cipher.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void bytes_to_hex(const uint8_t *bytes, size_t len, char *out_hex) {
    static const char *hex = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out_hex[i * 2]     = hex[(bytes[i] >> 4) & 0xF];
        out_hex[i * 2 + 1] = hex[bytes[i] & 0xF];
    }
    out_hex[len * 2] = '\0';
}

static void test_sha256_known_vectors(void) {
    fprintf(stderr, "test_sha256_known_vectors:\n");

    /* SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85 */
    uint8_t out[MC_HASH_SIZE];
    char hex[MC_HASH_SIZE * 2 + 1];
    mc_status_t st = mc_sha256_buffer((const uint8_t *)"", 0, out);
    bytes_to_hex(out, MC_HASH_SIZE, hex);
    MC_CHECK(st == MC_OK, "sha256 of empty buffer succeeds");
    MC_CHECK(strcmp(hex, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == 0,
              "sha256(\"\") matches the known test vector");

    /* SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad */
    st = mc_sha256_buffer((const uint8_t *)"abc", 3, out);
    bytes_to_hex(out, MC_HASH_SIZE, hex);
    MC_CHECK(st == MC_OK, "sha256 of \"abc\" succeeds");
    MC_CHECK(strcmp(hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") == 0,
              "sha256(\"abc\") matches the known test vector");
}

static void test_sha256_file(void) {
    fprintf(stderr, "test_sha256_file:\n");
    /* This was "/tmp/mc_test_sha256_file.txt", which does not exist on
     * Windows - where this project is developed - so three checks failed
     * on the author's own machine and `make test` had never been green
     * there. The working directory is writable on every platform the
     * suite runs on, and the runner is already in it. */
    const char *path = "mc_test_sha256_file.tmp";
    FILE *f = fopen(path, "wb");
    MC_CHECK(f != NULL, "can create temp file for hashing test");
    if (f) {
        fwrite("abc", 1, 3, f);
        fclose(f);
    }

    uint8_t out_file[MC_HASH_SIZE];
    uint8_t out_buf[MC_HASH_SIZE];
    mc_status_t st1 = mc_sha256_file(path, out_file);
    mc_status_t st2 = mc_sha256_buffer((const uint8_t *)"abc", 3, out_buf);
    MC_CHECK(st1 == MC_OK && st2 == MC_OK, "both file and buffer hashing succeed");
    MC_CHECK(memcmp(out_file, out_buf, MC_HASH_SIZE) == 0,
              "hashing a file gives the same result as hashing its bytes directly");

    remove(path);

    uint8_t missing[MC_HASH_SIZE];
    MC_CHECK(mc_sha256_file("mc_this_file_should_not_exist.tmp", missing) != MC_OK,
              "hashing a nonexistent file returns an error, not a crash");

    /* An empty file must hash to the empty-input digest rather than
     * failing: encrypting a zero-length file is a supported case, and
     * this is where its plaintext hash comes from. */
    FILE *e = fopen(path, "wb");
    if (e) fclose(e);
    uint8_t empty_hash[MC_HASH_SIZE], expected_empty[MC_HASH_SIZE];
    mc_status_t est = mc_sha256_file(path, empty_hash);
    mc_sha256_buffer((const uint8_t *)"", 0, expected_empty);
    MC_CHECK(est == MC_OK && memcmp(empty_hash, expected_empty, MC_HASH_SIZE) == 0,
              "an empty file hashes to the empty-input digest");
    remove(path);

    /* The streaming path reads in 64 KiB chunks, so anything that only
     * ever hashes short files never crosses a buffer boundary. */
    FILE *big = fopen(path, "wb");
    MC_CHECK(big != NULL, "can create a file larger than the read buffer");
    if (big) {
        uint8_t *chunk = (uint8_t *)malloc(70000);
        for (size_t i = 0; i < 70000; i++) chunk[i] = (uint8_t)(i * 31);
        fwrite(chunk, 1, 70000, big);
        fclose(big);

        uint8_t from_file[MC_HASH_SIZE], from_buffer[MC_HASH_SIZE];
        mc_status_t fst = mc_sha256_file(path, from_file);
        mc_sha256_buffer(chunk, 70000, from_buffer);
        MC_CHECK(fst == MC_OK && memcmp(from_file, from_buffer, MC_HASH_SIZE) == 0,
                  "a file spanning several read buffers hashes correctly");
        free(chunk);
        remove(path);
    }
}

static void test_argon2_key_seed_derivation(void) {
    fprintf(stderr, "test_argon2_key_seed_derivation:\n");

    uint8_t salt[MC_HASH_SIZE];
    memset(salt, 0xAB, sizeof(salt));

    uint8_t seed1[MC_SEED_SIZE];
    uint8_t seed2[MC_SEED_SIZE];
    mc_status_t st1 = mc_derive_key_seed("same-password", salt, seed1);
    mc_status_t st2 = mc_derive_key_seed("same-password", salt, seed2);
    MC_CHECK(st1 == MC_OK && st2 == MC_OK, "key seed derivation succeeds");
    MC_CHECK(memcmp(seed1, seed2, MC_SEED_SIZE) == 0,
              "same password + same salt -> same key seed (deterministic)");

    uint8_t seed3[MC_SEED_SIZE];
    mc_derive_key_seed("different-password", salt, seed3);
    MC_CHECK(memcmp(seed1, seed3, MC_SEED_SIZE) != 0,
              "different password -> different key seed");

    uint8_t salt2[MC_HASH_SIZE];
    memset(salt2, 0xCD, sizeof(salt2));
    uint8_t seed4[MC_SEED_SIZE];
    mc_derive_key_seed("same-password", salt2, seed4);
    MC_CHECK(memcmp(seed1, seed4, MC_SEED_SIZE) != 0,
              "same password but different salt (file hash) -> different key seed");
}

static void test_argon2_parameters_are_pinned(void) {
    fprintf(stderr, "test_argon2_parameters_are_pinned:\n");

    /* Argon2id with this project's parameters - t=3, m=64 MiB, p=1, a
     * 32-byte output - for the password "mountain" and a printable
     * 32-byte salt. Cross-checked against the reference implementation's
     * own command-line tool:
     *
     *   printf mountain | argon2 0123456789abcdef0123456789abcdef \
     *       -id -t 3 -m 16 -p 1 -l 32 -r
     *
     * so this is an independent vector, not a recording of what this code
     * happens to print.
     *
     * It matters because the parameters are not stored in the container.
     * Changing any of them - tuning the cost upwards, say - silently makes
     * every file ever encrypted by an older build undecryptable, with no
     * error that points at the cause. This check turns that into a failed
     * test at the moment the parameter changes. */
    static const char *salt_text = "0123456789abcdef0123456789abcdef";
    static const uint8_t expected[MC_SEED_SIZE] = {
        0x11, 0xec, 0xba, 0x6c, 0x44, 0x36, 0xc6, 0xd6,
        0x74, 0x36, 0xe8, 0x56, 0xa4, 0x77, 0x15, 0x25,
        0x7b, 0xf5, 0xc1, 0x1c, 0xa7, 0x45, 0x2b, 0x28,
        0x76, 0x1e, 0xf5, 0xae, 0xca, 0x02, 0xae, 0x12
    };

    uint8_t seed[MC_SEED_SIZE];
    mc_status_t st = mc_derive_key_seed("mountain", (const uint8_t *)salt_text, seed);
    MC_CHECK(st == MC_OK, "key seed derivation succeeds for the pinned vector");
    MC_CHECK(st == MC_OK && memcmp(seed, expected, MC_SEED_SIZE) == 0,
              "Argon2id output matches the reference implementation "
              "(t=3, m=64MiB, p=1) - if this fails, older files can no longer be opened");
}

static void test_key_matrix_generation(void) {
    fprintf(stderr, "test_key_matrix_generation:\n");

    uint8_t seed[MC_SEED_SIZE];
    for (int i = 0; i < MC_SEED_SIZE; i++) seed[i] = (uint8_t)(i * 3 + 1);

    for (int n = 2; n <= 6; n++) {
        mc_matrix_t key;
        mc_status_t st = mc_generate_key_matrix(n, seed, &key);
        char msg[64];
        snprintf(msg, sizeof(msg), "key generation for n=%d succeeds", n);
        MC_CHECK(st == MC_OK, msg);
        if (st == MC_OK) {
            int64_t det;
            mc_determinant(&key, &det);
            snprintf(msg, sizeof(msg), "generated n=%d key has nonzero determinant", n);
            MC_CHECK(det != 0, msg);
            mc_matrix_free(&key);
        }
    }

    /* Determinism: same seed and n -> identical key matrix every time */
    mc_matrix_t key_a, key_b;
    mc_generate_key_matrix(4, seed, &key_a);
    mc_generate_key_matrix(4, seed, &key_b);
    MC_CHECK(memcmp(key_a.data, key_b.data, sizeof(int64_t) * 16) == 0,
              "same seed + n -> identical key matrix (determinism)");
    mc_matrix_free(&key_a);
    mc_matrix_free(&key_b);

    /* Different seed -> (overwhelmingly likely) different key matrix */
    uint8_t seed_other[MC_SEED_SIZE];
    for (int i = 0; i < MC_SEED_SIZE; i++) seed_other[i] = (uint8_t)(i * 5 + 2);
    mc_matrix_t key_c;
    mc_generate_key_matrix(4, seed_other, &key_c);
    mc_generate_key_matrix(4, seed, &key_a);
    MC_CHECK(memcmp(key_a.data, key_c.data, sizeof(int64_t) * 16) != 0,
              "different seed -> different key matrix");
    mc_matrix_free(&key_a);
    mc_matrix_free(&key_c);
}

static void test_end_to_end_key_derivation_pipeline(void) {
    fprintf(stderr, "test_end_to_end_key_derivation_pipeline:\n");
    /* Mirrors Phase 1.1 -> 1.2 -> 1.3 exactly, to catch integration bugs
     * between the individual pieces. */
    uint8_t file_hash[MC_HASH_SIZE];
    mc_sha256_buffer((const uint8_t *)"pretend file contents", 22, file_hash);

    uint8_t seed[MC_SEED_SIZE];
    mc_status_t st = mc_derive_key_seed("hunter2", file_hash, seed);
    MC_CHECK(st == MC_OK, "end-to-end: argon2id derivation succeeds");

    mc_matrix_t key;
    st = mc_generate_key_matrix(4, seed, &key);
    MC_CHECK(st == MC_OK, "end-to-end: key matrix generation succeeds");
    int64_t det;
    mc_determinant(&key, &det);
    MC_CHECK(det != 0, "end-to-end: resulting key is invertible");
    mc_matrix_free(&key);

    /* Regenerating with the same password + file hash (as decryption
     * does in Phase 4.2) must reproduce the exact same key. */
    uint8_t seed2[MC_SEED_SIZE];
    mc_derive_key_seed("hunter2", file_hash, seed2);
    mc_matrix_t key2;
    mc_generate_key_matrix(4, seed2, &key2);
    mc_matrix_t key1;
    mc_generate_key_matrix(4, seed, &key1);
    MC_CHECK(memcmp(key1.data, key2.data, sizeof(int64_t) * 16) == 0,
              "end-to-end: regenerated key (decryption side) matches original (encryption side)");
    mc_matrix_free(&key1);
    mc_matrix_free(&key2);
}

int main(void) {
    test_sha256_known_vectors();
    test_sha256_file();
    test_argon2_key_seed_derivation();
    test_argon2_parameters_are_pinned();
    test_key_matrix_generation();
    test_end_to_end_key_derivation_pipeline();
    MC_TEST_EXIT();
}
