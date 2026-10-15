/* ===========================================================================
 * mountain_cipher.h
 *
 * Mountain Cipher - a Hill-cipher-inspired block cipher built from
 * classical linear algebra (determinants, adjugates, elementary row
 * operations) instead of modular arithmetic.
 *
 * This is a student research/proof-of-concept project. It is NOT a
 * production cryptographic primitive. See README.md for the full
 * background and a frank list of known weaknesses.
 * ===========================================================================
 */

#ifndef MOUNTAIN_CIPHER_H
#define MOUNTAIN_CIPHER_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---------------------------------------------------------------------
 * Constants
 * --------------------------------------------------------------------- */

#define MC_HASH_SIZE      32   /* SHA-256 digest size, in bytes            */
#define MC_SEED_SIZE      32   /* Argon2id output size used as XOF seed    */
#define MC_MAGIC          "MTNC"   /* 4-byte file magic                    */
#define MC_FORMAT_VERSION 1

/* Safety cap on matrix dimension. Adjugate computation here uses
 * cofactor expansion, which is O(n!) - keep n small (<= 8) in practice.
 * See README "Known Limitations" for why this matters.
 */
#define MC_MAX_N 12

/* ---------------------------------------------------------------------
 * Types
 * --------------------------------------------------------------------- */

/* Square integer matrix, n x n, row-major backing store. */
typedef struct {
    int n;
    int64_t *data; /* data[i*n + j] = entry (i, j) */
} mc_matrix_t;

/* Result codes returned by Mountain Cipher functions. */
typedef enum {
    MC_OK = 0,
    MC_ERR_IO = -1,
    MC_ERR_ALLOC = -2,
    MC_ERR_ARGON2 = -3,
    MC_ERR_BAD_DIMENSION = -4,
    MC_ERR_SINGULAR_KEY = -5,
    MC_ERR_INTEGRITY_CIPHERTEXT = -6,   /* ciphertext hash mismatch        */
    MC_ERR_INTEGRITY_PLAINTEXT = -7,    /* wrong password / corrupt data   */
    MC_ERR_BAD_FORMAT = -8,             /* malformed container file        */
    MC_ERR_NON_EXACT_DIVISION = -9,     /* internal consistency failure    */
    MC_ERR_OVERFLOW_GUARD = -10,        /* value exceeded safe range       */
    MC_ERR_NOT_RECOVERABLE = -11        /* ciphertext would not decrypt    */
} mc_status_t;

/* ---------------------------------------------------------------------
 * Matrix helpers (Phase 2 / Phase 5 building blocks)
 * --------------------------------------------------------------------- */

mc_status_t mc_matrix_alloc(mc_matrix_t *m, int n);
void        mc_matrix_free(mc_matrix_t *m);
mc_status_t mc_matrix_copy(const mc_matrix_t *src, mc_matrix_t *dst);

/* Returns a newly allocated transpose of m in *out. */
mc_status_t mc_matrix_transpose(const mc_matrix_t *m, mc_matrix_t *out);

/* out = a * b (standard integer matrix multiplication, no floats). */
mc_status_t mc_matrix_multiply(const mc_matrix_t *a, const mc_matrix_t *b,
                                mc_matrix_t *out);

/* Exact integer determinant via the Bareiss fraction-free algorithm. */
mc_status_t mc_determinant(const mc_matrix_t *m, int64_t *det_out);

/* Classical adjugate (transpose of the cofactor matrix), computed via
 * cofactor expansion of (n-1)x(n-1) minors. O(n!) - see MC_MAX_N. */
mc_status_t mc_adjugate(const mc_matrix_t *m, mc_matrix_t *out);

/* Step 2.2 / 5.2 - the "even d" row mutation, applied to a per-block
 * WORKING KEY (a fresh copy of the original, immutable key - never the
 * previous block's working key):
 *   R_i <- R_i + sum_{k != i} (-1)^(k+1) * R_k
 * Applied in place to `m`. i must be in [0, n). Note R_i is included in
 * its own replacement - this is what makes it a genuine elementary
 * Type III row operation (add a linear combination of other rows to a
 * row), which provably leaves det(m) unchanged. */
mc_status_t mc_row_mutation_even(mc_matrix_t *m, int i);

/* Step 2.2 / 5.2 - the "odd d" mutation: transpose in place. Like
 * mc_row_mutation_even, this is meant to be applied to a disposable
 * per-block working-key copy, not to the original key. */
mc_status_t mc_transpose_in_place(mc_matrix_t *m);

/* Step 2.3 / 5.3 - cyclic column shift of an n x n matrix.
 * positive `shift` = shift left (encryption), negative = shift right
 * (decryption), values are taken mod n. */
mc_status_t mc_cyclic_column_shift(mc_matrix_t *m, int shift);

/* ---------------------------------------------------------------------
 * Hashing (Phase 1 / Phase 3 / Phase 4 / Phase 6)
 * --------------------------------------------------------------------- */

mc_status_t mc_sha256_file(const char *path, uint8_t out[MC_HASH_SIZE]);
mc_status_t mc_sha256_buffer(const uint8_t *buf, size_t len,
                              uint8_t out[MC_HASH_SIZE]);

/* ---------------------------------------------------------------------
 * Key derivation (Phase 1.2 / 1.3, Phase 4.2)
 * --------------------------------------------------------------------- */

/* key_seed = Argon2id(password, salt = file_hash_plaintext) */
mc_status_t mc_derive_key_seed(const char *password,
                                const uint8_t salt[MC_HASH_SIZE],
                                uint8_t out_seed[MC_SEED_SIZE]);

/* Deterministically expand key_seed with SHAKE-256 (XOF) into an n x n
 * key matrix, retrying with an incrementing counter appended to the XOF
 * input whenever det(key) == 0, exactly as Step 1.3 specifies. */
mc_status_t mc_generate_key_matrix(int n, const uint8_t seed[MC_SEED_SIZE],
                                    mc_matrix_t *key_out);

/* ---------------------------------------------------------------------
 * Padding (Phase 1.4 / Phase 6.1)
 * --------------------------------------------------------------------- */

/* Returns a newly malloc'd buffer containing data padded with PKCS#7 to
 * a multiple of block_size. Caller frees the result. *out_len receives
 * the padded length. */
uint8_t *mc_pkcs7_pad(const uint8_t *data, size_t len, size_t block_size,
                       size_t *out_len);

/* Validates and strips PKCS#7 padding. Returns the unpadded length, or
 * -1 if the padding is invalid (used to detect corruption/tampering). */
long mc_pkcs7_unpad_len(const uint8_t *data, size_t len, size_t block_size);

/* ---------------------------------------------------------------------
 * Block pipeline (Phase 2 / Phase 5)
 * --------------------------------------------------------------------- */

/* Step 2.2 / 5.2 - derive this block's disposable working key from the
 * original key and the control determinant `d`. Odd d transposes; even d
 * applies the row mutation at row (d mod n). Both branches preserve
 * det(key), so the result is always invertible.
 *
 * Encryption and decryption MUST agree on this exactly or a file cannot
 * be recovered, which is why it lives here rather than being written out
 * once in each CLI. */
mc_status_t mc_block_work_key(const mc_matrix_t *key, int64_t d,
                               mc_matrix_t *work_out);

/* Phase 2 - encrypt `padded_len` bytes (which must be a whole number of
 * n*n-byte blocks) into `out`, which receives num_blocks * n*n int64
 * entries in row-major order, block after block.
 *
 * Returns MC_ERR_OVERFLOW_GUARD if any intermediate leaves the safe
 * 64-bit range. See mc_encrypt_is_recoverable() - a successful return
 * here is NOT on its own a promise that the result can be decrypted. */
mc_status_t mc_encrypt_blocks(const mc_matrix_t *key,
                               const uint8_t *padded, size_t padded_len,
                               int64_t *out);

/* Phase 5 - decrypt `num_blocks` blocks of n*n int64 entries into `out`,
 * which receives num_blocks * n*n bytes (still padded; strip with
 * mc_pkcs7_unpad_len). */
mc_status_t mc_decrypt_blocks(const mc_matrix_t *key, const int64_t *ct,
                               size_t num_blocks, uint8_t *out);

/* Confirms that ciphertext just produced by mc_encrypt_blocks() actually
 * decrypts back to `padded`, and returns MC_OK only if it does.
 *
 * This exists because encryption and decryption do not fail together.
 * Encryption multiplies key entries (|x| <= 128) by plaintext bytes and
 * stays comfortably inside int64; decryption multiplies by the ADJUGATE,
 * whose entries grow factorially with n, and can therefore trip the
 * overflow guard on a file that encrypted without complaint. Calling this
 * before reporting success turns a file that can never be decrypted into
 * an error the user sees while they still have the original. */
mc_status_t mc_encrypt_is_recoverable(const mc_matrix_t *key,
                                       const uint8_t *padded, size_t padded_len,
                                       const int64_t *ct);

/* ---------------------------------------------------------------------
 * Memory hygiene
 * --------------------------------------------------------------------- */

/* Overwrites `len` bytes at `p` with zeros through a volatile pointer, so
 * that the compiler may not treat the store as dead and remove it. A
 * plain memset() of a buffer that is freed or goes out of scope
 * immediately afterwards IS removed at -O2 - see README. */
void mc_secure_wipe(void *p, size_t len);

/* ---------------------------------------------------------------------
 * Error reporting
 * --------------------------------------------------------------------- */

/* Returns a short, static, human-readable description of a status code. */
const char *mc_strerror(mc_status_t status);

#ifdef __cplusplus
}
#endif

#endif /* MOUNTAIN_CIPHER_H */
