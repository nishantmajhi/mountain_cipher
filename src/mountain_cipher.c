/* ===========================================================================
 * mountain_cipher.c - core algorithm implementation
 *
 * Implements every step described in mountain_cipher_algorithm.md:
 *   - Bareiss fraction-free determinant (exact integers, no floats)
 *   - Cofactor-expansion adjugate
 *   - The "odd d -> transpose" / "even d -> R_i + alternating row sum"
 *     mutation, always applied to a disposable per-block working-key
 *     copy - the original key generated in Phase 1.3 is never itself
 *     overwritten (see docs/mountain_cipher_algorithm.md's Definitions table)
 *   - Cyclic column shifting
 *   - SHA-256 hashing (via OpenSSL EVP)
 *   - Argon2id key-seed derivation (via libargon2)
 *   - SHAKE-256 key matrix generation (via OpenSSL EVP_shake256)
 *   - PKCS#7 padding
 * ===========================================================================
 */

#include "mountain_cipher.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <openssl/evp.h>
#include <argon2.h>

/* ---------------------------------------------------------------------
 * Matrix helpers
 * --------------------------------------------------------------------- */

#define MC_AT(m, i, j) ((m)->data[(size_t)(i) * (size_t)(m)->n + (size_t)(j)])

mc_status_t mc_matrix_alloc(mc_matrix_t *m, int n) {
    if (!m || n <= 0 || n > MC_MAX_N) return MC_ERR_BAD_DIMENSION;
    m->n = n;
    m->data = (int64_t *)calloc((size_t)n * (size_t)n, sizeof(int64_t));
    if (!m->data) return MC_ERR_ALLOC;
    return MC_OK;
}

void mc_matrix_free(mc_matrix_t *m) {
    if (!m) return;
    free(m->data);
    m->data = NULL;
    m->n = 0;
}

mc_status_t mc_matrix_copy(const mc_matrix_t *src, mc_matrix_t *dst) {
    if (!src || !dst) return MC_ERR_BAD_DIMENSION;
    mc_status_t st = mc_matrix_alloc(dst, src->n);
    if (st != MC_OK) return st;
    memcpy(dst->data, src->data, sizeof(int64_t) * (size_t)src->n * (size_t)src->n);
    return MC_OK;
}

mc_status_t mc_matrix_transpose(const mc_matrix_t *m, mc_matrix_t *out) {
    if (!m || !out) return MC_ERR_BAD_DIMENSION;
    mc_status_t st = mc_matrix_alloc(out, m->n);
    if (st != MC_OK) return st;
    for (int i = 0; i < m->n; i++)
        for (int j = 0; j < m->n; j++)
            MC_AT(out, i, j) = MC_AT(m, j, i);
    return MC_OK;
}

mc_status_t mc_transpose_in_place(mc_matrix_t *key) {
    if (!key) return MC_ERR_BAD_DIMENSION;
    mc_matrix_t tmp;
    mc_status_t st = mc_matrix_transpose(key, &tmp);
    if (st != MC_OK) return st;
    memcpy(key->data, tmp.data, sizeof(int64_t) * (size_t)key->n * (size_t)key->n);
    mc_matrix_free(&tmp);
    return MC_OK;
}

mc_status_t mc_matrix_multiply(const mc_matrix_t *a, const mc_matrix_t *b,
                                mc_matrix_t *out) {
    if (!a || !b || !out || a->n != b->n) return MC_ERR_BAD_DIMENSION;
    int n = a->n;
    mc_status_t st = mc_matrix_alloc(out, n);
    if (st != MC_OK) return st;
    for (int i = 0; i < n; i++) {
        for (int j = 0; j < n; j++) {
            /* Accumulate in __int128: a dot product of n terms, each
             * itself a product of two int64 values, can overflow
             * int64 well before the final sum does for larger n or
             * larger intermediate matrix entries (e.g. adjugate
             * entries during decryption). Check range before the
             * narrowing store back to int64. */
            __int128 sum = 0;
            for (int k = 0; k < n; k++) {
                sum += (__int128)MC_AT(a, i, k) * (__int128)MC_AT(b, k, j);
            }
            if (sum > (__int128)INT64_MAX || sum < (__int128)INT64_MIN) {
                mc_matrix_free(out);
                return MC_ERR_OVERFLOW_GUARD;
            }
            MC_AT(out, i, j) = (int64_t)sum;
        }
    }
    return MC_OK;
}

/* Bareiss fraction-free determinant algorithm - stays in exact integers
 * throughout, never touching floating point, as the spec requires.
 *
 * Implementation note: the Bareiss recurrence's intermediate
 * "numerator" term (W(i,j)*W(k,k) - W(i,k)*W(k,j)) can temporarily
 * exceed the range of int64_t even when every matrix entry and the
 * final determinant comfortably fit in it - two int64 products summed
 * together can overflow well before the exact-division step brings the
 * magnitude back down. To avoid silently wrapping around (which
 * produces a wrong, wrapped determinant with no indication anything
 * went wrong), this computes that one line in __int128 and only writes
 * back to the int64 working matrix after confirming exact divisibility
 * and that the quotient still fits in int64_t. If it doesn't, this
 * returns MC_ERR_OVERFLOW_GUARD rather than a silently wrong answer. */
mc_status_t mc_determinant(const mc_matrix_t *m, int64_t *det_out) {
    if (!m || !det_out) return MC_ERR_BAD_DIMENSION;
    int n = m->n;
    if (n == 1) { *det_out = MC_AT(m, 0, 0); return MC_OK; }

    int64_t *work = (int64_t *)malloc(sizeof(int64_t) * (size_t)n * (size_t)n);
    if (!work) return MC_ERR_ALLOC;
    memcpy(work, m->data, sizeof(int64_t) * (size_t)n * (size_t)n);

    int sign = 1;
    int64_t prev_pivot = 1;

#define W(i, j) work[(size_t)(i) * (size_t)n + (size_t)(j)]

    for (int k = 0; k < n - 1; k++) {
        if (W(k, k) == 0) {
            int swap_row = -1;
            for (int r = k + 1; r < n; r++) {
                if (W(r, k) != 0) { swap_row = r; break; }
            }
            if (swap_row == -1) {
                free(work);
                *det_out = 0;
                return MC_OK; /* singular */
            }
            for (int c = 0; c < n; c++) {
                int64_t t = W(k, c);
                W(k, c) = W(swap_row, c);
                W(swap_row, c) = t;
            }
            sign = -sign;
        }

        for (int i = k + 1; i < n; i++) {
            for (int j = k + 1; j < n; j++) {
                __int128 wij = (__int128)W(i, j);
                __int128 wkk = (__int128)W(k, k);
                __int128 wik = (__int128)W(i, k);
                __int128 wkj = (__int128)W(k, j);
                __int128 numerator = wij * wkk - wik * wkj;
                __int128 pivot = (__int128)prev_pivot;

                if (numerator % pivot != 0) {
                    /* Should be mathematically impossible per the
                     * Bareiss guarantee; treat as an internal error
                     * rather than silently truncating. */
                    free(work);
                    return MC_ERR_NON_EXACT_DIVISION;
                }
                __int128 quotient = numerator / pivot;
                if (quotient > (__int128)INT64_MAX || quotient < (__int128)INT64_MIN) {
                    free(work);
                    return MC_ERR_OVERFLOW_GUARD;
                }
                W(i, j) = (int64_t)quotient;
            }
        }
        prev_pivot = W(k, k);
    }

    int64_t det = (int64_t)sign * W(n - 1, n - 1);
#undef W
    free(work);
    *det_out = det;
    return MC_OK;
}

/* Cofactor-expansion adjugate. Builds each (n-1)x(n-1) minor and takes
 * its Bareiss determinant. O(n!) - fine for the small n this project
 * targets (see MC_MAX_N), not intended to scale further. */
mc_status_t mc_adjugate(const mc_matrix_t *m, mc_matrix_t *out) {
    if (!m || !out) return MC_ERR_BAD_DIMENSION;
    int n = m->n;
    mc_status_t st = mc_matrix_alloc(out, n);
    if (st != MC_OK) return st;

    if (n == 1) {
        MC_AT(out, 0, 0) = 1;
        return MC_OK;
    }

    mc_matrix_t minor;
    st = mc_matrix_alloc(&minor, n - 1);
    if (st != MC_OK) { mc_matrix_free(out); return st; }

    for (int row = 0; row < n; row++) {
        for (int col = 0; col < n; col++) {
            /* Build minor by deleting `row` and `col` from m */
            int mi = 0;
            for (int i = 0; i < n; i++) {
                if (i == row) continue;
                int mj = 0;
                for (int j = 0; j < n; j++) {
                    if (j == col) continue;
                    MC_AT(&minor, mi, mj) = MC_AT(m, i, j);
                    mj++;
                }
                mi++;
            }
            int64_t minor_det;
            st = mc_determinant(&minor, &minor_det);
            if (st != MC_OK) { mc_matrix_free(&minor); mc_matrix_free(out); return st; }
            int64_t cofactor = ((row + col) % 2 == 0) ? minor_det : -minor_det;
            /* adjugate = TRANSPOSE of cofactor matrix -> write at (col, row) */
            MC_AT(out, col, row) = cofactor;
        }
    }
    mc_matrix_free(&minor);
    return MC_OK;
}

mc_status_t mc_row_mutation_even(mc_matrix_t *m, int i) {
    if (!m || i < 0 || i >= m->n) return MC_ERR_BAD_DIMENSION;
    int n = m->n;
    int64_t *new_row = (int64_t *)calloc((size_t)n, sizeof(int64_t));
    if (!new_row) return MC_ERR_ALLOC;

    /* R_i <- R_i + sum_{k != i} (-1)^(k+1) * R_k
     * R_i is deliberately included in its own replacement: this is a
     * Type III elementary row operation (add a linear combination of
     * the OTHER rows to row i), which is what guarantees det(m) is
     * unchanged. */
    for (int c = 0; c < n; c++) {
        new_row[c] = MC_AT(m, i, c);
    }
    for (int k = 0; k < n; k++) {
        if (k == i) continue;
        /* sign = (-1)^(k+1) : k even -> -1, k odd -> +1 */
        int64_t sign = (k % 2 == 0) ? -1 : 1;
        for (int c = 0; c < n; c++) {
            new_row[c] += sign * MC_AT(m, k, c);
        }
    }
    for (int c = 0; c < n; c++) {
        MC_AT(m, i, c) = new_row[c];
    }
    free(new_row);
    return MC_OK;
}

mc_status_t mc_cyclic_column_shift(mc_matrix_t *m, int shift) {
    if (!m) return MC_ERR_BAD_DIMENSION;
    int n = m->n;
    int s = ((shift % n) + n) % n; /* normalize to [0, n) as a LEFT shift amount */
    if (s == 0) return MC_OK;

    int64_t *tmp = (int64_t *)malloc(sizeof(int64_t) * (size_t)n * (size_t)n);
    if (!tmp) return MC_ERR_ALLOC;

    for (int i = 0; i < n; i++) {
        for (int j = 0; j < n; j++) {
            /* new column j takes old column (j + s) mod n, i.e. a left shift */
            tmp[(size_t)i * (size_t)n + (size_t)j] = MC_AT(m, i, (j + s) % n);
        }
    }
    memcpy(m->data, tmp, sizeof(int64_t) * (size_t)n * (size_t)n);
    free(tmp);
    return MC_OK;
}

/* ---------------------------------------------------------------------
 * Hashing
 * --------------------------------------------------------------------- */

mc_status_t mc_sha256_buffer(const uint8_t *buf, size_t len,
                              uint8_t out[MC_HASH_SIZE]) {
    if (!buf || !out) return MC_ERR_BAD_DIMENSION;
    unsigned int out_len = 0;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return MC_ERR_ALLOC;
    int ok = EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) &&
             EVP_DigestUpdate(ctx, buf, len) &&
             EVP_DigestFinal_ex(ctx, out, &out_len);
    EVP_MD_CTX_free(ctx);
    if (!ok || out_len != MC_HASH_SIZE) return MC_ERR_IO;
    return MC_OK;
}

mc_status_t mc_sha256_file(const char *path, uint8_t out[MC_HASH_SIZE]) {
    if (!path || !out) return MC_ERR_BAD_DIMENSION;
    FILE *f = fopen(path, "rb");
    if (!f) return MC_ERR_IO;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) { fclose(f); return MC_ERR_ALLOC; }
    if (!EVP_DigestInit_ex(ctx, EVP_sha256(), NULL)) {
        EVP_MD_CTX_free(ctx); fclose(f); return MC_ERR_IO;
    }

    uint8_t buf[65536];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
        if (!EVP_DigestUpdate(ctx, buf, n)) {
            EVP_MD_CTX_free(ctx); fclose(f); return MC_ERR_IO;
        }
    }
    fclose(f);

    unsigned int out_len = 0;
    int ok = EVP_DigestFinal_ex(ctx, out, &out_len);
    EVP_MD_CTX_free(ctx);
    if (!ok || out_len != MC_HASH_SIZE) return MC_ERR_IO;
    return MC_OK;
}

/* ---------------------------------------------------------------------
 * Key derivation
 * --------------------------------------------------------------------- */

mc_status_t mc_derive_key_seed(const char *password,
                                const uint8_t salt[MC_HASH_SIZE],
                                uint8_t out_seed[MC_SEED_SIZE]) {
    if (!password || !salt || !out_seed) return MC_ERR_BAD_DIMENSION;

    /* Argon2id parameters. Chosen to be memory-hard but still practical
     * for a student project; a real deployment would tune these to the
     * target hardware. */
    const uint32_t t_cost = 3;          /* iterations   */
    const uint32_t m_cost = 1 << 16;    /* 64 MiB       */
    const uint32_t parallelism = 1;

    int rc = argon2id_hash_raw(t_cost, m_cost, parallelism,
                                password, strlen(password),
                                salt, MC_HASH_SIZE,
                                out_seed, MC_SEED_SIZE);
    if (rc != ARGON2_OK) return MC_ERR_ARGON2;
    return MC_OK;
}

mc_status_t mc_generate_key_matrix(int n, const uint8_t seed[MC_SEED_SIZE],
                                    mc_matrix_t *key_out) {
    if (n <= 0 || n > MC_MAX_N || !seed || !key_out) return MC_ERR_BAD_DIMENSION;

    mc_status_t st = mc_matrix_alloc(key_out, n);
    if (st != MC_OK) return st;

    size_t needed_bytes = (size_t)n * (size_t)n;
    uint8_t *xof_out = (uint8_t *)malloc(needed_bytes);
    if (!xof_out) { mc_matrix_free(key_out); return MC_ERR_ALLOC; }

    /* Step 1.3: seed a SHAKE-256 XOF from key_seed, map to matrix
     * entries, and retry (by appending an incrementing counter to the
     * XOF input) until det(key) != 0. */
    for (uint32_t attempt = 0; attempt < 1000000u; attempt++) {
        uint8_t xof_input[MC_SEED_SIZE + 4];
        memcpy(xof_input, seed, MC_SEED_SIZE);
        xof_input[MC_SEED_SIZE + 0] = (uint8_t)(attempt >> 24);
        xof_input[MC_SEED_SIZE + 1] = (uint8_t)(attempt >> 16);
        xof_input[MC_SEED_SIZE + 2] = (uint8_t)(attempt >> 8);
        xof_input[MC_SEED_SIZE + 3] = (uint8_t)(attempt);

        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        if (!ctx) { free(xof_out); mc_matrix_free(key_out); return MC_ERR_ALLOC; }

        int ok = EVP_DigestInit_ex(ctx, EVP_shake256(), NULL) &&
                  EVP_DigestUpdate(ctx, xof_input, sizeof(xof_input)) &&
                  EVP_DigestFinalXOF(ctx, xof_out, needed_bytes);
        EVP_MD_CTX_free(ctx);
        if (!ok) { free(xof_out); mc_matrix_free(key_out); return MC_ERR_IO; }

        /* Map each byte to a small signed range to keep the integer
         * arithmetic in later phases from overflowing 64-bit ints too
         * quickly (see README "Known Limitations"). */
        for (size_t idx = 0; idx < needed_bytes; idx++) {
            int8_t signed_byte = (int8_t)xof_out[idx];
            key_out->data[idx] = (int64_t)signed_byte;
        }

        int64_t det;
        st = mc_determinant(key_out, &det);
        if (st != MC_OK) { free(xof_out); mc_matrix_free(key_out); return st; }
        if (det != 0) { free(xof_out); return MC_OK; }
        /* det == 0: advance the PRNG (the attempt counter) and retry, as
         * Step 1.3 specifies. */
    }

    free(xof_out);
    mc_matrix_free(key_out);
    return MC_ERR_SINGULAR_KEY;
}

/* ---------------------------------------------------------------------
 * Padding
 * --------------------------------------------------------------------- */

uint8_t *mc_pkcs7_pad(const uint8_t *data, size_t len, size_t block_size,
                       size_t *out_len) {
    if (!data || !out_len || block_size == 0 || block_size > 255) return NULL;
    size_t pad = block_size - (len % block_size);
    if (pad == 0) pad = block_size; /* always pad, even if already aligned */
    size_t total = len + pad;

    uint8_t *buf = (uint8_t *)malloc(total);
    if (!buf) return NULL;
    memcpy(buf, data, len);
    memset(buf + len, (int)pad, pad);
    *out_len = total;
    return buf;
}

long mc_pkcs7_unpad_len(const uint8_t *data, size_t len, size_t block_size) {
    if (!data || len == 0 || block_size == 0 || len % block_size != 0) return -1;
    uint8_t pad = data[len - 1];
    if (pad == 0 || (size_t)pad > block_size || (size_t)pad > len) return -1;
    for (size_t i = len - pad; i < len; i++) {
        if (data[i] != pad) return -1;
    }
    return (long)(len - pad);
}

/* ---------------------------------------------------------------------
 * Block pipeline
 *
 * Phases 2 and 5 used to be written out by hand in mountain_encrypt.c and
 * mountain_decrypt.c respectively - two transcriptions of the same four
 * steps, including two private copies of the d-mod-n helper below. They
 * have to agree exactly or a file cannot be recovered, so they are one
 * implementation here instead.
 * --------------------------------------------------------------------- */

/* C's % truncates toward zero, so a negative control determinant would
 * otherwise produce a negative row index and shift amount. */
static int64_t mc_mod_nonneg(int64_t d, int n) {
    int64_t r = d % (int64_t)n;
    if (r < 0) r += n;
    return r;
}

mc_status_t mc_block_work_key(const mc_matrix_t *key, int64_t d,
                               mc_matrix_t *work_out) {
    if (!key || !work_out) return MC_ERR_BAD_DIMENSION;
    mc_status_t st = mc_matrix_copy(key, work_out);
    if (st != MC_OK) return st;

    if ((d % 2) != 0) {
        st = mc_transpose_in_place(work_out);
    } else {
        st = mc_row_mutation_even(work_out, (int)mc_mod_nonneg(d, key->n));
    }
    if (st != MC_OK) mc_matrix_free(work_out);
    return st;
}

mc_status_t mc_encrypt_blocks(const mc_matrix_t *key,
                               const uint8_t *padded, size_t padded_len,
                               int64_t *out) {
    if (!key || !padded || !out) return MC_ERR_BAD_DIMENSION;
    int n = key->n;
    size_t block_bytes = (size_t)n * (size_t)n;
    if (block_bytes == 0 || padded_len % block_bytes != 0) return MC_ERR_BAD_FORMAT;
    size_t num_blocks = padded_len / block_bytes;

    mc_matrix_t C_prev;
    memset(&C_prev, 0, sizeof(C_prev));
    mc_status_t st = MC_OK;
    int64_t d = 0;

    for (size_t blk = 0; blk < num_blocks; blk++) {
        /* Step 2.1 - control determinant: the key for the first block,
         * the previous ciphertext block thereafter. */
        st = mc_determinant(blk == 0 ? key : &C_prev, &d);
        if (blk != 0) mc_matrix_free(&C_prev);
        if (st != MC_OK) return st;

        /* Step 2.2 */
        mc_matrix_t work_key;
        st = mc_block_work_key(key, d, &work_key);
        if (st != MC_OK) return st;

        /* Step 2.3 - load the block and shift its columns left by d mod n */
        mc_matrix_t P;
        st = mc_matrix_alloc(&P, n);
        if (st != MC_OK) { mc_matrix_free(&work_key); return st; }
        for (size_t idx = 0; idx < block_bytes; idx++) {
            P.data[idx] = (int64_t)padded[blk * block_bytes + idx];
        }
        st = mc_cyclic_column_shift(&P, (int)mc_mod_nonneg(d, n));
        if (st != MC_OK) { mc_matrix_free(&P); mc_matrix_free(&work_key); return st; }

        /* Step 2.4 */
        mc_matrix_t C;
        st = mc_matrix_multiply(&work_key, &P, &C);
        mc_matrix_free(&P);
        mc_matrix_free(&work_key);
        if (st != MC_OK) return st;

        /* Step 2.5 */
        memcpy(out + blk * block_bytes, C.data, sizeof(int64_t) * block_bytes);
        C_prev = C; /* carried into the next block's Step 2.1 */
    }
    mc_matrix_free(&C_prev);
    return MC_OK;
}

mc_status_t mc_decrypt_blocks(const mc_matrix_t *key, const int64_t *ct,
                               size_t num_blocks, uint8_t *out) {
    if (!key || !ct || !out) return MC_ERR_BAD_DIMENSION;
    int n = key->n;
    size_t block_bytes = (size_t)n * (size_t)n;

    mc_status_t st = MC_OK;
    int64_t d = 0;

    for (size_t blk = 0; blk < num_blocks; blk++) {
        /* Step 5.1 - the same rule as Step 2.1, except that the previous
         * ciphertext block is read straight back out of the container
         * rather than remembered, so nothing depends on having decrypted
         * it correctly first. */
        if (blk == 0) {
            st = mc_determinant(key, &d);
        } else {
            mc_matrix_t C_prev;
            st = mc_matrix_alloc(&C_prev, n);
            if (st != MC_OK) return st;
            memcpy(C_prev.data, ct + (blk - 1) * block_bytes,
                    sizeof(int64_t) * block_bytes);
            st = mc_determinant(&C_prev, &d);
            mc_matrix_free(&C_prev);
        }
        if (st != MC_OK) return st;

        /* Step 5.2 */
        mc_matrix_t work_key;
        st = mc_block_work_key(key, d, &work_key);
        if (st != MC_OK) return st;

        /* Step 5.3 - undo encryption's left shift with a left shift of
         * (n - shift), which is the same rotation in the other direction. */
        mc_matrix_t C;
        st = mc_matrix_alloc(&C, n);
        if (st != MC_OK) { mc_matrix_free(&work_key); return st; }
        memcpy(C.data, ct + blk * block_bytes, sizeof(int64_t) * block_bytes);
        int shift = (int)mc_mod_nonneg(d, n);
        if (shift != 0) {
            st = mc_cyclic_column_shift(&C, n - shift);
            if (st != MC_OK) { mc_matrix_free(&C); mc_matrix_free(&work_key); return st; }
        }

        /* Step 5.4 - Z = adj(work_key) * C, then P = Z / det(work_key),
         * which the adjugate identity guarantees is exact. */
        mc_matrix_t adj;
        st = mc_adjugate(&work_key, &adj);
        if (st != MC_OK) { mc_matrix_free(&C); mc_matrix_free(&work_key); return st; }

        mc_matrix_t Z;
        st = mc_matrix_multiply(&adj, &C, &Z);
        mc_matrix_free(&adj);
        mc_matrix_free(&C);
        if (st != MC_OK) { mc_matrix_free(&work_key); return st; }

        int64_t det_work_key = 0;
        st = mc_determinant(&work_key, &det_work_key);
        mc_matrix_free(&work_key);
        if (st != MC_OK) { mc_matrix_free(&Z); return st; }
        if (det_work_key == 0) {
            /* Both Step 5.2 branches preserve det(key), which Step 1.3
             * guaranteed is nonzero, so this is unreachable with a key
             * this library produced - kept as a defensive check. */
            mc_matrix_free(&Z);
            return MC_ERR_SINGULAR_KEY;
        }

        for (size_t idx = 0; idx < block_bytes; idx++) {
            int64_t q = Z.data[idx] / det_work_key;
            out[blk * block_bytes + idx] = (uint8_t)(q & 0xFF);
        }
        mc_matrix_free(&Z);
    }
    return MC_OK;
}

mc_status_t mc_encrypt_is_recoverable(const mc_matrix_t *key,
                                       const uint8_t *padded, size_t padded_len,
                                       const int64_t *ct) {
    if (!key || !padded || !ct) return MC_ERR_BAD_DIMENSION;
    size_t block_bytes = (size_t)key->n * (size_t)key->n;
    if (block_bytes == 0 || padded_len % block_bytes != 0) return MC_ERR_BAD_FORMAT;

    uint8_t *check = (uint8_t *)malloc(padded_len > 0 ? padded_len : 1);
    if (!check) return MC_ERR_ALLOC;

    mc_status_t st = mc_decrypt_blocks(key, ct, padded_len / block_bytes, check);
    if (st == MC_OK && memcmp(check, padded, padded_len) != 0) {
        st = MC_ERR_NOT_RECOVERABLE;
    }
    mc_secure_wipe(check, padded_len);
    free(check);
    return st;
}

/* ---------------------------------------------------------------------
 * Memory hygiene
 * --------------------------------------------------------------------- */

void mc_secure_wipe(void *p, size_t len) {
    if (!p) return;
    /* The pointer, not just the pointee, is volatile: that is what stops
     * the compiler from proving the stores are dead and deleting them.
     * The integration suite checks the built binaries for the stores
     * themselves (test_roundtrip.sh, "password wipe survives -O2"),
     * because a functional test can only show that the bytes end up zero,
     * never that the compiler kept the code that zeroed them. */
    volatile unsigned char *volatile q = (volatile unsigned char *volatile)p;
    while (len--) *q++ = 0;
}

/* ---------------------------------------------------------------------
 * Error reporting
 * --------------------------------------------------------------------- */

const char *mc_strerror(mc_status_t status) {
    switch (status) {
        case MC_OK: return "success";
        case MC_ERR_IO: return "I/O error";
        case MC_ERR_ALLOC: return "memory allocation failed";
        case MC_ERR_ARGON2: return "Argon2id key derivation failed";
        case MC_ERR_BAD_DIMENSION: return "invalid matrix dimension or null argument";
        case MC_ERR_SINGULAR_KEY: return "could not generate an invertible key matrix";
        case MC_ERR_INTEGRITY_CIPHERTEXT: return "ciphertext integrity check failed (tampered or corrupted)";
        case MC_ERR_INTEGRITY_PLAINTEXT: return "plaintext integrity check failed (wrong password or corrupted data)";
        case MC_ERR_BAD_FORMAT: return "malformed container file";
        case MC_ERR_NON_EXACT_DIVISION: return "internal error: expected an exact division but got a remainder";
        case MC_ERR_OVERFLOW_GUARD: return "a value exceeded the safe 64-bit integer range for this n; try a smaller n or a shorter file (see README 'Known Limitations')";
        case MC_ERR_NOT_RECOVERABLE: return "the ciphertext this key and file produce cannot be decrypted again; nothing was written (see README 'Known Limitations')";
        default: return "unknown error";
    }
}
