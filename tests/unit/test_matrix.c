/* ===========================================================================
 * test_matrix.c - unit tests for the linear algebra primitives in
 * mountain_cipher.c: transpose, multiply, Bareiss determinant, adjugate,
 * row mutation, and cyclic column shifting.
 * ===========================================================================
 */

#include "test_framework.h"
#include "mountain_cipher.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void fill_matrix(mc_matrix_t *m, const int64_t *values) {
    memcpy(m->data, values, sizeof(int64_t) * (size_t)m->n * (size_t)m->n);
}

static int matrix_equals(const mc_matrix_t *a, const mc_matrix_t *b) {
    if (a->n != b->n) return 0;
    return memcmp(a->data, b->data, sizeof(int64_t) * (size_t)a->n * (size_t)a->n) == 0;
}

static void test_alloc_and_copy(void) {
    fprintf(stderr, "test_alloc_and_copy:\n");
    mc_matrix_t m;
    MC_CHECK(mc_matrix_alloc(&m, 3) == MC_OK, "alloc n=3 succeeds");
    MC_CHECK(m.n == 3, "n stored correctly");
    for (int i = 0; i < 9; i++) MC_CHECK(m.data[i] == 0, "alloc zero-initializes");

    m.data[0] = 42;
    mc_matrix_t copy;
    MC_CHECK(mc_matrix_copy(&m, &copy) == MC_OK, "copy succeeds");
    MC_CHECK(copy.data[0] == 42, "copy preserves data");
    copy.data[0] = 99;
    MC_CHECK(m.data[0] == 42, "copy is independent of source");

    MC_CHECK(mc_matrix_alloc(&m, 0) != MC_OK, "n=0 rejected");
    MC_CHECK(mc_matrix_alloc(&m, MC_MAX_N + 1) != MC_OK, "n > MC_MAX_N rejected");

    mc_matrix_free(&m);
    mc_matrix_free(&copy);
}

static void test_transpose(void) {
    fprintf(stderr, "test_transpose:\n");
    mc_matrix_t m;
    mc_matrix_alloc(&m, 2);
    int64_t vals[] = {1, 2, 3, 4};
    fill_matrix(&m, vals);

    mc_matrix_t t;
    MC_CHECK(mc_matrix_transpose(&m, &t) == MC_OK, "transpose succeeds");
    MC_CHECK(t.data[0] == 1 && t.data[1] == 3 && t.data[2] == 2 && t.data[3] == 4,
              "transpose swaps off-diagonal entries");

    MC_CHECK(mc_transpose_in_place(&m) == MC_OK, "in-place transpose succeeds");
    MC_CHECK(matrix_equals(&m, &t), "in-place transpose matches out-of-place result");

    /* transposing twice returns to the original */
    MC_CHECK(mc_transpose_in_place(&m) == MC_OK, "second in-place transpose succeeds");
    int64_t original[] = {1, 2, 3, 4};
    mc_matrix_t orig;
    mc_matrix_alloc(&orig, 2);
    fill_matrix(&orig, original);
    MC_CHECK(matrix_equals(&m, &orig), "transpose(transpose(M)) == M");

    mc_matrix_free(&m); mc_matrix_free(&t); mc_matrix_free(&orig);
}

static void test_multiply(void) {
    fprintf(stderr, "test_multiply:\n");
    mc_matrix_t a, b, out;
    mc_matrix_alloc(&a, 2);
    mc_matrix_alloc(&b, 2);
    int64_t a_vals[] = {1, 2, 3, 4};
    int64_t b_vals[] = {5, 6, 7, 8};
    fill_matrix(&a, a_vals);
    fill_matrix(&b, b_vals);

    MC_CHECK(mc_matrix_multiply(&a, &b, &out) == MC_OK, "multiply succeeds");
    /* [1 2] [5 6]   [1*5+2*7  1*6+2*8]   [19 22]
     * [3 4] [7 8] = [3*5+4*7  3*6+4*8] = [43 50] */
    MC_CHECK(out.data[0] == 19 && out.data[1] == 22 &&
              out.data[2] == 43 && out.data[3] == 50,
              "2x2 multiply produces the expected result");

    mc_matrix_free(&a); mc_matrix_free(&b); mc_matrix_free(&out);
}

static void test_multiply_overflow_guard(void) {
    fprintf(stderr, "test_multiply_overflow_guard:\n");
    /* Deliberately construct a product that cannot fit in int64_t to
     * confirm the overflow guard fires instead of silently wrapping. */
    mc_matrix_t a, b, out;
    mc_matrix_alloc(&a, 2);
    mc_matrix_alloc(&b, 2);
    int64_t big = 5000000000000LL; /* 5e12 */
    int64_t a_vals[] = {big, big, big, big};
    int64_t b_vals[] = {big, big, big, big};
    fill_matrix(&a, a_vals);
    fill_matrix(&b, b_vals);

    mc_status_t st = mc_matrix_multiply(&a, &b, &out);
    MC_CHECK(st == MC_ERR_OVERFLOW_GUARD, "overflow guard fires instead of wrapping silently");

    mc_matrix_free(&a); mc_matrix_free(&b);
}

static void test_determinant_known_values(void) {
    fprintf(stderr, "test_determinant_known_values:\n");

    /* 1x1 */
    mc_matrix_t m1;
    mc_matrix_alloc(&m1, 1);
    m1.data[0] = 7;
    int64_t det1;
    mc_determinant(&m1, &det1);
    MC_CHECK(det1 == 7, "1x1 determinant is the single entry");
    mc_matrix_free(&m1);

    /* 2x2: [1 2; 3 4] -> det = 1*4 - 2*3 = -2 */
    mc_matrix_t m2;
    mc_matrix_alloc(&m2, 2);
    int64_t vals2[] = {1, 2, 3, 4};
    fill_matrix(&m2, vals2);
    int64_t det2;
    mc_determinant(&m2, &det2);
    MC_CHECK(det2 == -2, "2x2 determinant matches hand calculation");
    mc_matrix_free(&m2);

    /* 3x3 identity -> det = 1 */
    mc_matrix_t m3;
    mc_matrix_alloc(&m3, 3);
    int64_t ident[] = {1,0,0, 0,1,0, 0,0,1};
    fill_matrix(&m3, ident);
    int64_t det3;
    mc_determinant(&m3, &det3);
    MC_CHECK(det3 == 1, "3x3 identity has determinant 1");
    mc_matrix_free(&m3);

    /* Singular 3x3 (repeated row) -> det = 0 */
    mc_matrix_t m4;
    mc_matrix_alloc(&m4, 3);
    int64_t singular[] = {1,2,3, 1,2,3, 4,5,6};
    fill_matrix(&m4, singular);
    int64_t det4;
    mc_determinant(&m4, &det4);
    MC_CHECK(det4 == 0, "matrix with a repeated row has determinant 0");
    mc_matrix_free(&m4);

    /* 6x6 determinant with entries large enough that the Bareiss
     * recurrence's intermediate terms exceed int64_t range, verifying
     * the __int128 intermediate arithmetic still produces the correct
     * result. Confirmed independently in arbitrary-precision Python:
     * the true determinant is -1373872111012. */
    mc_matrix_t m6;
    mc_matrix_alloc(&m6, 6);
    int64_t vals6[] = {
        117,-23,107,103,18,81,
        81,40,-98,-127,67,75,
        25,-57,-26,3,37,16,
        -57,11,125,-67,-111,85,
        113,67,9,-80,107,-96,
        3,-52,-94,2,-23,124
    };
    fill_matrix(&m6, vals6);
    int64_t det6;
    mc_status_t st6 = mc_determinant(&m6, &det6);
    MC_CHECK(st6 == MC_OK, "6x6 determinant does not error");
    MC_CHECK(det6 == -1373872111012LL,
              "6x6 determinant matches the known-correct value");
    mc_matrix_free(&m6);
}

static void test_determinant_overflow_guard(void) {
    fprintf(stderr, "test_determinant_overflow_guard:\n");

    /* The Bareiss guard was the one safety-critical branch with no test.
     * A 3x3 of large entries has a true determinant far outside int64,
     * so the guard must report it rather than return a wrapped value -
     * a wrapped determinant would silently change which Step 2.2 branch
     * and which column shift a block takes, and the file would encrypt
     * "successfully" into something that decrypts to noise. */
    mc_matrix_t m;
    mc_matrix_alloc(&m, 3);
    int64_t big = 3000000000LL; /* 3e9; products reach 2.7e28 */
    int64_t vals[] = { big, 1, 2,
                       3, big, 4,
                       5, 6, big };
    fill_matrix(&m, vals);
    int64_t det = 12345;
    mc_status_t st = mc_determinant(&m, &det);
    MC_CHECK(st == MC_ERR_OVERFLOW_GUARD,
              "a determinant outside int64 is reported, not wrapped");
    mc_matrix_free(&m);

    /* And a determinant that only just fits must still be computed. */
    mc_matrix_t ok;
    mc_matrix_alloc(&ok, 2);
    int64_t ok_vals[] = { 3037000499LL, 1, 1, 3037000499LL }; /* ~9.22e18 - 1 */
    fill_matrix(&ok, ok_vals);
    int64_t ok_det = 0;
    mc_status_t ok_st = mc_determinant(&ok, &ok_det);
    MC_CHECK(ok_st == MC_OK, "a determinant that fits in int64 is computed");
    MC_CHECK(ok_det == 3037000499LL * 3037000499LL - 1,
              "the just-fitting determinant is exact");
    mc_matrix_free(&ok);
}

static void test_determinant_row_swap_path(void) {
    fprintf(stderr, "test_determinant_row_swap_path:\n");

    /* Bareiss has to swap rows when a pivot is zero, and the swap flips
     * the sign of the result. Nothing reached that branch before: every
     * fixture had a nonzero leading entry. */
    mc_matrix_t m;
    mc_matrix_alloc(&m, 2);
    int64_t swap_vals[] = { 0, 5,
                            3, 7 };  /* det = 0*7 - 5*3 = -15 */
    fill_matrix(&m, swap_vals);
    int64_t det = 0;
    MC_CHECK(mc_determinant(&m, &det) == MC_OK, "determinant with a zero pivot succeeds");
    MC_CHECK(det == -15, "the row swap flips the sign correctly");
    mc_matrix_free(&m);

    /* Three rows, zero pivot in the first column, nonzero further down. */
    mc_matrix_t m3;
    mc_matrix_alloc(&m3, 3);
    int64_t v3[] = { 0, 2, 3,
                     4, 5, 6,
                     7, 8, 10 };  /* det = -5 */
    fill_matrix(&m3, v3);
    int64_t det3 = 0;
    MC_CHECK(mc_determinant(&m3, &det3) == MC_OK, "3x3 with a zero pivot succeeds");
    MC_CHECK(det3 == -5, "3x3 zero-pivot determinant matches an independent calculation");
    mc_matrix_free(&m3);

    /* A whole zero column means singular, reached through the same
     * branch when no row below has a nonzero entry either. */
    mc_matrix_t z;
    mc_matrix_alloc(&z, 3);
    int64_t zv[] = { 0, 1, 2,
                     0, 3, 4,
                     0, 5, 6 };
    fill_matrix(&z, zv);
    int64_t zdet = 99;
    MC_CHECK(mc_determinant(&z, &zdet) == MC_OK, "a zero column is not an error");
    MC_CHECK(zdet == 0, "a zero column gives determinant 0");
    mc_matrix_free(&z);
}

static void test_determinant_sign_and_negatives(void) {
    fprintf(stderr, "test_determinant_sign_and_negatives:\n");

    /* The control determinant decides odd/even and the shift amount, and
     * it is routinely negative for a key made of signed bytes - so the
     * sign has to be right, not just the magnitude. */
    mc_matrix_t m;
    mc_matrix_alloc(&m, 3);
    int64_t vals[] = { -2, 3, -1,
                        4, -5, 6,
                       -7, 8, -9 };  /* det = -9 */
    fill_matrix(&m, vals);
    int64_t det = 0;
    mc_determinant(&m, &det);
    MC_CHECK(det == -9, "a negative determinant is computed with the right sign");

    /* Swapping two rows negates it. */
    mc_matrix_t s;
    mc_matrix_alloc(&s, 3);
    int64_t swapped[] = {  4, -5, 6,
                          -2, 3, -1,
                          -7, 8, -9 };
    fill_matrix(&s, swapped);
    int64_t det_s = 0;
    mc_determinant(&s, &det_s);
    MC_CHECK(det_s == -det, "swapping two rows negates the determinant");

    mc_matrix_free(&m); mc_matrix_free(&s);
}

static void test_adjugate_identity(void) {
    fprintf(stderr, "test_adjugate_identity:\n");
    /* adj(A) * A == det(A) * I, for several matrices/sizes */
    int64_t vals_list[3][16] = {
        {2, 0, 0, 0,  0, 3, 0, 0,  0, 0, 5, 0,  0, 0, 0, 7}, /* diagonal 4x4 */
        {0}, /* placeholder, filled below for 2x2 */
        {0}  /* placeholder, filled below for 3x3 */
    };
    (void)vals_list;

    /* 2x2 */
    {
        mc_matrix_t a, adj, prod;
        mc_matrix_alloc(&a, 2);
        int64_t v[] = {4, 7, 2, 6};
        fill_matrix(&a, v);
        int64_t det;
        mc_determinant(&a, &det);
        mc_adjugate(&a, &adj);
        mc_matrix_multiply(&adj, &a, &prod);
        MC_CHECK(prod.data[0] == det && prod.data[3] == det, "2x2 adj(A)*A diagonal equals det(A)");
        MC_CHECK(prod.data[1] == 0 && prod.data[2] == 0, "2x2 adj(A)*A off-diagonal is 0");
        mc_matrix_free(&a); mc_matrix_free(&adj); mc_matrix_free(&prod);
    }

    /* 4x4 diagonal: det = 2*3*5*7 = 210, adj(A)*A should be 210*I */
    {
        mc_matrix_t a, adj, prod;
        mc_matrix_alloc(&a, 4);
        fill_matrix(&a, vals_list[0]);
        int64_t det;
        mc_determinant(&a, &det);
        MC_CHECK(det == 210, "4x4 diagonal determinant is the product of the diagonal");
        mc_adjugate(&a, &adj);
        mc_matrix_multiply(&adj, &a, &prod);
        int ok = 1;
        for (int i = 0; i < 4; i++)
            for (int j = 0; j < 4; j++)
                if (prod.data[i*4+j] != (i == j ? det : 0)) ok = 0;
        MC_CHECK(ok, "4x4 adj(A)*A == det(A)*I");
        mc_matrix_free(&a); mc_matrix_free(&adj); mc_matrix_free(&prod);
    }

    /* Same larger 6x6 matrix used above, checked against the adjugate
     * identity end to end (this is exactly what decryption relies on). */
    {
        mc_matrix_t a, adj, prod;
        mc_matrix_alloc(&a, 6);
        int64_t vals6[] = {
            117,-23,107,103,18,81,
            81,40,-98,-127,67,75,
            25,-57,-26,3,37,16,
            -57,11,125,-67,-111,85,
            113,67,9,-80,107,-96,
            3,-52,-94,2,-23,124
        };
        fill_matrix(&a, vals6);
        int64_t det;
        mc_determinant(&a, &det);
        mc_status_t st = mc_adjugate(&a, &adj);
        MC_CHECK(st == MC_OK, "6x6 adjugate computes without error");
        mc_status_t st2 = mc_matrix_multiply(&adj, &a, &prod);
        MC_CHECK(st2 == MC_OK, "6x6 adj(A)*A multiply does not overflow");
        int ok = 1;
        for (int i = 0; i < 6; i++)
            for (int j = 0; j < 6; j++)
                if (prod.data[i*6+j] != (i == j ? det : 0)) ok = 0;
        MC_CHECK(ok, "6x6 adj(A)*A == det(A)*I");
        mc_matrix_free(&a); mc_matrix_free(&adj); mc_matrix_free(&prod);
    }
}

static void test_row_mutation_preserves_determinant(void) {
    fprintf(stderr, "test_row_mutation_preserves_determinant:\n");
    /* The row mutation must preserve the determinant exactly, for
     * every valid row index. */
    int64_t vals[] = {
        3, -2, 5, 1,
        7, 0, -4, 6,
        2, 9, 1, -3,
        -5, 4, 8, 2
    };
    for (int i = 0; i < 4; i++) {
        mc_matrix_t m;
        mc_matrix_alloc(&m, 4);
        fill_matrix(&m, vals);
        int64_t det_before;
        mc_determinant(&m, &det_before);

        MC_CHECK(mc_row_mutation_even(&m, i) == MC_OK, "row mutation succeeds");
        int64_t det_after;
        mc_determinant(&m, &det_after);
        char msg[64];
        snprintf(msg, sizeof(msg), "row mutation at i=%d preserves determinant", i);
        MC_CHECK(det_before == det_after, msg);
        mc_matrix_free(&m);
    }
}

static void test_cyclic_column_shift(void) {
    fprintf(stderr, "test_cyclic_column_shift:\n");
    mc_matrix_t m, original;
    mc_matrix_alloc(&m, 3);
    mc_matrix_alloc(&original, 3);
    int64_t vals[] = {1,2,3, 4,5,6, 7,8,9};
    fill_matrix(&m, vals);
    fill_matrix(&original, vals);

    MC_CHECK(mc_cyclic_column_shift(&m, 1) == MC_OK, "left shift by 1 succeeds");
    /* row 0 [1,2,3] shifted left by 1 -> [2,3,1] */
    MC_CHECK(m.data[0] == 2 && m.data[1] == 3 && m.data[2] == 1,
              "left shift by 1 moves columns as expected");

    /* shifting left by n should return to the original (full cycle) */
    mc_matrix_t m2;
    mc_matrix_alloc(&m2, 3);
    fill_matrix(&m2, vals);
    mc_cyclic_column_shift(&m2, 3);
    MC_CHECK(matrix_equals(&m2, &original), "left shift by n (full cycle) is a no-op");

    /* shifting left by s then left by (n - s) should undo it (this is
     * exactly how decryption undoes encryption's shift) */
    mc_matrix_t m3;
    mc_matrix_alloc(&m3, 3);
    fill_matrix(&m3, vals);
    mc_cyclic_column_shift(&m3, 1);
    mc_cyclic_column_shift(&m3, 3 - 1);
    MC_CHECK(matrix_equals(&m3, &original), "shift left by s then by (n-s) restores original");

    /* shift by 0 is a no-op */
    mc_matrix_t m4;
    mc_matrix_alloc(&m4, 3);
    fill_matrix(&m4, vals);
    mc_cyclic_column_shift(&m4, 0);
    MC_CHECK(matrix_equals(&m4, &original), "shift by 0 is a no-op");

    mc_matrix_free(&m); mc_matrix_free(&original);
    mc_matrix_free(&m2); mc_matrix_free(&m3); mc_matrix_free(&m4);
}

static void test_pkcs7_padding(void) {
    fprintf(stderr, "test_pkcs7_padding:\n");

    /* Not block-aligned: 5 bytes, block size 8 -> pad with 3 bytes of 0x03 */
    {
        uint8_t data[] = {1,2,3,4,5};
        size_t out_len;
        uint8_t *padded = mc_pkcs7_pad(data, 5, 8, &out_len);
        MC_CHECK(padded != NULL, "pad succeeds");
        MC_CHECK(out_len == 8, "pads up to block size");
        MC_CHECK(padded[5] == 3 && padded[6] == 3 && padded[7] == 3, "pad bytes equal pad length");

        long unpadded = mc_pkcs7_unpad_len(padded, out_len, 8);
        MC_CHECK(unpadded == 5, "unpad recovers original length");
        free(padded);
    }

    /* Exactly block-aligned: 8 bytes, block size 8 -> a FULL extra
     * block of padding is added (this implementation always pads,
     * even when already aligned, so unpadding is never ambiguous). */
    {
        uint8_t data[8] = {1,2,3,4,5,6,7,8};
        size_t out_len;
        uint8_t *padded = mc_pkcs7_pad(data, 8, 8, &out_len);
        MC_CHECK(out_len == 16, "aligned input still gets a full block of padding");
        long unpadded = mc_pkcs7_unpad_len(padded, out_len, 8);
        MC_CHECK(unpadded == 8, "unpad recovers original length for aligned input");
        free(padded);
    }

    /* Corrupted padding is rejected (this is what catches wrong
     * passwords / tampered ciphertext in Phase 6.2) */
    {
        uint8_t bad[8] = {1,2,3,4,5, 9,9,9}; /* pad byte value 9 doesn't match, and > block size */
        long unpadded = mc_pkcs7_unpad_len(bad, 8, 8);
        MC_CHECK(unpadded == -1, "corrupted padding is rejected");
    }
    {
        uint8_t bad[8] = {1,2,3,4,5, 3,3,4}; /* inconsistent pad bytes */
        long unpadded = mc_pkcs7_unpad_len(bad, 8, 8);
        MC_CHECK(unpadded == -1, "inconsistent pad bytes are rejected");
    }
}

static void test_pkcs7_padding_edges(void) {
    fprintf(stderr, "test_pkcs7_padding_edges:\n");

    /* Block sizes here are n*n, so 4 through 144. The interesting sizes
     * are the ones the CLIs actually use, and zero-length input, which
     * is a supported case: encrypting an empty file must produce exactly
     * one block of padding. */
    {
        uint8_t nothing[1] = { 0 };
        size_t out_len = 0;
        uint8_t *padded = mc_pkcs7_pad(nothing, 0, 16, &out_len);
        MC_CHECK(padded != NULL && out_len == 16, "an empty input pads to one full block");
        if (padded) {
            int all_16 = 1;
            for (int i = 0; i < 16; i++) if (padded[i] != 16) all_16 = 0;
            MC_CHECK(all_16, "the padding block is filled with the pad length");
            MC_CHECK(mc_pkcs7_unpad_len(padded, 16, 16) == 0,
                      "unpadding an all-padding block gives length 0");
            free(padded);
        }
    }

    /* The largest block this project can ask for. */
    {
        uint8_t data[200];
        memset(data, 'A', sizeof(data));
        size_t out_len = 0;
        uint8_t *padded = mc_pkcs7_pad(data, sizeof(data), 144, &out_len);
        MC_CHECK(padded != NULL && out_len == 288, "n=12 block size pads correctly");
        MC_CHECK(padded && mc_pkcs7_unpad_len(padded, out_len, 144) == 200,
                  "n=12 padding round-trips");
        free(padded);
    }

    /* Rejections. A pad byte larger than the block, a pad byte of zero,
     * and a length that is not a whole number of blocks are all things a
     * wrong password can produce, and all must be refused rather than
     * returning a nonsense length. */
    {
        uint8_t zero_pad[8] = { 1, 2, 3, 4, 5, 6, 7, 0 };
        MC_CHECK(mc_pkcs7_unpad_len(zero_pad, 8, 8) == -1, "a pad byte of zero is rejected");

        uint8_t over_pad[8] = { 1, 2, 3, 4, 5, 6, 7, 99 };
        MC_CHECK(mc_pkcs7_unpad_len(over_pad, 8, 8) == -1,
                  "a pad byte larger than the block is rejected");

        uint8_t fine[8] = { 1, 2, 3, 4, 5, 3, 3, 3 };
        MC_CHECK(mc_pkcs7_unpad_len(fine, 7, 8) == -1,
                  "a length that is not a multiple of the block size is rejected");
        MC_CHECK(mc_pkcs7_unpad_len(fine, 0, 8) == -1, "a zero length is rejected");
        MC_CHECK(mc_pkcs7_unpad_len(NULL, 8, 8) == -1, "a null buffer is rejected");
        MC_CHECK(mc_pkcs7_unpad_len(fine, 8, 0) == -1, "a zero block size is rejected");

        /* A full block of padding is valid, and is what an aligned input
         * produces - it must not be mistaken for corruption. */
        uint8_t full[8] = { 8, 8, 8, 8, 8, 8, 8, 8 };
        MC_CHECK(mc_pkcs7_unpad_len(full, 8, 8) == 0, "a full padding block is valid");
    }

    /* mc_pkcs7_pad's own refusals. */
    {
        uint8_t data[4] = { 1, 2, 3, 4 };
        size_t out_len = 0;
        MC_CHECK(mc_pkcs7_pad(data, 4, 0, &out_len) == NULL, "a zero block size is refused");
        MC_CHECK(mc_pkcs7_pad(data, 4, 256, &out_len) == NULL,
                  "a block size too large for a pad byte is refused");
        MC_CHECK(mc_pkcs7_pad(NULL, 4, 8, &out_len) == NULL, "a null buffer is refused");
        MC_CHECK(mc_pkcs7_pad(data, 4, 8, NULL) == NULL, "a null out_len is refused");
    }
}

int main(void) {
    test_alloc_and_copy();
    test_transpose();
    test_multiply();
    test_multiply_overflow_guard();
    test_determinant_known_values();
    test_determinant_overflow_guard();
    test_determinant_row_swap_path();
    test_determinant_sign_and_negatives();
    test_adjugate_identity();
    test_pkcs7_padding_edges();
    test_row_mutation_preserves_determinant();
    test_cyclic_column_shift();
    test_pkcs7_padding();
    MC_TEST_EXIT();
}
