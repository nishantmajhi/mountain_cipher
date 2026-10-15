/* ==========================================================================
 * vectors.h - GENERATED FILE. Do not edit by hand.
 *
 * Known-answer vectors for the Mountain Cipher, produced by
 * tools/gen_vectors.py, which implements docs/mountain_cipher_algorithm.md
 * independently of src/mountain_cipher.c. Regenerate with:
 *
 *     python tools/gen_vectors.py > tests/unit/vectors.h
 *
 * See the header comment of that script for why the values are derived
 * from the specification rather than recorded from this implementation.
 * ========================================================================== */

#ifndef MC_TEST_VECTORS_H
#define MC_TEST_VECTORS_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    const char    *label;
    int            n;
    const uint8_t *seed;        /* MC_SEED_SIZE bytes                     */
    int            attempt;     /* XOF retries needed before det != 0     */
    const int64_t *key;         /* n*n expected key matrix entries        */
    const uint8_t *plaintext;
    size_t         plaintext_len;
    size_t         num_blocks;
    const int64_t *ciphertext;  /* num_blocks * n*n expected entries      */
    const char    *branches;    /* which Step 2.2 branch each block took  */
} mc_vector_t;

static const uint8_t n2_multiblock_seed[] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
};
static const int64_t n2_multiblock_key[] = {
        114LL, 127LL, -74LL, 94LL,
};
static const uint8_t n2_multiblock_pt[] = {
        0x4d, 0x6f, 0x75, 0x6e, 0x74, 0x61, 0x69, 0x6e,
};
static const int64_t n2_multiblock_ct[] = {
        28937LL, 28750LL, 5300LL, 2126LL, 27845LL, 28190LL, 1286LL, 3162LL,
        1044LL, 1044LL, 80LL, 80LL,
};

static const uint8_t n3_multiblock_seed[] = {
        0x03, 0x0a, 0x11, 0x18, 0x1f, 0x26, 0x2d, 0x34, 0x3b, 0x42, 0x49, 0x50, 0x57, 0x5e, 0x65, 0x6c,
        0x73, 0x7a, 0x81, 0x88, 0x8f, 0x96, 0x9d, 0xa4, 0xab, 0xb2, 0xb9, 0xc0, 0xc7, 0xce, 0xd5, 0xdc,
};
static const int64_t n3_multiblock_key[] = {
        117LL, -23LL, 107LL, 103LL, 18LL, 81LL, 81LL, 40LL,
        -98LL,
};
static const uint8_t n3_multiblock_pt[] = {
        0x74, 0x68, 0x72, 0x65, 0x65, 0x20, 0x62, 0x79, 0x20, 0x74, 0x68, 0x72, 0x65, 0x65, 0x20, 0x62,
        0x6c, 0x6f, 0x63, 0x6b, 0x73,
};
static const int64_t n3_multiblock_ct[] = {
        32372LL, 19226LL, 31913LL, 4266LL, -766LL, 3070LL, 7451LL, 11654LL,
        10989LL, 21401LL, 24479LL, 21735LL, -2003LL, -2806LL, -3863LL, 1880LL,
        -364LL, 3832LL, 13959LL, 12087LL, 13023LL, 12439LL, 10791LL, 11615LL,
        7447LL, 6375LL, 6911LL,
};

static const uint8_t n4_multiblock_seed[] = {
        0x01, 0x04, 0x07, 0x0a, 0x0d, 0x10, 0x13, 0x16, 0x19, 0x1c, 0x1f, 0x22, 0x25, 0x28, 0x2b, 0x2e,
        0x31, 0x34, 0x37, 0x3a, 0x3d, 0x40, 0x43, 0x46, 0x49, 0x4c, 0x4f, 0x52, 0x55, 0x58, 0x5b, 0x5e,
};
static const int64_t n4_multiblock_key[] = {
        67LL, -13LL, -17LL, -63LL, -33LL, 66LL, -13LL, -77LL,
        2LL, 54LL, 113LL, 91LL, -67LL, 87LL, -11LL, 113LL,
};
static const uint8_t n4_multiblock_pt[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
};
static const int64_t n4_multiblock_ct[] = {
        -996LL, -1022LL, -944LL, -970LL, -878LL, -935LL, -764LL, -821LL,
        4710LL, 5061LL, 4008LL, 4359LL, 1860LL, 1982LL, 1616LL, 1738LL,
        -5840LL, -6061LL, -6282LL, -6503LL, -1676LL, -1733LL, -1790LL, -1847LL,
        6372LL, 6632LL, 6892LL, 7152LL, 3568LL, 3690LL, 3812LL, 3934LL,
        -9376LL, -9597LL, -9818LL, -10039LL, -2588LL, -2645LL, -2702LL, -2759LL,
        10532LL, 10792LL, 11052LL, 11312LL, 5520LL, 5642LL, 5764LL, 5886LL,
        -3536LL, -3536LL, -3536LL, -3536LL, -912LL, -912LL, -912LL, -912LL,
        4160LL, 4160LL, 4160LL, 4160LL, 1952LL, 1952LL, 1952LL, 1952LL,
};

static const uint8_t n4_empty_seed[] = {
        0x01, 0x04, 0x07, 0x0a, 0x0d, 0x10, 0x13, 0x16, 0x19, 0x1c, 0x1f, 0x22, 0x25, 0x28, 0x2b, 0x2e,
        0x31, 0x34, 0x37, 0x3a, 0x3d, 0x40, 0x43, 0x46, 0x49, 0x4c, 0x4f, 0x52, 0x55, 0x58, 0x5b, 0x5e,
};
static const int64_t n4_empty_key[] = {
        67LL, -13LL, -17LL, -63LL, -33LL, 66LL, -13LL, -77LL,
        2LL, 54LL, 113LL, 91LL, -67LL, 87LL, -11LL, 113LL,
};
static const uint8_t n4_empty_pt[] = {
        0
};
static const int64_t n4_empty_ct[] = {
        -416LL, -416LL, -416LL, -416LL, -912LL, -912LL, -912LL, -912LL,
        5616LL, 5616LL, 5616LL, 5616LL, 1952LL, 1952LL, 1952LL, 1952LL,
};

static const uint8_t n4_exact_block_seed[] = {
        0x05, 0x10, 0x1b, 0x26, 0x31, 0x3c, 0x47, 0x52, 0x5d, 0x68, 0x73, 0x7e, 0x89, 0x94, 0x9f, 0xaa,
        0xb5, 0xc0, 0xcb, 0xd6, 0xe1, 0xec, 0xf7, 0x02, 0x0d, 0x18, 0x23, 0x2e, 0x39, 0x44, 0x4f, 0x5a,
};
static const int64_t n4_exact_block_key[] = {
        27LL, 39LL, -75LL, -105LL, -59LL, -103LL, 71LL, -35LL,
        27LL, 120LL, 119LL, -59LL, -55LL, 88LL, 77LL, -9LL,
};
static const uint8_t n4_exact_block_pt[] = {
        0x65, 0x78, 0x61, 0x63, 0x74, 0x6c, 0x79, 0x31, 0x36, 0x62, 0x79, 0x74, 0x65, 0x73, 0x21, 0x21,
};
static const int64_t n4_exact_block_ct[] = {
        -34224LL, -38906LL, -31210LL, -24296LL, -17608LL, -15271LL, -10750LL, -3807LL,
        17114LL, 21077LL, 29591LL, 20410LL, 7902LL, 9415LL, 14333LL, 7502LL,
        -5536LL, -5536LL, -5536LL, -5536LL, -2016LL, -2016LL, -2016LL, -2016LL,
        3312LL, 3312LL, 3312LL, 3312LL, 1616LL, 1616LL, 1616LL, 1616LL,
};

static const uint8_t n5_single_seed[] = {
        0x02, 0x07, 0x0c, 0x11, 0x16, 0x1b, 0x20, 0x25, 0x2a, 0x2f, 0x34, 0x39, 0x3e, 0x43, 0x48, 0x4d,
        0x52, 0x57, 0x5c, 0x61, 0x66, 0x6b, 0x70, 0x75, 0x7a, 0x7f, 0x84, 0x89, 0x8e, 0x93, 0x98, 0x9d,
};
static const int64_t n5_single_key[] = {
        57LL, -56LL, -56LL, 116LL, 52LL, 9LL, 72LL, -88LL,
        102LL, 10LL, -84LL, 70LL, -22LL, -45LL, 17LL, 87LL,
        100LL, -75LL, 34LL, -71LL, 94LL, 106LL, -73LL, -110LL,
        83LL,
};
static const uint8_t n5_single_pt[] = {
        0x73, 0x68, 0x6f, 0x72, 0x74, 0x20, 0x6d, 0x73, 0x67,
};
static const int64_t n5_single_ct[] = {
        17309LL, 11116LL, 11757LL, 12906LL, 18412LL, 3723LL, 9168LL, 9663LL,
        8826LL, 2580LL, -8220LL, -1906LL, -2074LL, -3166LL, -9424LL, 11413LL,
        18156LL, 19365LL, 18426LL, 9900LL, 12602LL, 19730LL, 21024LL, 20034LL,
        11000LL,
};

static const uint8_t n6_single_seed[] = {
        0x09, 0x16, 0x23, 0x30, 0x3d, 0x4a, 0x57, 0x64, 0x71, 0x7e, 0x8b, 0x98, 0xa5, 0xb2, 0xbf, 0xcc,
        0xd9, 0xe6, 0xf3, 0x00, 0x0d, 0x1a, 0x27, 0x34, 0x41, 0x4e, 0x5b, 0x68, 0x75, 0x82, 0x8f, 0x9c,
};
static const int64_t n6_single_key[] = {
        39LL, -93LL, 34LL, 27LL, 10LL, 75LL, 113LL, 84LL,
        61LL, 52LL, -125LL, 64LL, -126LL, 90LL, 33LL, 31LL,
        -36LL, -76LL, -118LL, -17LL, 64LL, 4LL, -53LL, 58LL,
        -98LL, -123LL, -60LL, 12LL, 115LL, 24LL, 20LL, -57LL,
        -45LL, -83LL, -89LL, -23LL,
};
static const uint8_t n6_single_pt[] = {
        0x73, 0x69, 0x78,
};
static const int64_t n6_single_ct[] = {
        3036LL, 3036LL, 6234LL, 5844LL, 6429LL, 3036LL, 8217LL, 8217LL,
        17483LL, 16353LL, 18048LL, 8217LL, -2772LL, -2772LL, -13104LL, -11844LL,
        -13734LL, -2772LL, -2046LL, -2046LL, -11722LL, -10542LL, -12312LL, -2046LL,
        -7524LL, -7524LL, -7196LL, -7236LL, -7176LL, -7524LL, -9141LL, -9141LL,
        -7501LL, -7701LL, -7401LL, -9141LL,
};

static const uint8_t n2_highbytes_seed[] = {
        0x04, 0x15, 0x26, 0x37, 0x48, 0x59, 0x6a, 0x7b, 0x8c, 0x9d, 0xae, 0xbf, 0xd0, 0xe1, 0xf2, 0x03,
        0x14, 0x25, 0x36, 0x47, 0x58, 0x69, 0x7a, 0x8b, 0x9c, 0xad, 0xbe, 0xcf, 0xe0, 0xf1, 0x02, 0x13,
};
static const int64_t n2_highbytes_key[] = {
        -86LL, -107LL, 93LL, -78LL,
};
static const uint8_t n2_highbytes_pt[] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
};
static const int64_t n2_highbytes_ct[] = {
        1785LL, 1785LL, -47175LL, -47175LL, -45390LL, -45390LL, 3825LL, 3825LL,
        1230LL, -534LL, 23481LL, 45LL,
};

static const mc_vector_t mc_vectors[] = {
    { "n2_multiblock", 2, n2_multiblock_seed, 0, n2_multiblock_key, n2_multiblock_pt, 8, 3, n2_multiblock_ct, "even/row0 even/row0 even/row0" },
    { "n3_multiblock", 3, n3_multiblock_seed, 0, n3_multiblock_key, n3_multiblock_pt, 21, 3, n3_multiblock_ct, "odd/transpose even/row1 even/row2" },
    { "n4_multiblock", 4, n4_multiblock_seed, 0, n4_multiblock_key, n4_multiblock_pt, 48, 4, n4_multiblock_ct, "even/row2 even/row0 even/row0 even/row0" },
    { "n4_empty", 4, n4_empty_seed, 0, n4_empty_key, n4_empty_pt, 0, 1, n4_empty_ct, "even/row2" },
    { "n4_exact_block", 4, n4_exact_block_seed, 0, n4_exact_block_key, n4_exact_block_pt, 16, 2, n4_exact_block_ct, "even/row0 even/row0" },
    { "n5_single", 5, n5_single_seed, 0, n5_single_key, n5_single_pt, 9, 1, n5_single_ct, "even/row0" },
    { "n6_single", 6, n6_single_seed, 0, n6_single_key, n6_single_pt, 3, 1, n6_single_ct, "even/row4" },
    { "n2_highbytes", 2, n2_highbytes_seed, 0, n2_highbytes_key, n2_highbytes_pt, 9, 3, n2_highbytes_ct, "odd/transpose even/row0 even/row0" },
};

#define MC_VECTOR_COUNT (sizeof(mc_vectors) / sizeof(mc_vectors[0]))

#endif /* MC_TEST_VECTORS_H */
