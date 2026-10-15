#!/usr/bin/env python3
# ===========================================================================
# gen_vectors.py - generate known-answer test vectors for the Mountain Cipher.
#
# This is a SECOND, INDEPENDENT implementation of
# docs/mountain_cipher_algorithm.md, written from the specification rather
# than from src/mountain_cipher.c. It exists so that tests/unit/vectors.h
# contains values derived from the spec, not values recorded from the C
# implementation: freezing whatever the C currently prints would freeze its
# bugs along with its behaviour, and a known-answer test that agrees with the
# code by construction asserts nothing.
#
# Two deliberate differences from the C, both of which make disagreement
# meaningful rather than accidental:
#
#   * Determinants here are computed by Gaussian elimination over exact
#     Fractions, not by the Bareiss recurrence the C uses. Two different
#     algorithms arriving at the same integer is evidence; the same algorithm
#     transcribed twice is not.
#   * Python integers are arbitrary precision, so nothing here overflows.
#     Vectors are therefore only generated for (n, length) combinations where
#     the C's int64 range is not in question - see MC_MAX_SAFE_ENTRY below.
#     The int64 boundary itself is tested separately, in test_matrix.c.
#
# Argon2id is not reimplemented here: it has its own known-answer tests
# upstream, and these vectors start from a key_seed rather than a password so
# that the cipher can be tested without it. The password -> key_seed step is
# covered by test_crypto.c and by the container vectors in the integration
# suite.
#
# Usage (Python 3.12 lives at D:\dev-tools\Python312 on this machine):
#     D:\dev-tools\Python312\python.exe tools/gen_vectors.py > tests/unit/vectors.h
#
# The generated header is committed. Re-run it only if the specification
# changes, and say so in the commit message if you do.
# ===========================================================================

import hashlib
import sys
from fractions import Fraction

MC_SEED_SIZE = 32


def det_exact(matrix):
    """Determinant by Gaussian elimination over Fractions.

    Deliberately not the Bareiss recurrence used by mountain_cipher.c - the
    point of this file is to arrive at the same number by a different route.
    """
    n = len(matrix)
    work = [[Fraction(x) for x in row] for row in matrix]
    det = Fraction(1)
    for col in range(n):
        pivot = None
        for row in range(col, n):
            if work[row][col] != 0:
                pivot = row
                break
        if pivot is None:
            return 0
        if pivot != col:
            work[col], work[pivot] = work[pivot], work[col]
            det = -det
        det *= work[col][col]
        inv = work[col][col]
        for row in range(col + 1, n):
            factor = work[row][col] / inv
            if factor == 0:
                continue
            for c in range(col, n):
                work[row][c] -= factor * work[col][c]
    assert det.denominator == 1, "determinant of an integer matrix must be an integer"
    return int(det)


def generate_key_matrix(n, seed):
    """Step 1.3: SHAKE-256 expansion of key_seed, retried until det != 0."""
    for attempt in range(1000000):
        xof_input = seed + attempt.to_bytes(4, "big")
        raw = hashlib.shake_256(xof_input).digest(n * n)
        # Each byte is read as a SIGNED 8-bit value.
        entries = [b - 256 if b > 127 else b for b in raw]
        key = [entries[i * n:(i + 1) * n] for i in range(n)]
        if det_exact(key) != 0:
            return key, attempt
    raise RuntimeError("no invertible key matrix found")


def transpose(m):
    return [list(row) for row in zip(*m)]


def row_mutation_even(m, i):
    """Step 2.2, even branch: R_i <- R_i + sum_{k != i} (-1)^(k+1) R_k.

    Row indices are 0-based per the spec's Definitions table, so k = 0 takes
    the sign (-1)^1 = -1.
    """
    n = len(m)
    out = [list(row) for row in m]
    new_row = list(m[i])
    for k in range(n):
        if k == i:
            continue
        sign = -1 if k % 2 == 0 else 1
        for c in range(n):
            new_row[c] += sign * m[k][c]
    out[i] = new_row
    return out


def shift_columns_left(m, s):
    n = len(m)
    s %= n
    return [[row[(j + s) % n] for j in range(n)] for row in m]


def matmul(a, b):
    n = len(a)
    return [[sum(a[i][k] * b[k][j] for k in range(n)) for j in range(n)]
            for i in range(n)]


def pkcs7_pad(data, block_size):
    pad = block_size - (len(data) % block_size)
    return data + bytes([pad]) * pad


def encrypt_blocks(key, plaintext):
    """Phase 2, over the whole padded plaintext. Returns (blocks, trace)."""
    n = len(key)
    block_bytes = n * n
    padded = pkcs7_pad(plaintext, block_bytes)
    blocks = []
    trace = []
    prev_c = None
    for offset in range(0, len(padded), block_bytes):
        chunk = padded[offset:offset + block_bytes]
        # Step 2.1
        d = det_exact(key) if prev_c is None else det_exact(prev_c)
        # Step 2.2
        if d % 2 != 0:
            work_key = transpose(key)
            branch = "odd/transpose"
        else:
            work_key = row_mutation_even(key, d % n)
            branch = "even/row%d" % (d % n)
        # Step 2.3
        p = [list(chunk[i * n:(i + 1) * n]) for i in range(n)]
        shift = d % n
        if shift != 0:
            p = shift_columns_left(p, shift)
        # Step 2.4
        c = matmul(work_key, p)
        blocks.append(c)
        trace.append((branch, shift))
        prev_c = c
    return blocks, trace


# Python's % returns a non-negative result for a positive modulus, which is
# exactly the behaviour mountain_encrypt.c's mc_mod_nonneg() implements by
# hand for C's truncating %. Assert it rather than assume it.
assert (-7) % 4 == 1

# The C stores matrix entries as int64_t. Vectors are only emitted where every
# intermediate stays well inside that range, so that a C failure means a logic
# bug and never an overflow. 2^62 leaves four bits of headroom.
MC_MAX_SAFE_ENTRY = 1 << 62


CASES = [
    # (label, n, seed byte pattern, plaintext)
    ("n2_multiblock", 2, bytes(range(1, 33)), b"Mountain"),
    ("n3_multiblock", 3, bytes((i * 7 + 3) & 0xFF for i in range(32)), b"three by three blocks"),
    ("n4_multiblock", 4, bytes((i * 3 + 1) & 0xFF for i in range(32)), bytes(range(48))),
    ("n4_empty", 4, bytes((i * 3 + 1) & 0xFF for i in range(32)), b""),
    ("n4_exact_block", 4, bytes((i * 11 + 5) & 0xFF for i in range(32)), b"exactly16bytes!!"),
    ("n5_single", 5, bytes((i * 5 + 2) & 0xFF for i in range(32)), b"short msg"),
    ("n6_single", 6, bytes((i * 13 + 9) & 0xFF for i in range(32)), b"six"),
    ("n2_highbytes", 2, bytes((i * 17 + 4) & 0xFF for i in range(32)), bytes([0xFF] * 9)),
]


def c_array(values, per_line=8, indent="        "):
    out = []
    for i in range(0, len(values), per_line):
        chunk = ", ".join("%dLL" % v for v in values[i:i + per_line])
        out.append(indent + chunk + ",")
    return "\n".join(out)


def c_bytes(data, per_line=16, indent="        "):
    if not data:
        return indent + "0"
    out = []
    for i in range(0, len(data), per_line):
        chunk = ", ".join("0x%02x" % b for b in data[i:i + per_line])
        out.append(indent + chunk + ",")
    return "\n".join(out)


def main():
    w = sys.stdout.write
    w("/* ==========================================================================\n")
    w(" * vectors.h - GENERATED FILE. Do not edit by hand.\n")
    w(" *\n")
    w(" * Known-answer vectors for the Mountain Cipher, produced by\n")
    w(" * tools/gen_vectors.py, which implements docs/mountain_cipher_algorithm.md\n")
    w(" * independently of src/mountain_cipher.c. Regenerate with:\n")
    w(" *\n")
    w(" *     python tools/gen_vectors.py > tests/unit/vectors.h\n")
    w(" *\n")
    w(" * See the header comment of that script for why the values are derived\n")
    w(" * from the specification rather than recorded from this implementation.\n")
    w(" * ========================================================================== */\n\n")
    w("#ifndef MC_TEST_VECTORS_H\n#define MC_TEST_VECTORS_H\n\n#include <stdint.h>\n#include <stddef.h>\n\n")
    w("typedef struct {\n")
    w("    const char    *label;\n")
    w("    int            n;\n")
    w("    const uint8_t *seed;        /* MC_SEED_SIZE bytes                     */\n")
    w("    int            attempt;     /* XOF retries needed before det != 0     */\n")
    w("    const int64_t *key;         /* n*n expected key matrix entries        */\n")
    w("    const uint8_t *plaintext;\n")
    w("    size_t         plaintext_len;\n")
    w("    size_t         num_blocks;\n")
    w("    const int64_t *ciphertext;  /* num_blocks * n*n expected entries      */\n")
    w("    const char    *branches;    /* which Step 2.2 branch each block took  */\n")
    w("} mc_vector_t;\n\n")

    branch_kinds = set()
    shifts_seen = set()
    entries = []
    for label, n, seed, plaintext in CASES:
        assert len(seed) == MC_SEED_SIZE
        key, attempt = generate_key_matrix(n, seed)
        blocks, trace = encrypt_blocks(key, plaintext)
        flat_key = [v for row in key for v in row]
        flat_ct = [v for blk in blocks for row in blk for v in row]
        for v in flat_ct:
            assert abs(v) < MC_MAX_SAFE_ENTRY, "%s exceeds the safe int64 range" % label
        for branch, shift in trace:
            branch_kinds.add(branch.split("/")[0])
            shifts_seen.add(shift)
        w("static const uint8_t %s_seed[] = {\n%s\n};\n" % (label, c_bytes(seed)))
        w("static const int64_t %s_key[] = {\n%s\n};\n" % (label, c_array(flat_key)))
        w("static const uint8_t %s_pt[] = {\n%s\n};\n" % (label, c_bytes(plaintext)))
        w("static const int64_t %s_ct[] = {\n%s\n};\n\n" % (label, c_array(flat_ct)))
        entries.append((label, n, attempt, len(plaintext), len(blocks),
                        " ".join(b for b, _ in trace)))

    w("static const mc_vector_t mc_vectors[] = {\n")
    for label, n, attempt, pt_len, nblocks, branches in entries:
        w('    { "%s", %d, %s_seed, %d, %s_key, %s_pt, %d, %d, %s_ct, "%s" },\n'
          % (label, n, label, attempt, label, label, pt_len, nblocks, label, branches))
    w("};\n\n")
    w("#define MC_VECTOR_COUNT (sizeof(mc_vectors) / sizeof(mc_vectors[0]))\n\n")
    w("#endif /* MC_TEST_VECTORS_H */\n")

    # Coverage is reported on stderr so that it does not land in the header,
    # but is visible when the generator is run by hand.
    sys.stderr.write("branches exercised: %s\n" % ", ".join(sorted(branch_kinds)))
    sys.stderr.write("column shifts exercised: %s\n"
                     % ", ".join(str(s) for s in sorted(shifts_seen)))
    if len(branch_kinds) < 2:
        sys.stderr.write("WARNING: only one Step 2.2 branch is covered by these cases\n")
    if shifts_seen == {0}:
        sys.stderr.write("WARNING: no case produces a nonzero column shift\n")


if __name__ == "__main__":
    main()
