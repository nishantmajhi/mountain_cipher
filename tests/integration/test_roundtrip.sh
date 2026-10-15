#!/usr/bin/env bash
# =============================================================================
# test_roundtrip.sh - integration tests for mountain_encrypt / mountain_decrypt
#
# Exercises the actual CLI binaries (not the internal C API) the way a user
# would: encrypt a file, decrypt it, and confirm correctness. Also checks
# wrong-password rejection, tamper detection, multiple key sizes, container
# validation, and CLI argument handling.
#
# Usage: tests/integration/test_roundtrip.sh <path-to-mountain_encrypt> <path-to-mountain_decrypt>
# (the Makefile's `make test-integration` target passes these in automatically)
# =============================================================================

set -u

ENCRYPT_BIN="${1:?Usage: $0 <mountain_encrypt binary> <mountain_decrypt binary>}"
DECRYPT_BIN="${2:?Usage: $0 <mountain_encrypt binary> <mountain_decrypt binary>}"

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

PASS=0
FAIL=0

pass() { PASS=$((PASS+1)); echo "  PASS: $1"; }
fail() { FAIL=$((FAIL+1)); echo "  FAIL: $1"; }

# ---------------------------------------------------------------------------
# Preflight: the binaries must actually run.
#
# Most of the checks below are negative - they assert that something is
# REJECTED. A binary that cannot start is rejected by the operating system,
# so every one of those checks passed while the tools were completely broken.
# That happened here: with the OpenSSL DLL missing, this suite reported nine
# passes against two executables that could not load. Establish first that
# the tools run at all, and refuse to report anything if they do not.
# ---------------------------------------------------------------------------
echo "preflight:"
# The Makefile names the binaries without a suffix, and on Windows the
# linker writes mountain_encrypt.exe. The shell resolves that when running
# them; tools that open the file by name, such as objdump below, do not.
# The .exe name is tried FIRST: under MSYS, [ -f ./foo ] is already true
# when only ./foo.exe exists, so testing the bare name first always wins
# and hands the native tool a path it cannot open.
resolve_binary() {
    case "$1" in
        *.exe) printf '%s' "$1"; return;;
    esac
    if [ -f "$1.exe" ]; then printf '%s' "$1.exe"
    else printf '%s' "$1"
    fi
}
ENCRYPT_FILE="$(resolve_binary "$ENCRYPT_BIN")"
DECRYPT_FILE="$(resolve_binary "$DECRYPT_BIN")"

for bin in "$ENCRYPT_BIN" "$DECRYPT_BIN"; do
    usage_output="$("$bin" 2>&1 || true)"
    case "$usage_output" in
        *Usage:*)
            pass "$(basename "$bin") starts and prints its usage"
            ;;
        *)
            echo "  ABORT: $bin does not run - every negative test below would"
            echo "         pass vacuously. Output was:"
            echo "$usage_output" | sed 's/^/           /'
            exit 1
            ;;
    esac
done

# ---------------------------------------------------------------------------
# Test 1: basic round trip, default n
# ---------------------------------------------------------------------------
echo "test_basic_roundtrip:"
cat > "$WORKDIR/plain1.txt" << 'EOF'
This is a test of the Mountain Cipher algorithm.
It contains multiple lines and enough bytes to span several blocks
so we can exercise the block-chaining behavior (control determinant
carried from one ciphertext block to the next) as well as the
odd/even key mutation branches (transpose vs the row sum).
Let's see if round-trip encryption/decryption reproduces this exactly!
1234567890 !@#$%^&*()_+-=[]{}
EOF

echo "test_password_1" | "$ENCRYPT_BIN" "$WORKDIR/plain1.txt" "$WORKDIR/plain1.mtnc" 4 >/dev/null 2>"$WORKDIR/enc1.log"
if [ $? -eq 0 ]; then pass "basic encrypt exits 0"; else fail "basic encrypt exits 0"; cat "$WORKDIR/enc1.log"; fi

echo "test_password_1" | "$DECRYPT_BIN" "$WORKDIR/plain1.mtnc" "$WORKDIR/plain1.out" >/dev/null 2>"$WORKDIR/dec1.log"
if [ $? -eq 0 ]; then pass "basic decrypt exits 0"; else fail "basic decrypt exits 0"; cat "$WORKDIR/dec1.log"; fi

if cmp -s "$WORKDIR/plain1.txt" "$WORKDIR/plain1.out"; then
    pass "decrypted output is byte-identical to the original"
else
    fail "decrypted output is byte-identical to the original"
fi

# ---------------------------------------------------------------------------
# Test 2: wrong password is rejected
#
# The rejection message is checked as well as the exit status, so that a
# tool which fails for an unrelated reason cannot pass this test.
# ---------------------------------------------------------------------------
echo "test_wrong_password:"
echo "definitely_wrong_password" | "$DECRYPT_BIN" "$WORKDIR/plain1.mtnc" "$WORKDIR/wrong.out" >"$WORKDIR/wrong.log" 2>&1
WRONG_STATUS=$?
if [ "$WRONG_STATUS" -ne 0 ]; then
    pass "wrong password is rejected (nonzero exit)"
else
    fail "wrong password is rejected (nonzero exit)"
fi
if grep -qE "wrong password or corrupted data" "$WORKDIR/wrong.log"; then
    pass "wrong password is rejected for the right reason"
else
    fail "wrong password is rejected for the right reason"
    cat "$WORKDIR/wrong.log"
fi
if [ ! -f "$WORKDIR/wrong.out" ]; then
    pass "wrong password writes no output file at all"
else
    fail "wrong password writes no output file at all"
fi

# ---------------------------------------------------------------------------
# Test 3: tampered ciphertext is detected
# ---------------------------------------------------------------------------
echo "test_tamper_detection:"
cp "$WORKDIR/plain1.mtnc" "$WORKDIR/tampered.mtnc"
# Flip every bit of one byte well inside the ciphertext blocks (past the
# header). XORing with 0xFF guarantees the byte actually changes,
# regardless of its original value (unlike overwriting with a fixed
# byte, which could coincidentally match bytes that are already that
# value - int64 ciphertext entries routinely contain 0xFF bytes).
TAMPER_OFFSET=100
ORIG_BYTE=$(od -An -tu1 -j "$TAMPER_OFFSET" -N 1 "$WORKDIR/tampered.mtnc" | tr -d ' ')
NEW_BYTE=$(( (ORIG_BYTE ^ 0xFF) & 0xFF ))
printf "$(printf '\\%03o' "$NEW_BYTE")" | dd of="$WORKDIR/tampered.mtnc" bs=1 seek="$TAMPER_OFFSET" count=1 conv=notrunc >/dev/null 2>&1

echo "test_password_1" | "$DECRYPT_BIN" "$WORKDIR/tampered.mtnc" "$WORKDIR/tampered.out" >"$WORKDIR/tamper.log" 2>&1
TAMPER_STATUS=$?
if [ "$TAMPER_STATUS" -ne 0 ]; then
    pass "tampered ciphertext is rejected (nonzero exit)"
else
    fail "tampered ciphertext is rejected (nonzero exit)"
fi
if grep -q "integrity check FAILED" "$WORKDIR/tamper.log"; then
    pass "tamper rejection message reports an integrity check failure"
else
    fail "tamper rejection message reports an integrity check failure"
fi
# The ciphertext hash is checked before the password is even asked for, so
# tampering must be caught without a password being supplied.
"$DECRYPT_BIN" "$WORKDIR/tampered.mtnc" "$WORKDIR/tampered.out" </dev/null >"$WORKDIR/tamper2.log" 2>&1
if grep -q "integrity check FAILED" "$WORKDIR/tamper2.log"; then
    pass "tampering is detected before a password is requested"
else
    fail "tampering is detected before a password is requested"
fi

# ---------------------------------------------------------------------------
# Test 4: round trip across multiple values of n
# ---------------------------------------------------------------------------
echo "test_multiple_n_values:"
for n in 2 3 4; do
    echo "pw_for_n_$n" | "$ENCRYPT_BIN" "$WORKDIR/plain1.txt" "$WORKDIR/n_$n.mtnc" "$n" >/dev/null 2>"$WORKDIR/enc_n_$n.log"
    echo "pw_for_n_$n" | "$DECRYPT_BIN" "$WORKDIR/n_$n.mtnc" "$WORKDIR/n_$n.out" >/dev/null 2>"$WORKDIR/dec_n_$n.log"
    if cmp -s "$WORKDIR/plain1.txt" "$WORKDIR/n_$n.out"; then
        pass "round trip succeeds for n=$n"
    else
        fail "round trip succeeds for n=$n"
        cat "$WORKDIR/dec_n_$n.log"
    fi
done

printf "short msg" > "$WORKDIR/short.txt"
echo "pw_for_n_5" | "$ENCRYPT_BIN" "$WORKDIR/short.txt" "$WORKDIR/n_5.mtnc" 5 >/dev/null 2>"$WORKDIR/enc_n_5.log"
echo "pw_for_n_5" | "$DECRYPT_BIN" "$WORKDIR/n_5.mtnc" "$WORKDIR/n_5.out" >/dev/null 2>"$WORKDIR/dec_n_5.log"
if cmp -s "$WORKDIR/short.txt" "$WORKDIR/n_5.out"; then
    pass "round trip succeeds for n=5 on a short (single-block) message"
else
    fail "round trip succeeds for n=5 on a short (single-block) message"
    cat "$WORKDIR/dec_n_5.log"
fi

# ---------------------------------------------------------------------------
# Test 5: whatever encrypts must decrypt
#
# This is the regression test for the worst bug this project had. Encryption
# and decryption do not fail together: encryption multiplies small key
# entries, decryption multiplies by the adjugate, whose entries grow
# factorially with n. So n=8 used to write a container that could never be
# opened for about a quarter of passwords, and n=9 for every password, while
# printing "Encrypted" and exiting 0 - the user found out after deleting the
# original.
#
# The rule this asserts is the only one that matters to somebody with one
# copy of a file: if the encryptor reports success, the decryptor must
# reproduce the plaintext. Refusing up front is fine. Succeeding and then
# being unable to decrypt is not.
# ---------------------------------------------------------------------------
echo "test_whatever_encrypts_must_decrypt:"
printf 'a short but not trivial message' > "$WORKDIR/sweep.txt"
SWEEP_ENCRYPTED=0
SWEEP_REFUSED=0
SWEEP_LOST=0
for n in 2 3 4 5 6 7 8 9 10 11 12; do
    for i in 1 2 3 4; do
        pw="sweep_${n}_${i}"
        if echo "$pw" | "$ENCRYPT_BIN" "$WORKDIR/sweep.txt" "$WORKDIR/sweep.mtnc" "$n" >/dev/null 2>&1; then
            SWEEP_ENCRYPTED=$((SWEEP_ENCRYPTED+1))
            echo "$pw" | "$DECRYPT_BIN" "$WORKDIR/sweep.mtnc" "$WORKDIR/sweep.out" >/dev/null 2>&1
            if ! cmp -s "$WORKDIR/sweep.txt" "$WORKDIR/sweep.out"; then
                SWEEP_LOST=$((SWEEP_LOST+1))
                echo "    n=$n password=$pw encrypted but did not decrypt"
            fi
            rm -f "$WORKDIR/sweep.out"
        else
            SWEEP_REFUSED=$((SWEEP_REFUSED+1))
        fi
        rm -f "$WORKDIR/sweep.mtnc"
    done
done
if [ "$SWEEP_LOST" -eq 0 ]; then
    pass "every ciphertext the encryptor accepted decrypts ($SWEEP_ENCRYPTED encrypted, $SWEEP_REFUSED refused up front)"
else
    fail "$SWEEP_LOST of $SWEEP_ENCRYPTED accepted ciphertexts could not be decrypted"
fi
if [ "$SWEEP_REFUSED" -gt 0 ]; then
    pass "large n is refused up front rather than producing an unreadable file"
else
    fail "large n is refused up front rather than producing an unreadable file"
fi

# An n the tool cannot handle must leave no output file behind, so that a
# failed encryption cannot be mistaken for a successful one.
rm -f "$WORKDIR/refused.mtnc"
echo "refusal_pw" | "$ENCRYPT_BIN" "$WORKDIR/sweep.txt" "$WORKDIR/refused.mtnc" 12 >/dev/null 2>&1
if [ ! -f "$WORKDIR/refused.mtnc" ]; then
    pass "a refused encryption writes no output file"
else
    fail "a refused encryption writes no output file"
fi

# ---------------------------------------------------------------------------
# Test 6: round trip on a larger, random-content file (many blocks)
# ---------------------------------------------------------------------------
echo "test_larger_file:"
head -c 5000 /dev/urandom | base64 > "$WORKDIR/big.txt"
echo "big_file_password" | "$ENCRYPT_BIN" "$WORKDIR/big.txt" "$WORKDIR/big.mtnc" 4 >/dev/null 2>"$WORKDIR/enc_big.log"
echo "big_file_password" | "$DECRYPT_BIN" "$WORKDIR/big.mtnc" "$WORKDIR/big.out" >/dev/null 2>"$WORKDIR/dec_big.log"
if cmp -s "$WORKDIR/big.txt" "$WORKDIR/big.out"; then
    pass "larger multi-block file round trip succeeds"
else
    fail "larger multi-block file round trip succeeds"
    cat "$WORKDIR/dec_big.log"
fi

# Binary content, including NUL bytes and every byte value, must survive.
head -c 4096 /dev/urandom > "$WORKDIR/binary.bin"
echo "binary_password" | "$ENCRYPT_BIN" "$WORKDIR/binary.bin" "$WORKDIR/binary.mtnc" 4 >/dev/null 2>&1
echo "binary_password" | "$DECRYPT_BIN" "$WORKDIR/binary.mtnc" "$WORKDIR/binary.out" >/dev/null 2>&1
if cmp -s "$WORKDIR/binary.bin" "$WORKDIR/binary.out"; then
    pass "arbitrary binary content round-trips byte for byte"
else
    fail "arbitrary binary content round-trips byte for byte"
fi

# ---------------------------------------------------------------------------
# Test 7: many random passwords in a row
# ---------------------------------------------------------------------------
echo "test_many_random_passwords:"
RANDOM_TRIALS=10
RANDOM_SUCCESSES=0
for i in $(seq 1 "$RANDOM_TRIALS"); do
    pw="random_trial_${i}_$RANDOM"
    echo "$pw" | "$ENCRYPT_BIN" "$WORKDIR/plain1.txt" "$WORKDIR/rt.mtnc" 4 >/dev/null 2>&1
    echo "$pw" | "$DECRYPT_BIN" "$WORKDIR/rt.mtnc" "$WORKDIR/rt.out" >/dev/null 2>&1
    if cmp -s "$WORKDIR/plain1.txt" "$WORKDIR/rt.out"; then
        RANDOM_SUCCESSES=$((RANDOM_SUCCESSES+1))
    fi
done
if [ "$RANDOM_SUCCESSES" -eq "$RANDOM_TRIALS" ]; then
    pass "all $RANDOM_TRIALS random passwords round-tripped successfully"
else
    fail "only $RANDOM_SUCCESSES/$RANDOM_TRIALS random passwords round-tripped successfully"
fi

# Passwords with spaces, punctuation and non-ASCII bytes must work too:
# the password is read as a line and used as raw bytes.
for pw in "with spaces in it" 'quotes"and$dollars' "pässwörd mit Ümlauten"; do
    echo "$pw" | "$ENCRYPT_BIN" "$WORKDIR/short.txt" "$WORKDIR/pw.mtnc" 3 >/dev/null 2>&1
    echo "$pw" | "$DECRYPT_BIN" "$WORKDIR/pw.mtnc" "$WORKDIR/pw.out" >/dev/null 2>&1
    if cmp -s "$WORKDIR/short.txt" "$WORKDIR/pw.out"; then
        pass "password with unusual characters round-trips"
    else
        fail "password with unusual characters round-trips"
    fi
    rm -f "$WORKDIR/pw.out"
done

# ---------------------------------------------------------------------------
# Test 8: CLI argument validation
# ---------------------------------------------------------------------------
echo "test_cli_argument_validation:"
"$ENCRYPT_BIN" >/dev/null 2>&1
if [ $? -ne 0 ]; then pass "encrypt with no arguments fails"; else fail "encrypt with no arguments fails"; fi

"$DECRYPT_BIN" >/dev/null 2>&1
if [ $? -ne 0 ]; then pass "decrypt with no arguments fails"; else fail "decrypt with no arguments fails"; fi

echo "pw" | "$ENCRYPT_BIN" "$WORKDIR/plain1.txt" "$WORKDIR/badn.mtnc" 1 >/dev/null 2>&1
if [ $? -ne 0 ]; then pass "encrypt rejects n=1"; else fail "encrypt rejects n=1"; fi

echo "pw" | "$ENCRYPT_BIN" "$WORKDIR/plain1.txt" "$WORKDIR/badn.mtnc" 999 >/dev/null 2>&1
if [ $? -ne 0 ]; then pass "encrypt rejects n larger than MC_MAX_N"; else fail "encrypt rejects n larger than MC_MAX_N"; fi

# n was parsed with atoi(), which returns 0 for text that is not a number
# and ignores trailing garbage - so "4abc" and "4.9" were silently accepted
# as 4, and "banana" was reported as being out of range rather than as not
# being a number at all.
for bad_n in "4abc" "4.9" "banana" "" " " "0x4" "-4" "+"; do
    rm -f "$WORKDIR/argn.mtnc"
    echo "pw" | "$ENCRYPT_BIN" "$WORKDIR/plain1.txt" "$WORKDIR/argn.mtnc" "$bad_n" >"$WORKDIR/argn.log" 2>&1
    if [ $? -ne 0 ] && [ ! -f "$WORKDIR/argn.mtnc" ]; then
        pass "encrypt rejects a malformed n ('$bad_n')"
    else
        fail "encrypt rejects a malformed n ('$bad_n')"
    fi
done

# A valid n with surrounding whitespace is a number, and strtol accepts it.
echo "pw" | "$ENCRYPT_BIN" "$WORKDIR/plain1.txt" "$WORKDIR/okn.mtnc" " 3" >/dev/null 2>&1
if [ $? -eq 0 ]; then pass "encrypt accepts a well-formed n with leading space"; else fail "encrypt accepts a well-formed n with leading space"; fi

"$DECRYPT_BIN" "$WORKDIR/no_such_file_mc_integration" "$WORKDIR/nope.out" >/dev/null 2>&1
if [ $? -ne 0 ]; then pass "decrypt rejects a nonexistent input file"; else fail "decrypt rejects a nonexistent input file"; fi

echo "pw" | "$ENCRYPT_BIN" "$WORKDIR/no_such_file_mc_integration" "$WORKDIR/nope.mtnc" >/dev/null 2>&1
if [ $? -ne 0 ]; then pass "encrypt rejects a nonexistent input file"; else fail "encrypt rejects a nonexistent input file"; fi

echo "not a valid mountain cipher container" > "$WORKDIR/garbage.mtnc"
echo "pw" | "$DECRYPT_BIN" "$WORKDIR/garbage.mtnc" "$WORKDIR/garbage.out" >/dev/null 2>&1
if [ $? -ne 0 ]; then pass "decrypt rejects a file with a bad magic number"; else fail "decrypt rejects a file with a bad magic number"; fi

# ---------------------------------------------------------------------------
# Test 9: an over-long password is refused rather than truncated
#
# fgets filled the 1024-byte buffer and dropped the rest, so a passphrase
# longer than 1023 characters silently became its own first 1023 characters
# - a different key than the user typed, with nothing said about it - and
# the remainder was left on stdin for whatever read next.
# ---------------------------------------------------------------------------
echo "test_over_long_password:"
LONG_PW="$(head -c 3000 /dev/zero | tr '\0' 'x')"
PREFIX_PW="$(printf '%s' "$LONG_PW" | cut -c1-1023)"

rm -f "$WORKDIR/long.mtnc"
printf '%s\n' "$LONG_PW" | "$ENCRYPT_BIN" "$WORKDIR/short.txt" "$WORKDIR/long.mtnc" 4 >"$WORKDIR/long.log" 2>&1
if [ $? -ne 0 ] && [ ! -f "$WORKDIR/long.mtnc" ]; then
    pass "an over-long password is refused and nothing is encrypted"
else
    fail "an over-long password is refused and nothing is encrypted"
fi
if grep -q "longer than" "$WORKDIR/long.log"; then
    pass "the refusal says the password was too long"
else
    fail "the refusal says the password was too long"
    cat "$WORKDIR/long.log"
fi

# A password of exactly the maximum length must still work, both ways.
MAX_PW="$(printf '%s' "$LONG_PW" | cut -c1-1023)"
printf '%s\n' "$MAX_PW" | "$ENCRYPT_BIN" "$WORKDIR/short.txt" "$WORKDIR/max.mtnc" 3 >/dev/null 2>&1
printf '%s\n' "$MAX_PW" | "$DECRYPT_BIN" "$WORKDIR/max.mtnc" "$WORKDIR/max.out" >/dev/null 2>&1
if cmp -s "$WORKDIR/short.txt" "$WORKDIR/max.out"; then
    pass "a password of exactly the maximum length round-trips"
else
    fail "a password of exactly the maximum length round-trips"
fi
# And the truncation must be gone: the 1023-character prefix of the
# over-long password must NOT open anything, because nothing was written.
if [ ! -f "$WORKDIR/long.mtnc" ]; then
    pass "the 1023-character prefix of an over-long password opens nothing"
else
    printf '%s\n' "$PREFIX_PW" | "$DECRYPT_BIN" "$WORKDIR/long.mtnc" "$WORKDIR/long.out" >/dev/null 2>&1
    if [ $? -ne 0 ]; then
        pass "the 1023-character prefix of an over-long password opens nothing"
    else
        fail "the 1023-character prefix of an over-long password opens nothing"
    fi
fi

# ---------------------------------------------------------------------------
# Test 10: malformed containers are rejected cleanly
#
# num_blocks and n come straight off disk and are not covered by either
# hash, so a crafted file can claim anything. None of these may crash, hang,
# or be read as valid.
# ---------------------------------------------------------------------------
echo "test_malformed_containers:"
HEADER_LEN=78

# Truncated: the last eight bytes removed.
SIZE=$(wc -c < "$WORKDIR/plain1.mtnc")
head -c $((SIZE - 8)) "$WORKDIR/plain1.mtnc" > "$WORKDIR/trunc.mtnc"
echo "test_password_1" | "$DECRYPT_BIN" "$WORKDIR/trunc.mtnc" "$WORKDIR/trunc.out" >"$WORKDIR/trunc.log" 2>&1
if [ $? -ne 0 ] && grep -q "size mismatch" "$WORKDIR/trunc.log"; then
    pass "a truncated container is rejected as a size mismatch"
else
    fail "a truncated container is rejected as a size mismatch"
fi

# Header only, with the block count left claiming real ciphertext.
head -c "$HEADER_LEN" "$WORKDIR/plain1.mtnc" > "$WORKDIR/hdronly.mtnc"
echo "test_password_1" | "$DECRYPT_BIN" "$WORKDIR/hdronly.mtnc" "$WORKDIR/hdronly.out" >/dev/null 2>&1
if [ $? -ne 0 ]; then pass "a header with no ciphertext is rejected"; else fail "a header with no ciphertext is rejected"; fi

# Empty file, and a file shorter than the header.
: > "$WORKDIR/empty.mtnc"
echo "pw" | "$DECRYPT_BIN" "$WORKDIR/empty.mtnc" "$WORKDIR/e.out" >/dev/null 2>&1
if [ $? -ne 0 ]; then pass "an empty file is rejected"; else fail "an empty file is rejected"; fi

printf 'MTNC' > "$WORKDIR/tiny.mtnc"
echo "pw" | "$DECRYPT_BIN" "$WORKDIR/tiny.mtnc" "$WORKDIR/t.out" >/dev/null 2>&1
if [ $? -ne 0 ]; then pass "a file shorter than the header is rejected"; else fail "a file shorter than the header is rejected"; fi

# A bad format version.
cp "$WORKDIR/plain1.mtnc" "$WORKDIR/badver.mtnc"
printf '\377' | dd of="$WORKDIR/badver.mtnc" bs=1 seek=4 count=1 conv=notrunc >/dev/null 2>&1
echo "test_password_1" | "$DECRYPT_BIN" "$WORKDIR/badver.mtnc" "$WORKDIR/bv.out" >"$WORKDIR/badver.log" 2>&1
if [ $? -ne 0 ] && grep -q "unsupported format version" "$WORKDIR/badver.log"; then
    pass "an unsupported format version is rejected by name"
else
    fail "an unsupported format version is rejected by name"
fi

# An impossible n in the header.
for bad_n_byte in '\000' '\001' '\377'; do
    cp "$WORKDIR/plain1.mtnc" "$WORKDIR/badn2.mtnc"
    printf "$bad_n_byte" | dd of="$WORKDIR/badn2.mtnc" bs=1 seek=5 count=1 conv=notrunc >/dev/null 2>&1
    echo "test_password_1" | "$DECRYPT_BIN" "$WORKDIR/badn2.mtnc" "$WORKDIR/bn.out" >/dev/null 2>&1
    if [ $? -ne 0 ]; then
        pass "an out-of-range n in the header is rejected"
    else
        fail "an out-of-range n in the header is rejected"
    fi
done

# A zero block count. The encryptor always pads, so it never writes one;
# a container claiming zero blocks is malformed and must be refused before
# any key derivation work is done.
cp "$WORKDIR/plain1.mtnc" "$WORKDIR/zeroblocks.mtnc"
dd if=/dev/zero of="$WORKDIR/zeroblocks.mtnc" bs=1 seek=6 count=8 conv=notrunc >/dev/null 2>&1
echo "test_password_1" | "$DECRYPT_BIN" "$WORKDIR/zeroblocks.mtnc" "$WORKDIR/zb.out" >"$WORKDIR/zb.log" 2>&1
if [ $? -ne 0 ] && grep -q "no ciphertext blocks" "$WORKDIR/zb.log"; then
    pass "a container claiming zero blocks is rejected as malformed"
else
    fail "a container claiming zero blocks is rejected as malformed"
    cat "$WORKDIR/zb.log"
fi

# A block count large enough that num_blocks * n * n * 8 overflows a 64-bit
# size, which the size check alone would not catch.
cp "$WORKDIR/plain1.mtnc" "$WORKDIR/hugeblocks.mtnc"
printf '\001\000\000\000\000\000\000\010' | dd of="$WORKDIR/hugeblocks.mtnc" bs=1 seek=6 count=8 conv=notrunc >/dev/null 2>&1
echo "test_password_1" | "$DECRYPT_BIN" "$WORKDIR/hugeblocks.mtnc" "$WORKDIR/hb.out" >"$WORKDIR/hb.log" 2>&1
if [ $? -ne 0 ] && grep -q "implausible block count" "$WORKDIR/hb.log"; then
    pass "an implausible block count is rejected by arithmetic, not by a failed malloc"
else
    fail "an implausible block count is rejected by arithmetic, not by a failed malloc"
    cat "$WORKDIR/hb.log"
fi

# ---------------------------------------------------------------------------
# Test 11: empty file round trip (edge case: zero-length plaintext)
# ---------------------------------------------------------------------------
echo "test_empty_file:"
: > "$WORKDIR/empty.txt"
echo "empty_pw" | "$ENCRYPT_BIN" "$WORKDIR/empty.txt" "$WORKDIR/empty2.mtnc" 4 >/dev/null 2>"$WORKDIR/enc_empty.log"
if [ $? -eq 0 ]; then
    echo "empty_pw" | "$DECRYPT_BIN" "$WORKDIR/empty2.mtnc" "$WORKDIR/empty.out" >/dev/null 2>"$WORKDIR/dec_empty.log"
    if cmp -s "$WORKDIR/empty.txt" "$WORKDIR/empty.out"; then
        pass "empty file round trip succeeds"
    else
        fail "empty file round trip succeeds"
        cat "$WORKDIR/dec_empty.log"
    fi
else
    fail "empty file encryption succeeds"
    cat "$WORKDIR/enc_empty.log"
fi

# A single byte, and a file exactly one block long, are the other two
# boundaries of the padding rule.
printf 'x' > "$WORKDIR/one.txt"
echo "one_pw" | "$ENCRYPT_BIN" "$WORKDIR/one.txt" "$WORKDIR/one.mtnc" 4 >/dev/null 2>&1
echo "one_pw" | "$DECRYPT_BIN" "$WORKDIR/one.mtnc" "$WORKDIR/one.out" >/dev/null 2>&1
if cmp -s "$WORKDIR/one.txt" "$WORKDIR/one.out"; then
    pass "a one-byte file round-trips"
else
    fail "a one-byte file round-trips"
fi

printf '0123456789abcdef' > "$WORKDIR/exact.txt"
echo "exact_pw" | "$ENCRYPT_BIN" "$WORKDIR/exact.txt" "$WORKDIR/exact.mtnc" 4 >/dev/null 2>&1
echo "exact_pw" | "$DECRYPT_BIN" "$WORKDIR/exact.mtnc" "$WORKDIR/exact.out" >/dev/null 2>&1
if cmp -s "$WORKDIR/exact.txt" "$WORKDIR/exact.out"; then
    pass "a file exactly one block long round-trips (full padding block added)"
else
    fail "a file exactly one block long round-trips (full padding block added)"
fi

# ---------------------------------------------------------------------------
# Test 12: documented weaknesses, pinned at the container level
#
# These assert that the cipher still behaves the way README "Known
# Limitations" says it does. If one fails, the design has changed and the
# README needs changing with it.
# ---------------------------------------------------------------------------
echo "test_documented_weaknesses:"

# Encryption is deterministic: no nonce, no IV, and the salt is derived
# from the plaintext, so the same file and password give the same bytes.
echo "same_pw" | "$ENCRYPT_BIN" "$WORKDIR/plain1.txt" "$WORKDIR/det_a.mtnc" 4 >/dev/null 2>&1
echo "same_pw" | "$ENCRYPT_BIN" "$WORKDIR/plain1.txt" "$WORKDIR/det_b.mtnc" 4 >/dev/null 2>&1
if cmp -s "$WORKDIR/det_a.mtnc" "$WORKDIR/det_b.mtnc"; then
    pass "encryption is deterministic (documented weakness: no nonce or IV)"
else
    fail "encryption is deterministic (documented weakness: no nonce or IV)"
fi

# The container stores SHA-256 of the plaintext in the clear, which is a
# confirmation oracle for guessable content.
if command -v sha256sum >/dev/null 2>&1; then
    PLAIN_HASH="$(sha256sum "$WORKDIR/plain1.txt" | cut -d' ' -f1)"
    HEADER_HASH="$(od -An -tx1 -j 14 -N 32 "$WORKDIR/plain1.mtnc" | tr -d ' \n')"
    if [ "$PLAIN_HASH" = "$HEADER_HASH" ]; then
        pass "the plaintext hash is stored in the clear (documented weakness: confirmation oracle)"
    else
        fail "the plaintext hash is stored in the clear (documented weakness: confirmation oracle)"
    fi
else
    echo "  SKIP: sha256sum not available for the plaintext-hash check"
fi

# Identical plaintext blocks produce identical ciphertext blocks, because
# a singular plaintext block gives a zero control determinant.
printf 'AAAAAAAAAAAAAAAA%.0s' 1 2 3 4 5 > "$WORKDIR/repeat.txt"
echo "repeat_pw" | "$ENCRYPT_BIN" "$WORKDIR/repeat.txt" "$WORKDIR/repeat.mtnc" 4 >/dev/null 2>&1
BLOCK_A="$(od -An -tx1 -j $((HEADER_LEN + 128)) -N 128 "$WORKDIR/repeat.mtnc" | tr -d ' \n')"
BLOCK_B="$(od -An -tx1 -j $((HEADER_LEN + 256)) -N 128 "$WORKDIR/repeat.mtnc" | tr -d ' \n')"
if [ "$BLOCK_A" = "$BLOCK_B" ] && [ -n "$BLOCK_A" ]; then
    pass "repeated plaintext blocks are visible in the ciphertext (documented weakness: ECB-like)"
else
    fail "repeated plaintext blocks are visible in the ciphertext (documented weakness: ECB-like)"
fi

# ---------------------------------------------------------------------------
# Test 13: the password wipe is not optimised away
#
# memset(password, 0, strlen(password)) immediately before free() is a dead
# store, and GCC 13 at -O2 removed it along with the strlen - the built
# binary contained neither. mc_secure_wipe() writes through a volatile
# pointer and is called across a translation unit boundary, so the stores
# have to survive. Checked by looking at the binary, because a functional
# test can only show that the bytes end up zero, never that the compiler
# kept the code that zeroed them.
# ---------------------------------------------------------------------------
echo "test_password_wipe_survives_optimisation:"
if command -v objdump >/dev/null 2>&1; then
    # Only the binary under test is inspected. An earlier draft fell back
    # to build/mountain_encrypt.o when the symbol was not found, which made
    # this check pass for the original binaries - it was reading a
    # different build's object file. A test that can pass by looking
    # somewhere else is not testing the thing it names.
    for bin in "$ENCRYPT_FILE" "$DECRYPT_FILE"; do
        if objdump -d "$bin" 2>/dev/null | grep -q "mc_secure_wipe"; then
            pass "$(basename "$bin") contains the secure wipe routine"
        else
            fail "$(basename "$bin") contains the secure wipe routine"
        fi
    done
else
    echo "  SKIP: objdump not available for the wipe check"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "======================================"
echo "Integration tests: $PASS passed, $FAIL failed"
echo "======================================"

if [ "$FAIL" -ne 0 ]; then
    exit 1
fi
exit 0
