# Mountain Cipher

A C implementation of the Mountain Cipher: a Hill-cipher variant that
replaces modular arithmetic with exact integer linear algebra —
determinants, adjugates and elementary row operations over `int64_t`,
with no modulus and no floating point anywhere.

**Do not use it to protect anything.** It is a student exploration of an
idea, implemented carefully and documented honestly, and it has real
weaknesses — several of them serious, all of them listed below. If you
need encryption, use AES-GCM or ChaCha20-Poly1305.

## Where it came from

The algorithm is Manish Majhi's final-year project for a BSc CSIT at
Mechi Multiple Campus, Tribhuvan University. It began as one question:

> *Can I improve the Hill cipher using other techniques of linear algebra?*

The classical Hill cipher multiplies a plaintext vector by a key matrix
modulo some base, usually 26 or 256. It is elegant and textbook-breakable:
the map is purely linear, so a handful of known plaintext blocks recovers
the key by ordinary algebra.

Mountain Cipher asks what happens if you drop the modulus and work in
exact integers, and make the key change from block to block — transposed
or row-mutated depending on the parity of a *control determinant* carried
forward from the previous ciphertext block, with a determinant-driven
column shift on top. That is the whole idea, and this repository
implements it exactly as written in
[`docs/mountain_cipher_algorithm.md`](docs/mountain_cipher_algorithm.md).

The specification is the authority. Where the code and the spec disagree,
the code is wrong.

## How it works

Encryption, per the spec's six phases:

1. **Hash the plaintext.** `file_hash_plaintext = SHA-256(file)`.
2. **Derive a key seed.** `key_seed = Argon2id(password, salt = file_hash_plaintext)`,
   with t=3, m=64 MiB, p=1.
3. **Generate the key matrix once.** SHAKE-256 expands `key_seed` into
   `n×n` bytes, each read as a signed 8-bit value. If the result is
   singular, a counter is appended and it tries again. This `key` is then
   fixed for the whole file and is never mutated.
4. **Split into blocks** of `n×n` bytes, PKCS#7 padded — always padded,
   so unpadding is never ambiguous.
5. **For each block**, take a control determinant `d` — `det(key)` for the
   first block, `det(C_prev)` afterwards — and from it derive a
   *disposable* working key: transpose if `d` is odd, or add an
   alternating-sign combination of the other rows onto row `d mod n` if it
   is even. Both operations leave the determinant unchanged, so the
   working key is always invertible. Shift the plaintext block's columns
   left by `d mod n`, then `C = work_key × P`.
6. **Hash the ciphertext** and write the container.

Decryption reverses it. The trick that makes it work in integers is the
adjugate identity: `adj(M) × M = det(M) × I`, so

```
adj(work_key) × C = adj(work_key) × work_key × P = det(work_key) × P
```

and dividing by `det(work_key)` is always exact — no fractions, no
rounding, no floating point. The column shift is undone on the
*ciphertext* rather than the plaintext, which is valid because a column
shift is right-multiplication by a permutation matrix and therefore
commutes with the key's left-multiplication.

## Layout

```
mountain_cipher/
├── docs/mountain_cipher_algorithm.md   the specification this implements
├── include/
│   ├── mountain_cipher.h               matrix ops, hashing, key derivation,
│   │                                   padding, and the block pipeline
│   └── cli_util.h                      password and file helpers
├── src/
│   ├── mountain_cipher.c               everything above, including Phases 2 and 5
│   ├── cli_util.c                      password reading, file read/write
│   ├── mountain_encrypt.c              CLI: Phases 1-3
│   └── mountain_decrypt.c              CLI: Phases 4-6
├── tests/
│   ├── unit/                           C test binaries, no framework
│   │   ├── test_framework.h            ~30 lines of assertion macro
│   │   ├── test_matrix.c               linear algebra and padding
│   │   ├── test_crypto.c               SHA-256, Argon2id, SHAKE-256
│   │   ├── test_cipher.c               the block pipeline, against known answers
│   │   ├── test_cli_util.c             password parsing and file I/O
│   │   └── vectors.h                   GENERATED - see tools/gen_vectors.py
│   └── integration/test_roundtrip.sh   drives the real binaries
└── tools/gen_vectors.py                generates vectors.h from the spec
```

Phases 2 and 5 live in `src/mountain_cipher.c`, not in the two CLI
programs. They used to be written out separately in each, which meant two
hand-made copies of the same four steps that had to agree exactly or a
file could not be recovered.

## Building

Needs a C11 compiler, OpenSSL's `libcrypto` (SHA-256 and SHAKE-256) and
`libargon2` (Argon2id).

```sh
# Debian/Ubuntu
sudo apt-get install libssl-dev libargon2-dev
make
```

That produces `mountain_encrypt` and `mountain_decrypt`.

Where the libraries are not on the default search path — which is every
Windows machine — append to the search paths rather than overriding the
flags, which would drop the warning and optimisation settings:

```sh
make EXTRA_CFLAGS=-IC:/path/to/argon2/include \
     EXTRA_LDFLAGS=-LC:/path/to/argon2/lib \
     EXTRA_LDLIBS="-lws2_32 -lcrypt32 -ladvapi32 -luser32"
```

Those four extra libraries are what a statically linked OpenSSL needs on
Windows. `libargon2` ships no Windows binary; building it from the
reference implementation is six files and one `ar` invocation.

## Usage

```sh
mountain_encrypt <input_file> <output_file> [n]
mountain_decrypt <input_file> <output_file>
```

`n` is the key matrix dimension, default 4. Both tools read the password
from the terminal with echo disabled, on Windows as well as on Unix.

```console
$ mountain_encrypt secret.txt secret.mtnc 4
Password:
Encrypted 'secret.txt' -> 'secret.mtnc' (n=4, 1 block(s))

$ mountain_decrypt secret.mtnc recovered.txt
Password:
Decrypted 'secret.mtnc' -> 'recovered.txt' (integrity verified)
```

A wrong password, or a modified file, is refused:

```console
$ mountain_decrypt secret.mtnc out.txt
Password:
Error: plaintext integrity check FAILED - wrong password or corrupted data.

$ mountain_decrypt tampered.mtnc out.txt
Error: ciphertext integrity check FAILED - file was tampered with or corrupted. Aborting.
```

### Choosing `n`

Use 4 unless you have a reason not to. The practical ceiling is lower
than `MC_MAX_N` suggests, and it depends on the file and the key rather
than on `n` alone:

| `n` | Multi-block files | Single-block files |
| --- | --- | --- |
| 2-4 | fine | fine |
| 5-7 | refused: the chaining determinant leaves 64-bit range | fine |
| 8   | refused | refused for roughly a quarter of passwords |
| 9+  | refused | refused |

Every one of those refusals happens *before* anything is written, and
`mountain_encrypt` exits non-zero with an explanation. It will not write a
container it cannot read back — see Known Limitation 1.

## Container format

```
[4 bytes]   magic "MTNC"
[1 byte]    format version (1)
[1 byte]    n
[8 bytes]   num_blocks, little-endian uint64
[32 bytes]  file_hash_plaintext   SHA-256 of the original input
[32 bytes]  file_hash_ciphertext  SHA-256 of the raw ciphertext blocks
[...]       num_blocks * n * n entries, each an int64 little-endian
```

The key is never stored. Note that only the ciphertext is hashed: the
header is not covered by either digest. See Known Limitation 9.

## Testing

```sh
make test              # everything
make test-unit         # the four C test binaries
make test-integration  # the real CLI binaries, end to end
```

502 checks: 440 unit and 62 integration. They need no test framework and
no dependency beyond what the project already builds against.

The known-answer vectors in `tests/unit/vectors.h` are **generated from
the specification, not recorded from this code**. `tools/gen_vectors.py`
is a second implementation of the algorithm written from the spec
document, using arbitrary-precision integers and computing determinants
by a different algorithm than the C does. Vectors captured from the code
under test would agree with it by construction and would assert nothing;
these can disagree. Regenerate with:

```sh
python tools/gen_vectors.py > tests/unit/vectors.h
```

Running the tests does not need Python — the header is committed.

Three of the tests assert that documented *weaknesses* are still present:
that encryption is deterministic, that repeated plaintext blocks are
visible in the ciphertext, and that a change does not propagate past the
following block. If one of those fails, the cipher has changed for the
better and this README needs to change with it.

---

## Known Limitations

The first six were in the original README and are still accurate, with
corrections where measurement disagreed with them. Numbers 7 to 10 were
added after the code was tested properly.

### 1. Encryption and decryption do not fail together

Encryption multiplies key entries (at most 128 in absolute value) by
plaintext bytes, and stays well inside `int64_t`. Decryption multiplies by
the **adjugate**, whose entries grow factorially with `n`. So there are
files and keys that encrypt without complaint and can never be decrypted.

This used to be silent. `mountain_encrypt` printed `Encrypted ...`,
exited 0, and wrote a container that `mountain_decrypt` could not open:
at `n=8` for about a quarter of passwords, and at `n=9` for every one it
managed to encrypt at all. A user following that with `rm secret.txt` lost
the file.

`mountain_encrypt` now decrypts its own output in memory and compares it
against the plaintext before writing anything. If the result would not be
recoverable it says so and writes nothing. This costs one extra
decryption per file; the alternative cost is the file.

There is no safe fixed ceiling on `n` to use instead — whether the
overflow happens depends on the key and the data, which is why three
different passwords at `n=8` behave three different ways. Checking is
exact where a limit would be a guess.

### 2. Intermediate values can exceed 64-bit range

Every matrix entry is a signed 64-bit integer. The Bareiss determinant
recurrence's intermediate term can exceed that range even when the entries
and the final determinant are modest, and the adjugate is worse. Both
routines compute in `__int128` and check the result fits before narrowing,
returning `MC_ERR_OVERFLOW_GUARD` rather than a wrapped value.

The original README said `n = 4` "comfortably handles files of hundreds
of blocks" and that larger `n` "can hit this ceiling sooner". Measured,
the boundary is sharper than that: for any file of more than one block,
`n = 5` and above fails immediately, because the control determinant is
`det(C_prev)` and a ciphertext block's determinant is about
`det(key) × det(P)`, which leaves 64-bit range at once for `n ≥ 5`.
Single-block files reach `n = 8`. See the table under "Choosing `n`".

This is a consequence of fixed-width integers under a design that has no
modulus to keep values bounded. Arbitrary precision would remove the
ceiling and replace it with unbounded ciphertext growth.

### 3. No known-plaintext resistance

`C = work_key × P` is a linear map, exactly as in the Hill cipher.
Enough known plaintext/ciphertext pairs recover `work_key` by ordinary
linear algebra. Dropping the modulus does not change that — real block
ciphers resist it with non-linear substitution, and this has none.

### 4. The adjugate is `O(n!)`

`mc_adjugate()` expands cofactors over `(n-1)×(n-1)` minors, each needing
its own determinant. `MC_MAX_N` caps `n` at 12 so the program cannot hang,
though the range limits above bite first. A production cipher would not
have a per-block cost shaped like this.

### 5. Key entries carry little entropy each

Each SHAKE-256 output byte becomes one signed key entry in [-128, 127],
partly to keep later arithmetic inside the 64-bit range. An `n=4` key is
16 bytes of key material regardless of how much entropy the password had.

### 6. Integrity is a bare hash, not a MAC

Phases 4.1 and 6.2 compare SHA-256 digests. That catches corruption and
casual tampering, but a hash is not keyed: it is not a substitute for
HMAC or an AEAD tag against an adversary who can rewrite the container.

### 7. The plaintext hash is stored in the clear, which is a confirmation oracle

The container holds `SHA-256(plaintext)` at offset 14, unencrypted.
Anyone with the file can test a guessed plaintext by hashing it and
comparing — no key, no cryptanalysis. For anything guessable (a form, a
short message, a file from a known set) that reduces confidentiality to
nothing, and it also reveals when two containers hold the same plaintext.

The hash is there so decryption can verify itself, which is a reasonable
goal. The standard way to get it is a MAC over the *ciphertext* under a
key derived alongside the encryption key, never a bare hash of the
plaintext.

### 8. Encryption is deterministic: same file, same password, same bytes

`mc_derive_key_seed(password, salt = file_hash_plaintext)` uses the
plaintext's hash as the Argon2id salt, and there is no nonce or IV
anywhere in the design. Encrypting the same file twice produces
byte-identical output, so an observer learns when you re-encrypted the
same content.

A salt exists to make precomputation across *different* encryptions
infeasible; one derived from the message still does that between files,
but there is no fresh entropy per encryption. It also makes streaming
impossible by construction: the whole plaintext must be hashed before any
key exists.

The fix is a random 16-byte salt in the header plus a keyed MAC over the
ciphertext. That is a specification change, not a code fix, so it is
documented rather than done.

### 9. The header is not covered by any hash

`file_hash_ciphertext` covers the ciphertext blocks only. The magic,
version, `n`, `num_blocks` and `file_hash_plaintext` are unauthenticated,
so a crafted container can claim any geometry it likes.

This is not a forgery route — decryption with altered header fields
produces garbage, which fails the plaintext hash check — but it means the
"ciphertext integrity" row in the specification's summary table covers
less than the name suggests, and a tampered header is not reported as
tampering. `mountain_decrypt` now rejects the impossible cases (a zero
block count, a count too large to describe a real file) by arithmetic
before doing any Argon2id work.

### 10. The block chaining carries almost nothing

The specification's summary table lists "block chaining" as a security
property: each block's mutation and column shift are chosen by the
previous ciphertext block's determinant. That is what the code does, and
it achieves much less than it sounds like.

Because every Step 2.2 branch preserves `det(key)`:

```
det(C_i) = ± det(work_key) × det(P_i) = ± det(key) × det(P_i)
```

Three things follow, all of them demonstrable in seconds:

- **A block's control determinant depends only on the previous plaintext
  block**, not on anything before it. The chain does not accumulate. A
  one-bit change to the first block of a file changes the second block
  and then stops: the rest of the ciphertext is byte-identical.
- **The mutation and shift only see `d mod 2` and `d mod n`**, so the
  entire influence of one block on the next is a value with at most `2n`
  possibilities — three bits, for the default `n = 4`.
- **A plaintext block whose matrix is singular gives `det(C) = 0`**, which
  fixes the next block's mutation at row 0 and its shift at none. A run of
  one repeated byte is singular, so a file of repeated blocks encrypts to
  repeated ciphertext blocks. That is the property ECB mode is notorious
  for, and it is visible by eye in a hex dump.

Combined with limitation 8, the practical summary is that this is closer
to ECB with a weak per-block tweak than to a chaining mode.

### 11. No formal cryptanalysis

No cryptographer has reviewed this. There is no security proof and no
testing against standard attack models beyond what is written above.

---

## Why publish it

The point was never to ship a cipher. It was to work through
determinants, adjugates and row operations by hand, and then see what a
Hill-cipher variant built out of them actually does when you implement it
for real and test it properly. Some of what it does is in the list above.
That is the useful part.

## Licence

Free for personal, non-commercial use. You may use, study and modify this
software for yourself, but you may not use it commercially, and you may not
share or publish it, in its original form or modified. See [LICENSE](LICENSE)
for the full terms.
