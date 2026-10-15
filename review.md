# Code Review — Mountain Cipher

First reviewed 2026-09-04. **Remediated 2026-09-21** on branch
`cleanup/2026-09-21`; this file is now a record rather than a to-do list.
What was found, what was fixed, what was deliberately left alone, and
what is still waiting for a person, are all below.

---

## Corrections to the first review

The first review was accurate. Every one of its six findings was real and
all were reproduced against the original code before anything was
changed — including finding 3, which is the kind of claim that is usually
theoretical. Two things it said need qualifying rather than correcting.

**Its verdict — "the most disciplined project in the archive" — holds up
under testing, and the testing was worth doing anyway.** The linear
algebra is correct: an independent implementation of the specification,
written in Python with arbitrary-precision integers and a different
determinant algorithm, agrees with the C on every generated vector,
covering both Step 2.2 branches and four distinct column shifts. The
overflow guards work. The original key really is never mutated.

**But "the suite is real" understated how much it was not covering.** It
had 87 checks and had never once been green on the author's own platform
(see finding 7), it could not tell a working binary from one that would
not start (finding 8), and the three worst defects in the project were
all outside what it looked at. The QIC lesson applies here in a milder
form: a passing suite is evidence about what it covers.

**Finding 1's severity was understated, not overstated.** The review put
the plaintext-hash oracle at P1 and said it was "arguably more serious
than several that are already there". It is. It is also not the worst
thing in the project — see new finding A.

---

## New findings, in severity order

These are the things the first review did not have. All were reproduced
against the original code first.

### A. P0 — `mountain_encrypt` could produce files that could never be decrypted, and reported success

This is the one that matters. Encryption multiplies key entries
(|x| ≤ 128) by plaintext bytes and stays comfortably inside `int64_t`.
Decryption multiplies by the **adjugate**, whose entries grow factorially
with `n`. The two do not fail together.

So `mountain_encrypt secret.txt secret.mtnc 9` printed

```
Encrypted 'secret.txt' -> 'secret.mtnc' (n=9, 1 block(s))
```

exited 0, and produced a container that `mountain_decrypt` could not open
with the correct password, then or ever. Measured over twelve passwords
on a two-byte file:

| `n` | encrypted | unrecoverable |
| --- | --- | --- |
| 6, 7 | 12/12 | 0 |
| **8** | **12/12** | **3** |
| **9** | **4/12** | **4 — all of them** |
| 10-12 | 0/12 | 0 |

`n = 9` is within the range the CLI accepts (`MC_MAX_N` is 12), and the
header's own comment recommends "keep n small (<= 8)" — which is exactly
where the losses begin. Anybody who encrypted, checked the file existed,
and deleted the original lost the file.

**Fixed** by having `mountain_encrypt` decrypt its own output in memory
and compare it against the padded plaintext before writing anything
(`mc_encrypt_is_recoverable()`). If the ciphertext would not decrypt, it
says so and writes no file. It costs one extra decryption per encryption.

There is deliberately no new fixed ceiling on `n`. Whether the overflow
fires depends on the key and the data, not on `n` alone — which is why
three passwords out of twelve failed at `n=8` and nine did not. A static
limit would have to be conservative and would still be a guess;
verification is exact.

### B. P1 — the block chaining carries almost nothing

The specification's summary table lists "block chaining" as a security
property. The code implements the specification faithfully; the
specification's claim is the problem, so this is documentation, not a
code bug, and the code was not touched.

Every Step 2.2 branch preserves `det(key)` — that is the invariant the
whole design rests on. Therefore

```
det(C_i) = ± det(work_key) × det(P_i) = ± det(key) × det(P_i)
```

and three things follow:

1. **The chain does not accumulate.** Block `i`'s control determinant is
   a function of block `i-1`'s *plaintext* alone. A one-bit change to
   block 0 changes block 1 and then stops — blocks 2 onward are
   byte-identical. Demonstrated in
   `test_chaining_does_not_reach_past_the_next_block`.
2. **Only `d mod 2` and `d mod n` are ever observed**, so one block's
   entire influence on the next is a value with at most `2n`
   possibilities: three bits at the default `n = 4`.
3. **A singular plaintext block zeroes the control determinant.** A run
   of one repeated byte is singular, so a file of repeated blocks
   produces repeated ciphertext blocks — the ECB property, visible in a
   hex dump:

```
block 1: 8b740000000000008b74000000000000...
block 2: 8b740000000000008b74000000000000...
block 3: 8b740000000000008b74000000000000...
```

Added to the README as Known Limitation 10, and pinned by two tests that
assert the weakness is still there, so that a future change which fixes
it cannot silently leave the README wrong.

### C. P3 — the container header is not covered by any hash

`file_hash_ciphertext` covers the ciphertext blocks only; `n`,
`num_blocks` and `file_hash_plaintext` are unauthenticated. This is not a
forgery route — altering them yields garbage that fails the plaintext
hash check — but `num_blocks` came off disk and went straight into size
arithmetic, and the only thing stopping an absurd value was a very large
`malloc` happening to fail.

**Fixed** in `mountain_decrypt`: a zero block count (which the encryptor
never writes, since it always pads) and a count too large to describe a
real file are both rejected by arithmetic, before any Argon2id work.
Documented as Known Limitation 9.

---

## The first review's findings

**1. Plaintext-hash confirmation oracle — confirmed, documented.**
`SHA-256(plaintext)` sits in the clear at offset 14. Verified against
`sha256sum`. Now Known Limitation 7, with the standard fix (a MAC over the
ciphertext under a key derived alongside the encryption key) named. Not
implemented: it is a specification change.

**2. Deterministic encryption; plaintext hash used as the Argon2id salt —
confirmed, documented.** Two encryptions of the same file with the same
password are byte-identical. Now Known Limitation 8, and pinned by a test
so the README cannot drift from the behaviour.

**3. Password wipe elided — confirmed on this toolchain, fixed.** Not
theoretical: `objdump` on the original object file showed neither a
`memset` nor a `strlen` relocation anywhere in `mountain_encrypt.o`, and
the disassembly runs `call mc_derive_key_seed` → `test eax` →
`call free`. GCC 13.2 at `-O2` deleted the whole wipe. Replaced with
`mc_secure_wipe()`, which writes through a `volatile` pointer from
another translation unit; the stores survive, and the integration suite
checks the built binaries for them. Also now wipes `key_seed`, and the
decrypted plaintext buffer, which nothing wiped before.

**4. No echo-off on Windows — confirmed, fixed.** The echo-disabling code
was inside `#if defined(__unix__) || defined(__APPLE__)`, so on the
platform this project is developed on it compiled out entirely and
passwords were typed in plain view. Added a `_WIN32` branch using
`GetConsoleMode`/`SetConsoleMode` with `ENABLE_ECHO_INPUT` cleared.
`GetConsoleMode` only succeeds for a real console, so piped input still
takes the visible path exactly as before.

**5. Over-long passwords silently truncated — confirmed, fixed.** A
3000-character passphrase became its own first 1023 characters with
nothing said, and the remaining 1977 were left on stdin for whatever read
next. Demonstrated by encrypting with 3000 characters and decrypting with
the first 1023. `cli_read_password_line()` now distinguishes the three
cases — end of input, a line exactly the maximum length, and a genuinely
over-long line — and refuses the third. A password of exactly 1023
characters still works; an early version of the fix rejected it, and the
unit test caught that before it was committed.

**6. `atoi` for the matrix dimension — confirmed, fixed.** `4abc` and
`4.9` were both silently accepted as 4, and `banana` produced a message
about the valid range rather than about the argument not being a number.
Replaced with `strtol` and end-pointer validation.

**Testing — both suggestions taken.** Known-answer tests and overflow-path
tests are described below.

**Cleanup — nothing to remove, still true.** No debug output, no dead
code, no secrets. The only addition is a `.gitignore` for build output.

---

## Two defects in the test suite itself

### 7. The unit suite had never passed on the author's own platform

`test_crypto.c` wrote its fixture to `/tmp/mc_test_sha256_file.txt`. On
Windows there is no `/tmp`, `fopen` returned NULL, and three checks
failed — so `make test` had never been green on the machine this project
is developed on. Fixed by using the working directory, which the runner is
already in on every platform.

### 8. Every negative test passed while the binaries could not start

Most of the integration suite asserts that something is *rejected*, and a
binary that cannot load its libraries is rejected by the operating
system. Running the original suite against two executables that could not
find `libcrypto` reported **nine passes**, including "wrong password is
rejected" and "tampered ciphertext is rejected", against tools that never
executed a line of their own code.

Fixed with a preflight that requires both binaries to run and print their
usage, and aborts the whole suite otherwise. The rejection tests now also
assert on the specific message rather than on the exit status alone.

An earlier draft of the new wipe check had the same shape of bug: when it
could not find the symbol in the binary it fell back to reading
`build/mountain_encrypt.o`, which made it pass against the *original*
binaries because it was looking at a different build. Removed.

---

## What the test suite is now

502 checks, from 107. No framework, no new dependency.

| File | Checks | What it covers |
| --- | --- | --- |
| `tests/unit/test_matrix.c` | 86 | Linear algebra and padding. New: the Bareiss overflow guard, the zero-pivot row-swap branch, negative determinants, and the padding edge cases. |
| `tests/unit/test_crypto.c` | 33 | Hashing and key derivation. New: an Argon2id parameter vector, an empty file, and a file spanning several read buffers. |
| `tests/unit/test_cipher.c` | 277 | New. The block pipeline against known answers, the recoverability guarantee, and the chaining properties. |
| `tests/unit/test_cli_util.c` | 44 | New. Password line parsing, file I/O, secure wipe. |
| `tests/integration/test_roundtrip.sh` | 62 | The real binaries. New: the `n` sweep, malformed containers, argument validation, over-long passwords, and the documented weaknesses. |

Run against the original code, the new integration suite fails 10 of 62.
Every fix above has a test that fails without it.

Three things in it are worth stealing:

**The known-answer vectors are generated from the specification, not
recorded from the code.** `tools/gen_vectors.py` is a second
implementation of `docs/mountain_cipher_algorithm.md`, written from the
document, using arbitrary-precision integers and computing determinants by
Gaussian elimination over `Fraction` rather than by the Bareiss recurrence
the C uses. Two different algorithms agreeing is evidence; the same
algorithm transcribed twice is not. Recording the C's current output would
have frozen its bugs as the expected answer — which is what QIC's 152
passing tests did.

**The Argon2id vector was cross-checked against the reference
implementation's own CLI**, not just recorded:

```sh
printf mountain | argon2 0123456789abcdef0123456789abcdef -id -t 3 -m 16 -p 1 -l 32 -r
```

It matters because the parameters are not stored in the container, so
changing any of them makes every previously encrypted file undecryptable
with no error that points at the cause. The test turns that into a
failure at the moment the parameter changes.

**Three tests assert that documented weaknesses are still present** —
deterministic output, repeated ciphertext blocks, and the one-block
chaining depth. If one fails, the cipher has improved and the README is
now wrong. The recoverability test does the same in the other direction:
it asserts that the sweep still finds cases where encryption succeeds and
decryption cannot, so that nobody deletes the check on the grounds that it
never fires.

---

## Deliberately not changed

**The cipher's design.** The plaintext-hash salt, the missing nonce, the
bare-hash integrity, the linear map and the shallow chaining are all
properties of the specification in `docs/`. The value of this repository
is that it implements that algorithm faithfully and says where the
algorithm falls short, so all of them are documented rather than fixed.

**`docs/mountain_cipher_algorithm.md`.** Its "Security Properties"
summary table overstates what the block chaining achieves (finding B).
The specification is the author's final-year-project document and is left
as written; the correction is in the README and here.

**`MC_MAX_N`.** Still 12. Finding A's fix means a value too large for a
given file now fails loudly before anything is written, which is a better
answer than a lower constant that would still be wrong in both directions.

**The CLI's wording**, with one addition and one correction. The usage
text, the prompts and the existing error messages are untouched. Added: a
message for a ciphertext that would not decrypt (a failure mode that did
not previously exist), one for an over-long password, and two for
malformed block counts. Corrected: a non-numeric `n` now says it is not a
number instead of describing the valid range, which is the same shape of
fix as the validation message flagged in `CLEANUP-LOG.md`.

---

## Still needs a person

**Nothing blocking.** Two small things worth ten minutes if you are at the
machine:

1. **The Windows echo-off branch has never been used by a human.** It
   cannot be tested automatically: the tests pipe stdin, and
   `GetConsoleMode` only succeeds for a real console, so the automated
   path is precisely the one that skips the new code. Run
   `mountain_encrypt secret.txt out.mtnc` in a real terminal and confirm
   the password does not appear as you type, and that the terminal still
   echoes normally afterwards — including if you press Ctrl+C at the
   prompt, which leaves echo disabled if the restore is missed.
2. **The same on a Unix terminal**, to confirm the `termios` path still
   behaves after the restructuring. It was working before and the logic is
   unchanged, so this is a check that nothing regressed.

---

## Notes for a future session

Build and test with `make` then `make test`. On Windows, `libargon2` has
to be built from the reference implementation first; see README
"Building" for the flag shape, and `CONTINUE-HERE.md` for where it was put
on this machine.

The authority for behaviour is `docs/mountain_cipher_algorithm.md`. If
code and spec disagree, that is a finding, not a licence to change the
code. Do not "fix" the cipher's design in place.

If you add or change anything in Phases 2 or 5, they now live in
`src/mountain_cipher.c` and are shared by both CLIs — they used to be
transcribed separately into each, which is two copies of four steps that
must agree exactly or a file cannot be recovered.

And if you change how a key is derived or a matrix is generated, regenerate
the vectors **from the specification** with `tools/gen_vectors.py`. Do not
regenerate them by recording what the new code prints.

## Licence, 2026-10-02

The author chose one licence for all of their projects: free for personal,
non-commercial use, modifiable for the user's own use, and not to be
distributed, original or modified. No standard licence says that, so `LICENSE`
is a short custom text, the same in every project apart from the year and what
it excludes. The README's licence section says the same. Anything above that
calls the licence an open question, or calls the project MIT, is superseded.

## CI, 2026-10-02

`.github/workflows/ci.yml` installs `libssl-dev` and `libargon2-dev` and runs
`make test` on `ubuntu-latest`. Nothing has been pushed, so it has not run on
GitHub yet. Every job was run before committing, from a fresh clone of this
branch, the way a runner would run it: Linux jobs in a throwaway Ubuntu 24.04
(the image `ubuntu-latest` uses) with the same tool versions. 440 unit checks
and 62 integration checks.

Windows is left out: its build needs an Argon2 compiled by hand.
