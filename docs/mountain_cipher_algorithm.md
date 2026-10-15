# Mountain Cipher — Complete Algorithm

---

## Definitions

| Symbol      | Meaning                                                              |
| ----------- | --------------------------------------------------------------------- |
| `n`         | Dimension of the square key matrix (n×n)                             |
| `P`         | Plaintext block (n×n integer matrix)                                 |
| `C`         | Ciphertext block (n×n integer matrix)                                |
| `key`       | The **original** key matrix (n×n integer matrix). Generated **once** in Phase 1.3 and never overwritten afterward. |
| `work_key`  | A **temporary, per-block** matrix derived from `key` by applying that block's mutation. Used only to encrypt/decrypt the current block, then discarded. It never carries over to the next block. |
| `d`         | Control determinant for the current block                            |
| `adj(M)`    | Adjugate (classical adjoint) of matrix M                              |
| `det(M)`    | Determinant of matrix M                                               |
| `Rᵢ`        | Row i of a matrix (0-indexed)                                         |

**The one rule to hold onto:** `key` itself never changes after Phase 1.3.
What changes from block to block is (a) which mutation is applied to
`key` to produce that block's disposable `work_key`, and (b) the cyclic
shift applied to the plaintext/ciphertext block. Nothing here
accumulates across blocks except the *choice* of `d`, which is carried
forward via the previous ciphertext block.

---

## Phase 1 — Pre-Encryption Setup

**Step 1.1 — Hash the plaintext file**

```
file_hash_plaintext = SHA256(plaintext file)
```

**Step 1.2 — Derive the key seed from password**

```
key_seed = Argon2id(password, salt = file_hash_plaintext)
```

Argon2id is used instead of raw SHA256 to make brute force attacks infeasible.

**Step 1.3 — Generate the key matrix (once, for the whole file)**

```
key = n×n integer matrix seeded deterministically from key_seed
      using SHAKE-256 XOF (extendable output function)
      such that det(key) ≠ 0
```

If the generated matrix has det = 0, advance the PRNG and retry.

`key` is now fixed. It is **not** reassigned, overwritten, or mutated
anywhere in Phase 2 or Phase 5 below — every later step that needs a
mutated matrix computes it fresh from this original `key` into
`work_key`, and throws `work_key` away after the block is done.

**Step 1.4 — Split plaintext into blocks**

```
Divide plaintext bytes into chunks of n×n bytes each
Pad the final block using PKCS#7 padding if needed
Map each chunk to an n×n integer matrix in row-major order
```

---

## Phase 2 — Encryption (per block, left to right)

**Step 2.1 — Set control determinant**

```
For the first block:   d = det(key)
For block i > 1:       d = det(C_{i-1})   ← determinant of previous ciphertext block
```

**Step 2.2 — Derive this block's working key from the original key**

`work_key` always starts as a fresh copy of the original `key` — never
from the previous block's `work_key`.

```
work_key = copy(key)
```

If `d` is **odd**:

```
work_key = transpose(work_key)
```

If `d` is **even**:

```
Let i = d mod n        ← index of row to update
Replace row Rᵢ of work_key with:

Rᵢ ← Rᵢ + Σ (-1)^(k+1) · Rₖ    for all k ≠ i,  k = 0, 1, ..., n-1

i.e. add an alternating-sign combination of every OTHER row onto row i
itself (Rᵢ is part of its own replacement — this is what makes it a
genuine elementary row operation).
This is a Type III elementary row operation (add a linear combination of
other rows to a row) → det(work_key) = det(key) exactly, always.
```

Because `work_key` is rebuilt from the untouched original `key` every
single block, and because this mutation is now determinant-preserving,
`work_key` is guaranteed invertible (nonzero determinant) for every
block, for the entire file — not just the first one.

**Step 2.3 — Column shift**

```
If d = 0  → skip (no shift)
Else      → cyclically shift all columns of P left by (d mod n) positions
```

**Step 2.4 — Encrypt the block**

```
C = work_key × P_shifted    ← integer matrix multiplication, no floats
```

**Step 2.5 — Store ciphertext block**

```
Append C to ciphertext output
```

**Step 2.6 — Repeat**

```
Discard work_key.
Move to next plaintext block, go back to Step 2.1.
(key itself is untouched and reused as the starting point next block.)
```

---

## Phase 3 — Post-Encryption Output

**Step 3.1 — Hash the ciphertext**

```
file_hash_ciphertext = SHA256(all ciphertext blocks)
```

**Step 3.2 — Transmit**

```
Transmitted package = [ file_hash_plaintext ]
                      [ file_hash_ciphertext ]
                      [ ciphertext blocks ]
```

The key is NEVER transmitted. It is regenerated from the password on the receiver's side.

---

## Phase 4 — Pre-Decryption Setup

**Step 4.1 — Verify ciphertext integrity**

```
Compute SHA256(received ciphertext blocks)
Compare with received file_hash_ciphertext

If they do NOT match → abort (ciphertext was tampered with)
If they match       → proceed
```

**Step 4.2 — Regenerate the key**

```
key_seed = Argon2id(password, salt = file_hash_plaintext)
key      = same deterministic SHAKE-256 generation as encryption
```

This regenerated `key` is, again, fixed for the whole file — identical
in spirit to Phase 1.3. Wrong password → wrong `key` → garbage
plaintext → will fail the integrity check in Step 6.2.

**Step 4.3 — Read ciphertext blocks**

```
Split received ciphertext into n×n blocks
Map each to an n×n integer matrix in row-major order
```

---

## Phase 5 — Decryption (per block, left to right)

**Step 5.1 — Set control determinant**

```
For the first block:   d = det(key)
For block i > 1:       d = det(C_{i-1})   ← same rule as encryption, read from the ciphertext blocks already on hand
```

**Step 5.2 — Reconstruct this block's working key from the original key**

Exactly mirrors Step 2.2: always start from a fresh copy of the
original, regenerated `key`, never from the previous block's
`work_key`.

```
work_key = copy(key)

If d is odd  → work_key = transpose(work_key)
If d is even → replace row Rᵢ (i = d mod n) with:
               Rᵢ ← Rᵢ + Σ (-1)^(k+1) · Rₖ   for all k ≠ i
```

**Step 5.3 — Undo column shift**

```
If d = 0  → skip
Else      → cyclically shift all columns of C RIGHT by (d mod n) positions
            (opposite direction of encryption's shift on P)
```

**Step 5.4 — Decrypt the block (integer-only, no floats)**

```
Compute:   Z = adj(work_key) × C_unshifted       ← pure integer matrix multiply

Then:      P = Z / det(work_key)                 ← exact integer division, always

Why exact: since C = work_key × P was how C was produced,
           adj(work_key) × C = adj(work_key) × work_key × P
                              = det(work_key) × I × P = det(work_key) × P
           so det(work_key) cancels perfectly with no remainder, guaranteed
           — provided det(work_key) ≠ 0, which Step 2.2/5.2's mutation
           guarantees for every block.
```

**Step 5.5 — Repeat**

```
Discard work_key.
Move to next ciphertext block, go back to Step 5.1.
```

---

## Phase 6 — Post-Decryption Verification

**Step 6.1 — Reassemble plaintext**

```
Concatenate all decrypted plaintext blocks
Strip padding bytes from the final block
```

**Step 6.2 — Verify plaintext integrity**

```
Compute SHA256(reassembled plaintext)
Compare with received file_hash_plaintext

If they do NOT match → wrong password was used, or data is corrupted
If they match       → decryption successful, plaintext is authentic
```

---

## Security Properties Summary

| Property                 | Mechanism                                                                        |
| ------------------------ | -------------------------------------------------------------------------------- |
| Key secrecy              | Derived via Argon2id, never transmitted                                          |
| Brute force resistance   | Argon2id is deliberately slow and memory-hard                                    |
| Key uniqueness per file  | file_hash_plaintext acts as salt → same password, different file = different key |
| Ciphertext integrity     | SHA256(ciphertext) checked before decryption attempt                             |
| Plaintext integrity      | SHA256(plaintext) checked after decryption                                       |
| Wrong password detection | Produces garbage plaintext → hash mismatch at Step 6.2                           |
| No floating point        | Adjugate identity guarantees exact integer division always                       |
| Block chaining           | Each block's working-key mutation and column shift are chosen by the previous ciphertext block's determinant |
| Determinant preserved    | Transpose and the Type III row operation both leave `det(key)` unchanged, so every block's `work_key` is invertible |
| Bounded key size         | `key` is generated once and never accumulates changes, so `work_key` magnitudes stay a fixed function of the original key — they don't grow block over block |
