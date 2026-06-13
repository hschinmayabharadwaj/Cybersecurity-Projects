<!-- ©AngelaMos | 2026 -->
<!-- CONFORMANCE.md -->

# PKCS#11 v2.40 Conformance Statement

The AngelaMos HSM Emulator implements the full Cryptoki (PKCS#11) v2.40 C ABI: all
68 functions in the canonical `CK_FUNCTION_LIST`, machine-checked against the
vendored OASIS headers at build time. This document records every place where the
module narrows behavior: the exact return code it gives, the spec clause that
permits it, and why. Every narrowing here is a documented decision with a defined
return value.

A function that is not applicable to a fixed software token returns the specific
code the spec defines for that situation. The `CKR_FUNCTION_NOT_SUPPORTED` results
that remain mark the boundary between single-shot and multi-part operation surfaces,
covered in section 2.

**Specifications**

- PKCS#11 Base Specification v2.40 (OASIS, errata 01) — function semantics and return codes.
- PKCS#11 Current Mechanisms v2.40 (OASIS, errata 01) — per-mechanism parameters.

Section numbers below refer to the Base specification unless a line names the
Mechanisms document.

---

## 1. Function-level conformance

### 1.1 `C_WaitForSlotEvent` — §5.5 (slot and token management)

The module exposes a single fixed slot (ID 0) whose token is always present. No
insertion or removal event can ever occur, so the function reports that fact
precisely rather than pretending to support hardware slot events.

| Call | Return | Basis |
|------|--------|-------|
| `flags` has `CKF_DONT_BLOCK`, no event pending | `CKR_NO_EVENT` | §5.5: a non-blocking poll with no pending event returns `CKR_NO_EVENT`. For a fixed slot, no event is ever pending, so this is always the answer. |
| `flags` clears `CKF_DONT_BLOCK` (blocking) | `CKR_FUNCTION_NOT_SUPPORTED` | A blocking wait must not return until an event occurs. For a fixed software slot no event can occur, so blocking would hang the caller forever. The module declines the blocking mode instead. |
| `pReserved != NULL_PTR` | `CKR_ARGUMENTS_BAD` | §5.5: `pReserved` is reserved and must be `NULL_PTR` in v2.40. |
| called before `C_Initialize` | `CKR_CRYPTOKI_NOT_INITIALIZED` | §5.4 general semantics. |

Interop note: `pkcs11-tool --wait` calls this in blocking mode and therefore
receives `CKR_FUNCTION_NOT_SUPPORTED` immediately rather than blocking. Hosts that
poll with `CKF_DONT_BLOCK` (the common case for slot enumeration) get the correct
`CKR_NO_EVENT`.

### 1.2 `C_GetFunctionStatus`, `C_CancelFunction` — §5.15 (parallel function management)

Both are legacy functions from the era of parallel (asynchronous) Cryptoki calls.
v2.40 has no parallel execution model, and the spec defines the canonical answer
for a serial implementation:

| Call | Return | Basis |
|------|--------|-------|
| `C_GetFunctionStatus` | `CKR_FUNCTION_NOT_PARALLEL` | §5.15: the only meaningful return for a library that does not run functions in parallel. |
| `C_CancelFunction` | `CKR_FUNCTION_NOT_PARALLEL` | §5.15: same. |

### 1.3 `C_SeedRandom` — §5.14 (random number generation)

| Call | Return | Basis |
|------|--------|-------|
| `C_SeedRandom` | `CKR_RANDOM_SEED_NOT_SUPPORTED` | The RNG is the operating-system CSPRNG, drawn through `std.Io.randomSecure` (`getrandom(2)`, `arc4random_buf`, or `/dev/urandom` depending on platform and libc). Caller-supplied seed material cannot meaningfully reseed it, so the module declines rather than silently discarding the seed (which would mislead the caller). |
| `C_GenerateRandom` | fully supported | — |

---

## 2. Operation-surface boundaries

These are the deliberate edges of the multi-part operation surface. Each returns a
specific code so a caller can distinguish "wrong call for this mechanism" from a
runtime failure.

### 2.1 AES-GCM is RUP-safe buffered — §5.8, §5.9

`CKM_AES_GCM` multi-part encryption and decryption buffer the entire message and run
the authenticated operation **once at `*Final`**:

- `C_EncryptUpdate` / `C_DecryptUpdate` append the part to an internal buffer and
  emit **0 bytes**. §5.8/§5.9 permit an Update to produce fewer output bytes than it
  consumes (block buffering); producing the whole result at `*Final` is conformant.
- `C_EncryptFinal` emits ciphertext + 128-bit tag; `C_DecryptFinal` verifies the tag
  and only then releases plaintext.

This is a security decision. A streaming GCM *decrypt* built on incremental
release would hand back **unverified plaintext** before the tag is checked (release
of unverified plaintext, "RUP") — an anti-pattern for an HSM. Buffering until the
tag verifies makes RUP impossible by construction.

Because the buffer holds the whole message, a single GCM message is bounded:

| Condition | Return |
|-----------|--------|
| buffered length would exceed 16 MiB (`max_gcm_stream_len`), encrypt | `CKR_DATA_LEN_RANGE` |
| buffered length would exceed 16 MiB, decrypt | `CKR_ENCRYPTED_DATA_LEN_RANGE` |

Strict parameter validation (`CK_GCM_PARAMS`):

| Parameter | Accepted | Else |
|-----------|----------|------|
| `ulIvLen` | exactly 12 bytes | `CKR_MECHANISM_PARAM_INVALID` |
| `ulIvBits` | `0` or `96` | `CKR_MECHANISM_PARAM_INVALID` |
| `ulTagBits` | exactly `128` | `CKR_MECHANISM_PARAM_INVALID` |
| `pIv` | non-NULL | `CKR_MECHANISM_PARAM_INVALID` |
| `ulAADLen` | ≤ 256 bytes | `CKR_ARGUMENTS_BAD` |

Interop note: a host MUST request a 128-bit tag and supply a 12-byte IV. With
`pkcs11-tool` that means `--iv <24 hex chars> --tag-bits-len 128`; omitting either
trips `CKR_MECHANISM_PARAM_INVALID`.

### 2.2 Dual-function operations — §5.12

| Function | Supported modes | Else |
|----------|-----------------|------|
| `C_DigestEncryptUpdate`, `C_SignEncryptUpdate` (encrypt side) | AES-CBC, AES-CBC-PAD, AES-GCM | — |
| `C_DecryptDigestUpdate`, `C_DecryptVerifyUpdate` (decrypt side) | AES-CBC only | non-CBC → `CKR_FUNCTION_NOT_SUPPORTED` |
| any dual-function leg using an RSA sign/verify operation | — | `CKR_FUNCTION_NOT_SUPPORTED` |

The decrypt side couples the **recovered plaintext** of each `C_Decrypt*Update` into
the digest/verify operation. That coupling is only exact when the cipher releases
exactly the decrypted bytes on every call:

- **AES-CBC** releases each decrypted block immediately, so bytes-out equals
  bytes-to-digest per call. Supported.
- **AES-CBC-PAD** holds back the final block until `C_DecryptFinal` (it cannot know
  the padding until the end), so the digest would miss the last block.
- **AES-GCM** buffers everything and releases at `C_DecryptFinal` (§2.1), so the
  digest would receive nothing incrementally.

Coupling either of the latter would desynchronize the pair, so the module returns
`CKR_FUNCTION_NOT_SUPPORTED` rather than producing a silently wrong digest. The
encrypt side has no such constraint — it digests/signs the **input** plaintext,
which is fully available on each call, so all three modes work.

### 2.3 RSA is single-shot — §5.8, §5.9, §5.11

Every RSA operation is a single modular exponentiation over the whole input, so RSA
has no multi-part form:

| Call on an RSA operation | Return |
|--------------------------|--------|
| `C_EncryptUpdate` / `C_EncryptFinal` | `CKR_FUNCTION_NOT_SUPPORTED` |
| `C_DecryptUpdate` / `C_DecryptFinal` | `CKR_FUNCTION_NOT_SUPPORTED` |
| `C_SignUpdate` / `C_SignFinal` | `CKR_FUNCTION_NOT_SUPPORTED` |
| `C_VerifyUpdate` / `C_VerifyFinal` | `CKR_FUNCTION_NOT_SUPPORTED` |

Use the one-shot `C_Encrypt` / `C_Decrypt` / `C_Sign` / `C_Verify`. The hash-then-sign
mechanisms (`CKM_SHA256_RSA_PKCS`, the PSS variants) still need the full message
before the single RSA operation, so they too are one-shot.

### 2.4 Sign / Verify-Recover — §5.11

| Mechanism | Supported | Else |
|-----------|-----------|------|
| `CKM_RSA_PKCS` (EMSA-PKCS1-v1.5 type 1, message recoverable from the signature) | yes | other mechanism → `CKR_MECHANISM_INVALID` |

`C_SignRecover` rejects input that cannot fit the modulus with PKCS#1 v1.5 overhead
(data length + 11 bytes > modulus) with `CKR_DATA_LEN_RANGE`. `C_VerifyRecover`
returns the recovered message; a signature whose length is not the modulus length
returns `CKR_SIGNATURE_LEN_RANGE`, and a malformed encoding returns
`CKR_SIGNATURE_INVALID`. Raw recover (`CKM_RSA_X_509`) is not offered.

### 2.5 Get / SetOperationState — §5.6

Operation state is **digest-only**:

| Call | Return | Basis |
|------|--------|-------|
| `C_GetOperationState` with an active sign/verify/encrypt/decrypt/sign-recover/verify-recover operation | `CKR_STATE_UNSAVEABLE` | §5.6: a library may decline to save state it cannot serialize. Only digest state is saveable here. |
| `C_GetOperationState` with no operation active | `CKR_OPERATION_NOT_INITIALIZED` | §5.6. |
| `C_SetOperationState` with non-zero `hEncryptionKey` or `hAuthenticationKey` | `CKR_KEY_NOT_NEEDED` | §5.6: a digest needs no key, so passing one is an error. |
| `C_SetOperationState` with a malformed blob (wrong version byte, unknown hasher tag, wrong length) | `CKR_SAVED_STATE_INVALID` | §5.6. |

The saved blob is `[version][hasher tag][raw hasher state]`, validated on restore.
It is **opaque and same-build only**: it carries the raw standard-library hasher
state, whose layout is not stable across builds. PKCS#11 does not promise
operation-state portability across implementations or builds (§5.6). Restore is
byte-exact within the same binary; any other input fails closed via the version,
tag, and exact-length checks above.

---

## 3. Mechanism constraints

### 3.1 ECDH key derivation — §5.13, Mechanisms (CKM_ECDH1_DERIVE)

| Aspect | Value | Else |
|--------|-------|------|
| KDF | `CKD_NULL` only | other KDF → `CKR_MECHANISM_PARAM_INVALID` |
| peer public point | raw SEC1 uncompressed **or** DER `OCTET STRING`-wrapped | malformed → `CKR_MECHANISM_PARAM_INVALID` |
| curves | P-256, P-384 | — |
| shared data | none (`CKD_NULL` carries no shared data) | — |

### 3.2 RSA — Mechanisms (CKM_RSA_PKCS, _PSS, _OAEP)

| Aspect | Value | Else |
|--------|-------|------|
| key size | 2048–4096 bits | outside range → `CKR_KEY_SIZE_RANGE` |
| public exponent | fixed at 65537 (F4) | not selectable at keygen |
| PSS / OAEP hash | SHA-256, SHA-384, SHA-512 | other → `CKR_MECHANISM_PARAM_INVALID` |
| MGF hash | must equal the content hash | mismatch → `CKR_MECHANISM_PARAM_INVALID` |
| OAEP label (source) | not supported | `ulSourceDataLen != 0` → `CKR_MECHANISM_PARAM_INVALID` |

Dedicated `CKM_SHA384_RSA_PKCS` / `CKM_SHA512_RSA_PKCS` mechanisms are not
advertised; SHA-384 and SHA-512 are reachable through the `CKM_RSA_PKCS_PSS` and
`CKM_RSA_PKCS_OAEP` parameter `hashAlg`.

### 3.3 AES — Mechanisms (CKM_AES_*)

AES-128 and AES-256 only. AES-192 is not implemented (the Zig standard library
exposes no 192-bit AES). A key length outside {16, 32} bytes → `CKR_KEY_SIZE_RANGE`.

### 3.4 ECDSA — Mechanisms (CKM_ECDSA*)

Curves P-256 and P-384. Mechanisms `CKM_ECDSA` (pre-hashed input) and
`CKM_ECDSA_SHA256`. `CKM_ECDSA_SHA384` and `CKM_ECDSA_SHA512` are out of scope.

### 3.5 Key wrap — §5.13

| Aspect | Value | Else |
|--------|-------|------|
| wrappable target | secret keys (`CKO_SECRET_KEY`) only | asymmetric target → `CKR_KEY_NOT_WRAPPABLE` |
| wrapping mechanisms | `CKM_AES_KEY_WRAP` (RFC 3394), `CKM_RSA_PKCS_OAEP` | other → `CKR_MECHANISM_INVALID` |
| unextractable target | refused | `CKR_KEY_UNEXTRACTABLE` |
| tampered wrapped blob on unwrap | refused | `CKR_WRAPPED_KEY_INVALID` |

---

## 4. Object and token model (informative)

- **One fixed slot** (ID 0), always present, hosting **one token**. Login is required
  to see or use private objects.
- **Encrypted at rest.** Token objects persist to a file under a selective envelope:
  only sensitive attribute *values* are sealed with AES-256-GCM under a per-token
  master key. The master key is wrapped under a single **User-PIN keyslot**
  (Argon2id-derived KEK). There is no SO keyslot for user secrets by design — the
  Security Officer must not be able to read user key material.
- **Public objects and attributes stay in plaintext** and are visible before login,
  which is spec-correct: only private/sensitive material is gated by login.
- In memory, sensitive attributes are plaintext only while the User is logged in;
  logout and session teardown re-seal them and zeroize the master key.

---

## 5. Advertised mechanism list

`C_GetMechanismList` returns these 21 mechanisms. Key-size units are
mechanism-dependent per the spec (bits for RSA and EC, bytes for AES and HMAC).

| Mechanism | Min | Max | Flags |
|-----------|-----|-----|-------|
| `CKM_SHA256` | 0 | 0 | DIGEST |
| `CKM_SHA384` | 0 | 0 | DIGEST |
| `CKM_SHA512` | 0 | 0 | DIGEST |
| `CKM_SHA256_HMAC` | 32 | 64 | SIGN, VERIFY |
| `CKM_SHA384_HMAC` | 32 | 64 | SIGN, VERIFY |
| `CKM_SHA512_HMAC` | 32 | 64 | SIGN, VERIFY |
| `CKM_AES_KEY_GEN` | 16 | 32 | GENERATE |
| `CKM_AES_CBC` | 16 | 32 | ENCRYPT, DECRYPT |
| `CKM_AES_CBC_PAD` | 16 | 32 | ENCRYPT, DECRYPT |
| `CKM_AES_GCM` | 16 | 32 | ENCRYPT, DECRYPT |
| `CKM_EC_KEY_PAIR_GEN` | 256 | 384 | GENERATE_KEY_PAIR, EC_NAMEDCURVE |
| `CKM_ECDSA` | 256 | 384 | SIGN, VERIFY, EC_NAMEDCURVE |
| `CKM_ECDSA_SHA256` | 256 | 384 | SIGN, VERIFY, EC_NAMEDCURVE |
| `CKM_ECDH1_DERIVE` | 256 | 384 | DERIVE, EC_NAMEDCURVE |
| `CKM_RSA_PKCS_KEY_PAIR_GEN` | 2048 | 4096 | GENERATE_KEY_PAIR |
| `CKM_RSA_PKCS` | 2048 | 4096 | SIGN, VERIFY, ENCRYPT, DECRYPT, SIGN_RECOVER, VERIFY_RECOVER |
| `CKM_SHA256_RSA_PKCS` | 2048 | 4096 | SIGN, VERIFY |
| `CKM_RSA_PKCS_PSS` | 2048 | 4096 | SIGN, VERIFY |
| `CKM_SHA256_RSA_PKCS_PSS` | 2048 | 4096 | SIGN, VERIFY |
| `CKM_RSA_PKCS_OAEP` | 2048 | 4096 | ENCRYPT, DECRYPT, WRAP, UNWRAP |
| `CKM_AES_KEY_WRAP` | 16 | 32 | WRAP, UNWRAP |

---

## 6. Summary: deliberate return codes

| Boundary | Return code |
|----------|-------------|
| `C_WaitForSlotEvent`, non-blocking poll | `CKR_NO_EVENT` |
| `C_WaitForSlotEvent`, blocking mode | `CKR_FUNCTION_NOT_SUPPORTED` |
| `C_WaitForSlotEvent`, `pReserved != NULL` | `CKR_ARGUMENTS_BAD` |
| `C_GetFunctionStatus`, `C_CancelFunction` | `CKR_FUNCTION_NOT_PARALLEL` |
| `C_SeedRandom` | `CKR_RANDOM_SEED_NOT_SUPPORTED` |
| GCM message over 16 MiB | `CKR_DATA_LEN_RANGE` / `CKR_ENCRYPTED_DATA_LEN_RANGE` |
| GCM bad parameters | `CKR_MECHANISM_PARAM_INVALID` / `CKR_ARGUMENTS_BAD` |
| dual-function decrypt side, non-CBC | `CKR_FUNCTION_NOT_SUPPORTED` |
| RSA multi-part (`*Update` / `*Final`) | `CKR_FUNCTION_NOT_SUPPORTED` |
| Sign/Verify-Recover, non-`CKM_RSA_PKCS` | `CKR_MECHANISM_INVALID` |
| Get/SetOperationState, non-digest operation | `CKR_STATE_UNSAVEABLE` |
| SetOperationState with a key handle | `CKR_KEY_NOT_NEEDED` |
| SetOperationState, malformed blob | `CKR_SAVED_STATE_INVALID` |
| ECDH non-`CKD_NULL` KDF | `CKR_MECHANISM_PARAM_INVALID` |
| OAEP with a label | `CKR_MECHANISM_PARAM_INVALID` |
| AES key length not 16/32 bytes | `CKR_KEY_SIZE_RANGE` |
| wrap of an asymmetric target | `CKR_KEY_NOT_WRAPPABLE` |
| wrap of an unextractable key | `CKR_KEY_UNEXTRACTABLE` |

Every entry above is exercised by the unit tests, the in-process smoke harness, or a
cross-process `pkcs11-tool` run; the corrected slot/parallel/RNG codes are asserted
in `examples/smoke.zig` against the built shared object.
