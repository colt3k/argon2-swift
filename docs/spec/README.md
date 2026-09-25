# argon2-swift — Specification

Current state as of 2026-09-25. This spec describes the code in the working tree, not its history.

## Overview

`argon2-swift` is a pure-Swift implementation of the Argon2 memory-hard
function (RFC 9106, version 1.3 / `v=19` / `0x13`), with a small
password-vault built on top using AES-256-GCM from Apple's CryptoKit. No C
interop, no `libsodium`.

- **Language / toolchain:** Swift, `swift-tools-version: 5.9` (`Package.swift:1`).
- **Platforms:** iOS 15+, macOS 12+ (`Package.swift:6-9`).
- **Package layout:** one library product `Argon2` (target `Argon2`), one test
  target `Argon2Tests` (`Package.swift:10-20`).
- **Dependencies:** none declared; system frameworks only — `Foundation`,
  `Security` (CSPRNG), `CryptoKit` (AES-GCM).
- **Determinism:** all crypto arithmetic uses the wrapping operators
  (`&+`, `&*`, `&-`, `&^`), so debug and release builds produce identical
  output (stated in `ByteHelpers.swift:1-5`, `Argon2Engine.swift:6-7`).

## Module map

| Spec file | Symbols | Visibility | Purpose |
| --- | --- | --- | --- |
| [modules/facade.md](modules/facade.md) | `Argon2`, `Argon2Params`, `Argon2Variant`, `Argon2Error` | public | Public API surface: key derivation, constant-time verify, random salt, parameter validation, error types |
| [modules/engine.md](modules/engine.md) | `Argon2Engine` | internal | Argon2 core engine: hash initialization, memory block setup, main loop, index selection, BLAMKA mixing |
| [modules/blake2b.md](modules/blake2b.md) | `Blake2b` | internal | Incremental BLAKE2b digest + extended-length `blake2bHash` used by the engine |
| [modules/phc.md](modules/phc.md) | `Argon2PHC`, `PHCBase64` | public / internal | PHC string encode/decode (`$argon2id$v=19$m=...,t=...,p=...$salt$tag`) |
| [modules/vault.md](modules/vault.md) | `PasswordVault` | public | Argon2id-derived AES-256-GCM vault with self-describing records |
| [modules/support.md](modules/support.md) | `putLE32`, `putLE64`, `leUint64`, `rotl64`, `appendLE32`, `wipe` | internal | Little-endian byte helpers and sensitive-buffer zeroing |
| [data.md](data.md) | — | — | Wire/data formats: PHC string layout, vault record binary layout, fixed constants |
| [tests.md](tests.md) | `RFC9106Test`, `ParityTest`, `PHCTest`, `ValidationTest`, `VaultTest`, `run_tests.sh` | — | Test suite (22 tests) and the test runner script |

There is no UI in this project; the `ui/` directory is not used. There is no
HTTP/endpoint API; the consolidated API reference is the public API table in
[modules/facade.md](modules/facade.md) plus the per-module tables.

## Dependency graph (internal)

```
Argon2 (public facade)
 ├─> Argon2Engine.derive ──> Blake2b (initHash, initBlocks, extractKey, address hashing)
 │        └─> putLE32 / leUint64 / rotl64 / appendLE32 (ByteHelpers)
 ├─> Argon2Params.validate ──> Argon2Error
 ├─> constantTimeEqual (internal, Argon2.swift)
 ├─> SecRandomCopyBytes (Security framework, CSPRNG)
Argon2PHC ──> PHCBase64 ──> Argon2Params.validate
PasswordVault
 ├─> Argon2Engine.derive (key derivation; key wiped via wipe())
 ├─> Argon2.randomSalt (salt + GCM nonce)
 └─> CryptoKit AES.GCM (seal/open)
```

## Verification status

- **Verified by build + run (2026-09-25):** `swift build -c release --build-tests`
  succeeds; all 22 tests pass via `./run_tests.sh -c release`
  (see [tests.md](tests.md) for the per-test breakdown, including the
  RFC 9106 §5 tag and H0 vectors for all three variants and the Go
  reference-implementation parity vectors).
- **Static analysis only:** performance characteristics, the constant-time
  property of `constantTimeEqual` under the Swift optimizer, and the
  effectiveness of `wipe()` against the Swift runtime.
- No area of this spec is marked "(external, not verifiable locally)": all
  behavior is in-tree. The only external dependency is the system
  CSPRNG (`SecRandomCopyBytes`), whose randomness quality is out of scope.

## Discrepancies

- `Argon2Error` declares three cases that are never thrown anywhere in
  `Sources/`: `invalidSaltLength(Int)`, `invalidKeyLength(Int)`,
  `incompatibleRecord(String)` (`Argon2Error.swift:6,8,17`). They are part of
  the public error surface but unreachable from current code paths.
- The README (`README.md:13-14`) states the library "supports the optional
  secret key (K), associated data (X) and all three variants" — consistent
  with the code. The README's claim of "22 tests" (`README.md:167`) matches
  the actual test count.
- `PasswordVault.decrypt` trusts the cost parameters embedded in the record
  and does not compare the record's variant against the vault's configured
  variant (`Vault.swift:91-100`). Records with an unknown variant byte are
  silently treated as argon2id (`Argon2Variant(rawValue:) ?? .id`).