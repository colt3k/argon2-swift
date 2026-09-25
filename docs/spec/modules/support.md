# Support — byte helpers and buffer wiping

Purpose: internal little-endian encoding/decoding helpers shared by the
BLAKE2b and Argon2 ports, plus the sensitive-buffer zeroing function.
All crypto arithmetic in the package uses the wrapping operators
(`&+`, `&*`, `&-`) so debug and release builds are identical
(`ByteHelpers.swift:1-4`).

Sources: `Sources/Argon2/ByteHelpers.swift`, `Sources/Argon2/Wipe.swift`.
Visibility: all internal (no `public`).

## API

| Symbol | Signature | Behavior | Source |
| --- | --- | --- | --- |
| `putLE32` | `func putLE32(_ arr: inout [UInt8], _ offset: Int, _ value: UInt32)` | `@inline(__always)`; writes 4 little-endian bytes at `offset` | `ByteHelpers.swift:6-12` |
| `putLE64` | `func putLE64(_ arr: inout [UInt8], _ offset: Int, _ value: UInt64)` | `@inline(__always)`; writes 8 little-endian bytes at `offset` | `ByteHelpers.swift:14-24` |
| `leUint64` | `func leUint64(_ b: [UInt8], _ off: Int) -> UInt64` | reads 8 little-endian bytes at `off` | `ByteHelpers.swift:26-36` |
| `rotl64` | `func rotl64(_ v: UInt64, _ n: UInt64) -> UInt64` | `@inline(__always)`; `(v << n) \| (v >> (64 - n))`. Documented contract: `n` is always in `1...63` in this codebase — `rotl64(v, 0)` would trap (`64 - 0 == 64` shift on a 64-bit value) | `ByteHelpers.swift:38-42` |
| `appendLE32` | `extension Array where Element == UInt8 { mutating func appendLE32(_ v: UInt32) }` | appends `v` as 4 little-endian bytes | `ByteHelpers.swift:44-52` |
| `wipe` | `func wipe(_ bytes: inout [UInt8])` | overwrites every element with `0` via an explicit index loop; buffer is `inout`, so the writes are observable mutations of the caller's storage (stated intent: cannot be elided by optimization) | `Wipe.swift:7-10` |

Note: there is no `leUint32` in `ByteHelpers.swift` — `PasswordVault`
defines its own private `leUint32`/`leUint16` pair for record parsing
(`Vault.swift:146-156`).

## Usage map

| Helper | Used by |
| --- | --- |
| `putLE32` | `Argon2Engine.initHash` (password/salt/secret/ad length prefixes), `Argon2Engine.initBlocks` (counter/lane fields in `H_0`) |
| `putLE64` | `Argon2Engine.extractKey` (LE-encoding the final block) |
| `leUint64` | `Blake2b.hashBlocks` (message words), `Argon2Engine.initBlocks` (block words) |
| `rotl64` | `Blake2b.g`, `Argon2Engine.blamkaGeneric` |
| `appendLE32` | `Argon2Engine.initHash` (the 6 parameter fields) |
| `wipe` | `PasswordVault.deriveKey` (`defer { wipe(&key) }`, `Vault.swift:125`) |

## Dependencies

Calls: nothing (leaf module).
Called by: `Blake2b`, `Argon2Engine`; `wipe` by `PasswordVault`.

## Data

None.
