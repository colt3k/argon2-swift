# Data formats (as-is)

Two binary/text formats are defined by this package. Both are little-endian
unless noted. There is no persistence layer, database, or file I/O in the
tree; these are the formats of the values the API returns.

## 1. PHC string (text)

Defined by `Argon2PHC.encode` / `Argon2PHC.decode` (`PHC.swift:24-83`).

```
$argon2<variant>$v=<version>$m=<memory>,t=<time>,p=<parallelism>$<salt>$<tag>
```

| Field | Format | Domain (enforced) |
| --- | --- | --- |
| `variant` | one of `d`, `i`, `id` (literal `argon2d` / `argon2i` / `argon2id`) | complete set, `PHC.swift:26-49` |
| `version` | unsigned decimal `UInt32` | `19` (`0x13`) is the only value that survives `validate()` |
| `memory` | unsigned decimal `UInt32`, KiB | `>= 8 * parallelism` (after decode) |
| `time` | unsigned decimal `UInt32` | `>= 1` (after decode) |
| `parallelism` | unsigned decimal `UInt32` | `>= 1` (after decode) |
| `salt` | standard base64, padding stripped | any length; `count % 4 != 1` |
| `tag` | standard base64, padding stripped | `>= 4` bytes (after decode), length defines `outputLength` |

Fixed examples:

- Round-trip shape: `$argon2id$v=19$m=19456,t=2,p=1$<22 b64 chars>$<44 b64
  chars>` for a 16-byte salt and 32-byte tag (`PHCTest.swift:16`).
- Known vector: `$argon2i$v=19$m=8,t=1,p=1$AQIDBA$3q2+7w` — salt
  `01 02 03 04`, tag `DE AD BE EF` (`PHC.swift:39-40` via
  `PHCTest.testKnownVectorEncoding`).

`decode` tolerates reordered `m/t/p` fields and duplicate keys (last
occurrence wins); everything else is rejected — the complete rejection list
is in [modules/phc.md](modules/phc.md#decode-_--parsing-rules-and-complete-rejection-list).

## 2. Vault record (binary)

Defined by `PasswordVault.encrypt` / `PasswordVault.decrypt`
(`Vault.swift:11-18,40-111`).

| Offset (bytes) | Size | Field | Notes |
| --- | --- | --- | --- |
| 0 | 4 | `variant` | LE32; `2` for argon2id (only accepted value in practice — `init` precondition) |
| 4 | 4 | `version` | LE32; `19` (`0x13`) |
| 8 | 4 | `timeCost` | LE32; `t` |
| 12 | 4 | `memoryCostKilobytes` | LE32; `m` |
| 16 | 4 | `parallelism` | LE32; `p` |
| 20 | 2 | `saltLen` | LE16; max `65535` |
| 22 | `saltLen` | `salt` | bytes as passed to `encrypt` (default: 16 random bytes) |
| `22 + saltLen` | 12 | `nonce` | AES-GCM nonce, random per record |
| `34 + saltLen` | 16 | `tag` | AES-GCM authentication tag |
| `50 + saltLen` | `record.count - 50 - saltLen` | `ciphertext` | AES-GCM ciphertext exactly as produced by CryptoKit (`box.ciphertext`, appended as-is; the 16-byte GCM tag lives in the separate field above) |

Fixed sizes: header `22` bytes (`headerLength = 5 * 4 + 2`,
`Vault.swift:27`), nonce `12` (`Vault.swift:25`), tag `16`
(`Vault.swift:26`). Minimum record length `50` bytes (empty salt, empty
plaintext). With the default 16-byte salt, header + salt = `38` bytes, so a
record for an N-byte plaintext is `50 + 16 + N` = `66 + N` bytes.

Self-describing property: `decrypt` reads `variant`, `version`, `t`, `m`,
`p` and `salt` from the record itself (`Vault.swift:76-100`) and derives the
key with those values, so a differently-configured vault instance can open
the record. The record's fields are not authenticated against the vault's
configuration — only the GCM tag authenticates the ciphertext/nonce/tag
under the derived key.

## 3. Engine-internal format: `H_0`

`Argon2Engine.initHash` produces a 72-byte buffer: the 64-byte
`BLAKE2b-512` digest of

```
LE32(p) || LE32(keyLen) || LE32(m) || LE32(t) || LE32(0x13) || LE32(mode)
|| LE32(len(P)) || P || LE32(len(S)) || S || LE32(len(K)) || K || LE32(len(X)) || X
```

followed by 8 zero bytes reused as the counter (offset 64, 4 bytes) and lane
(offset 68, 4 bytes) fields during block initialization
(`Argon2Engine.swift:48-79`). `h0Digest` exposes only the first 64 bytes
(`Argon2Engine.swift:37-44`).
