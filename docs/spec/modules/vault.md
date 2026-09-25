# Vault — `PasswordVault`

Purpose: derive an AES-256 key from a low-entropy password with Argon2id,
then encrypt/decrypt self-describing records with AES-256-GCM (CryptoKit).
The key is never stored; derived key material is wiped after use
(`Vault.swift:1-9,113-127`).

Source: `Sources/Argon2/Vault.swift`. Visibility: public struct.

## Public API

| Symbol | Signature | Parameters | Returns | Errors | Source |
| --- | --- | --- | --- | --- | --- |
| `defaultParams` | `static let defaultParams: Argon2Params` | — | `Argon2Params(variant: .id, timeCost: 3, memoryCostKilobytes: 65536, parallelism: 4, outputLength: 32)` — RFC 9106 second recommended setting (argon2id, t=3, m=64 MiB, p=4, AES-256 key) | — | `Vault.swift:21-23` |
| `params` | `public let params: Argon2Params` | — | the vault's configured parameters | — | `Vault.swift:29` |
| `init(params:)` | `public init(params: Argon2Params = PasswordVault.defaultParams)` | `params` | new vault | `precondition` traps (not an error) unless `params.variant == .id` **and** `params.outputLength == 32` — messages: `"PasswordVault requires argon2id"`, `"PasswordVault requires a 32-byte (AES-256) key"` | `Vault.swift:33-37` |
| `encrypt(plaintext:password:salt:)` | `public func encrypt(plaintext: Data, password: Data, salt: Data = Argon2.randomSalt(length: 16)) throws -> Data` | `plaintext`: any length (0 allowed — GCM seals empty plaintext fine). `password`: any length. `salt`: default a fresh 16-byte `Argon2.randomSalt` | the self-describing record `Data` (layout in [data.md](../data.md)) | `Argon2Error.invalidParameters` from `params.validate()`; CryptoKit `Error` (unwrapped, non-`Argon2Error`) if `AES.GCM.Nonce(data:)` or `AES.GCM.seal` fails | `Vault.swift:40-64` |
| `decrypt(_:password:)` | `public func decrypt(_ record: Data, password: Data) throws -> Data` | `record`: bytes from `encrypt`. `password`: any length | the recovered plaintext | `Argon2Error.malformedCiphertext`, `Argon2Error.invalidParameters`, `Argon2Error.authenticationFailed` (see below) | `Vault.swift:70-111` |

Internal: `private func deriveKey(password:salt:params:) -> [UInt8]`
(`Vault.swift:113-127`) — calls `Argon2Engine.derive` with empty `secret`
and `ad`, `defer { wipe(&key) }`.

Also internal (file-private, `Vault.swift:130-157`): `Data.appendLE32`,
`Data.appendLE16`, `leUint32(_:_:)`, `leUint16(_:_:)` — little-endian
serialization helpers (separate from `ByteHelpers.swift`).

## Constants (literal values)

| Constant | Value | Source |
| --- | --- | --- |
| `nonceLength` | `12` (private) | `Vault.swift:25` |
| `tagLength` | `16` (private) | `Vault.swift:26` |
| `headerLength` | `5 * 4 + 2` = `22` bytes (private) | `Vault.swift:27` |
| Minimum record size | `headerLength + nonceLength + tagLength` = `50` bytes (zero-length salt, zero-length ciphertext) | `Vault.swift:72` |
| Max salt length | `65535` (`UInt16` field; larger salts cannot be encoded by `encrypt` — `appendLE16(UInt16(salt.count))` would trap on overflow, `Vault.swift:58`) | `Vault.swift:58,81` |

## Internal Behavior

### `encrypt` (`Vault.swift:40-64`)

1. `params.validate()`.
2. Derive the AES-256 key: `deriveKey(password:salt:params:)` (Argon2id,
   wiped on return).
3. `SymmetricKey(data: key)`.
4. Random 12-byte GCM nonce via `Argon2.randomSalt(length: 12)`, wrapped in
   `AES.GCM.Nonce`.
5. `AES.GCM.seal(plaintext, using: symKey, nonce: nonce)` → `box.ciphertext`
   + `box.tag` (16 bytes).
6. Serialize the record (all integers little-endian):
   `LE32(variant) || LE32(version) || LE32(timeCost) ||
   LE32(memoryCostKilobytes) || LE32(parallelism) || LE16(salt.count) ||
   salt || nonce(12) || tag(16) || ciphertext`.

### `decrypt` (`Vault.swift:70-111`)

1. If `record.count < 50` → `malformedCiphertext`.
2. Parse the 22-byte header and `saltLen` (LE16).
3. If `record.count < 22 + saltLen + 12 + 16` → `malformedCiphertext`
   (second length check, `Vault.swift:83-85`).
4. Slice `salt`, `nonce`, `tag`, `ciphertext` (`ciphertext` = all remaining
   bytes, may be empty).
5. Reconstruct `Argon2Params` **from the record's own fields** with
   `outputLength: 32` and
   `variant: Argon2Variant(rawValue: variant) ?? .id` — an unknown variant
   byte silently falls back to `.id` (`Vault.swift:92-99`).
6. `recordParams.validate()` → can throw `invalidParameters` (e.g. a record
   claiming `m < 8p` or `t = 0`).
7. Derive the key from the password with those params (wiped), build
   `AES.GCM.SealedBox(nonce:ciphertext:tag:)`.
8. `AES.GCM.open(box, using: symKey)` — **any** thrown error (wrong password,
   tampered ciphertext or tag, malformed nonce, etc.) is caught and
   rethrown as `Argon2Error.authenticationFailed`
   (`Vault.swift:106-110`). The original error is discarded.

Because the record embeds its cost parameters and salt, a `PasswordVault`
configured with *different* parameters can still open the record (covered by
`VaultTest.testRecordIsSelfDescribing`). `decrypt` never compares the
record's variant/costs against `self.params`.

## Dependencies

Calls: `Argon2Params` (init, `validate()`), `Argon2Variant`, `Argon2Error`,
`Argon2.randomSalt`, `Argon2Engine.derive`, `wipe`, CryptoKit `AES.GCM`
(`Nonce`, `seal`, `SealedBox`, `open`).
Called by: package users (no in-tree callers besides `VaultTest`).

## Data

Pure in-memory. Records are opaque `Data` blobs the caller persists
everywhere; the vault itself performs no I/O.
