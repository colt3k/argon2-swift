# Facade — `Argon2`, `Argon2Params`, `Argon2Variant`, `Argon2Error`

Purpose: the public API surface of the package: key derivation, constant-time
verification, random salt generation, parameter validation, and the error
type shared with `Argon2PHC` and `PasswordVault`.

Sources: `Sources/Argon2/Argon2.swift`, `Sources/Argon2/Argon2Params.swift`,
`Sources/Argon2/Argon2Error.swift`.

## Public API

### `Argon2` (enum namespace, `Argon2.swift:14`)

| Symbol | Signature | Parameters (type, default, valid values) | Returns | Errors | Source |
| --- | --- | --- | --- | --- | --- |
| `deriveKey` | `static func deriveKey(password: Data, salt: Data, secret: Data, associatedData: Data, params: Argon2Params) throws -> Data` | `password`: password bytes, any length (0 allowed). `salt`: salt bytes, any length (0 allowed). `secret`: RFC 9106 secret key `K`, default `Data()` (empty). `associatedData`: RFC 9106 `X`, default `Data()` (empty). `params`: validated against RFC §3.1 before use | `Data` of exactly `params.outputLength` bytes (the tag) | `Argon2Error.invalidParameters(String)` from `params.validate()`. (Inferred: if `outputLength > UInt32.max`, the `UInt32(params.outputLength)` conversion at `Argon2.swift:40` traps at runtime.) | `Argon2.swift:24-44` |
| `verify` | `static func verify(password: Data, expected: Data, salt: Data, secret: Data, associatedData: Data, params: Argon2Params) throws -> Bool` | same as `deriveKey`, plus `expected`: the previously derived tag to compare against | `true` iff the freshly derived key is byte-for-byte equal to `expected`; `false` on length mismatch or any byte difference | same as `deriveKey` | `Argon2.swift:50-63` |
| `randomSalt` | `static func randomSalt(length: Int) -> Data` | `length`: default `16`. Bytes come from `SecRandomCopyBytes(kSecRandomDefault, ...)` | `Data` of `length` cryptographically random bytes | no throws; `precondition` traps if `SecRandomCopyBytes` returns anything other than `errSecSuccess` (`Argon2.swift:69`) | `Argon2.swift:66-71` |

Internal (not public):

| Symbol | Signature | Notes | Source |
| --- | --- | --- | --- |
| `constantTimeEqual` | `static func constantTimeEqual(_ a: Data, _ b: Data) -> Bool` | Returns `false` immediately on length mismatch; otherwise ORs the XOR of every byte pair into a `UInt8` accumulator and compares to 0. Used only by `verify`. | `Argon2.swift:74-81` |

### `Argon2Variant` (enum, `Argon2Params.swift:2-6`)

`public enum Argon2Variant: UInt32, Equatable, Sendable, CaseIterable` with the
complete case list:

| Case | Raw value | PHC name |
| --- | --- | --- |
| `.d` | `0` | `argon2d` |
| `.i` | `1` | `argon2i` |
| `.id` | `2` | `argon2id` |

### `Argon2Params` (struct, `Argon2Params.swift:12-61`)

`public struct Argon2Params: Equatable, Sendable`. All stored properties are
`public var`:

| Property | Type | Notes |
| --- | --- | --- |
| `variant` | `Argon2Variant` | |
| `timeCost` | `UInt32` | iteration count `t` |
| `memoryCostKilobytes` | `UInt32` | memory `m` in KiB (kibibytes), matching RFC `m` |
| `parallelism` | `UInt32` | lane count `p` |
| `outputLength` | `Int` | tag length in bytes |
| `version` | `UInt32` | only `0x13` (19) is accepted |

`public init(variant: Argon2Variant = .id, timeCost: UInt32,
memoryCostKilobytes: UInt32, parallelism: UInt32, outputLength: Int = 32,
version: UInt32 = 0x13)` — defaults: variant `.id`, outputLength `32`,
version `0x13`.

`public func validate() throws` (`Argon2Params.swift:43-60`) enforces, in this
order, throwing `Argon2Error.invalidParameters(String)` with these exact
messages:

| # | Constraint | Error message |
| --- | --- | --- |
| 1 | `version == 0x13` | `"only version 0x13 (v1.3) is supported"` |
| 2 | `timeCost >= 1` | `"timeCost must be >= 1"` |
| 3 | `parallelism >= 1` | `"parallelism must be >= 1"` |
| 4 | `outputLength >= 4` | `"outputLength must be >= 4 bytes"` |
| 5 | `memoryCostKilobytes >= 8 * parallelism` | `"memoryCostKilobytes must be >= 8 * parallelism (<8*p>)"` (message interpolates the computed minimum) |

`validate()` is called by `Argon2.deriveKey`, `Argon2PHC.decode`, and
`PasswordVault.encrypt` (and by `PasswordVault.decrypt` on the record's
embedded parameters). The engine itself does not validate; it is only reached
through callers that do.

### `Argon2Error` (enum, `Argon2Error.swift:2-18`)

`public enum Argon2Error: Error, Equatable`. Complete case list:

| Case | Payload | Thrown by |
| --- | --- | --- |
| `invalidParameters` | `String` | `Argon2Params.validate()` — the only throw site in the tree |
| `invalidSaltLength` | `Int` | **never thrown** (declared only; `Argon2Error.swift:6`) |
| `invalidKeyLength` | `Int` | **never thrown** (declared only; `Argon2Error.swift:8`) |
| `malformedPHC` | `String` | `Argon2PHC.decode`, `PHCBase64.decodeNoPad` (see [phc.md](phc.md)) |
| `authenticationFailed` | — | `PasswordVault.decrypt` when `AES.GCM.open` fails (see [vault.md](vault.md)) |
| `malformedCiphertext` | — | `PasswordVault.decrypt` on size violations (see [vault.md](vault.md)) |
| `incompatibleRecord` | `String` | **never thrown** (declared only; `Argon2Error.swift:17`) |

## Internal Behavior

- `deriveKey` converts `Data` arguments to `[UInt8]` and delegates to
  `Argon2Engine.derive` with `mode: Int(params.variant.rawValue)`
  (`Argon2.swift:32-42`).
- `verify` never short-circuits on a mismatch beyond the length check: it
  derives the full tag, then compares with `constantTimeEqual`.
- `randomSalt` allocates a zero-filled buffer, fills it via
  `SecRandomCopyBytes`, and traps on any non-`errSecSuccess` status
  (`Argon2.swift:67-70`).

## Dependencies

Calls: `Argon2Engine.derive`, `Argon2Params.validate`,
`SecRandomCopyBytes` (Security framework).
Called by: `Argon2PHC` (via `Argon2Params`/`Argon2Error`), `PasswordVault`
(via `Argon2.randomSalt`, `Argon2Error`), and downstream package users.

## Data

Reads / writes: none directly. Random bytes come from the OS CSPRNG.
