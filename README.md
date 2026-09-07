# Argon2 (Swift)

A pure-Swift implementation of the [Argon2](https://www.rfc-editor.org/rfc/rfc9106)
memory-hard function (RFC 9106, version 1.3), with a small, secure
password-vault built on top using AES-256-GCM from Apple's CryptoKit.

No C interop, no system `libsodium`. The core is a Swift implementation
whose output is verified byte-for-byte against both the official RFC 9106
test vectors and the Go reference implementation
(`golang.org/x/crypto/argon2`). It supports the optional secret key (`K`),
associated data (`X`) and all three variants so it can run the full
RFC 9106 test-vector suite.

## Features

- **All three variants** — `argon2d`, `argon2i`, `argon2id` (RFC 9106 §3).
- **Optional secret key and associated data** inputs.
- **PHC string** encode/decode (`$argon2id$v=19$m=...,t=...,p=...$salt$tag`).
- **`PasswordVault`** — derive an AES-256 key from a low-entropy password and
  encrypt/decrypt self-describing records with AES-256-GCM. The key is never
  stored; derived key material is wiped after use.
- **Deterministic** — all arithmetic uses wrapping operators, so debug and
  release builds produce identical output.
- **Accredited** — passes the RFC 9106 §5 tag *and* pre-hashing-digest (H0)
  vectors for all three variants, plus byte-for-byte parity with the Go
  reference library.

## Requirements

- Swift 5.9+
- iOS 15+ / macOS 12+ (for the `PasswordVault` / CryptoKit target)

## Installation

Add the package in `Package.swift`:

```swift
dependencies: [
    .package(path: "../argon2-swift")   // or .package(url: "...", from: "0.1.0")
],
targets: [
    .target(name: "MyTarget", dependencies: [
        .product(name: "Argon2", package: "argon2-swift"),
    ])
]
```

## Usage

### Key derivation

```swift
import Argon2

let params = Argon2Params(variant: .id, timeCost: 3,
                          memoryCostKilobytes: 65536, parallelism: 4,
                          outputLength: 32)
let salt = Argon2.randomSalt(length: 16)

let key = try Argon2.deriveKey(password: Data("s3cret".utf8),
                               salt: salt,
                               params: params)
```

### Verification (constant-time)

```swift
let ok = try Argon2.verify(password: Data("s3cret".utf8),
                           expected: key,
                           salt: salt,
                           params: params)
```

### PHC string

```swift
let phc = Argon2PHC(params: params, salt: salt, tag: key)
let string = phc.encode()          // "$argon2id$v=19$m=65536,t=3,p=4$..."
let decoded = try Argon2PHC.decode(string)
```

`decode` validates the string against the RFC constraints (variant, version,
cost fields) and throws `Argon2Error.malformedPHC` on any malformed input.

### Password vault

```swift
let vault = PasswordVault()   // argon2id, t=3, m=64 MiB, p=4, AES-256

let record = try vault.encrypt(plaintext: Data("top secret".utf8),
                               password: Data("hunter2".utf8))

let plaintext = try vault.decrypt(record, password: Data("hunter2".utf8))
```

Each record is self-describing: it embeds the Argon2 cost parameters, the
salt, the GCM nonce, the 16-byte auth tag and the ciphertext, so `decrypt`
only needs the password. A wrong password or any tampered byte fails
authentication and throws `Argon2Error.authenticationFailed`.

## Parameter guidance

`PasswordVault.defaultParams` uses the RFC 9106 **second recommended**
setting (argon2id, t=3, m=64 MiB, p=4) — a good default for memory-constrained
environments. For server-side password storage, OWASP recommends at least
argon2id with m ≥ 19 MiB, t ≥ 2, p ≥ 1; scale `m`/`t` up to your memory and
latency budget.

## Security notes

- Argon2id is the recommended variant; `argon2d`/`argon2i` are available but
  `argon2id` should be used for password hashing (side-channel resistance).
- Use a **unique, random salt per password** (`Argon2.randomSalt`).
- Derived key material is zeroed before return (`Wipe.swift`).
- The vault uses AES-256-GCM (authenticated encryption) from CryptoKit — no
  hand-rolled AEAD.

## Testing

The standard SwiftPM commands work as usual:

```
swift build
swift test
```

For test runs you want to read, use the provided script:

```
./run_tests.sh                 # release build, all tests
./run_tests.sh -c debug        # debug configuration
./run_tests.sh -f vault        # only tests matching "vault"
./run_tests.sh -l              # list tests without running
```

`run_tests.sh` runs the built `.xctest` bundle directly via `xcrun xctest`
instead of `swift test`. SwiftPM pipes the xctest process's stdout and drops
buffered chunks, which truncates the tests' printed output; invoking the
bundle directly inherits stdout and streams everything. It also passes
`-enable-testing` so the tests can `@testable import Argon2`.

The suite (22 tests) covers:

- **RFC 9106 §5** — tag and H0 vectors for `argon2d`, `argon2i`, `argon2id`.
- **Go parity** — byte-for-byte match against `golang.org/x/crypto/argon2`.
- **PHC** — encode/decode round-trip, a fixed known vector, malformed rejection.
- **Vault** — round-trip, self-describing records, wrong-password and
  tamper rejection, truncated-record rejection.
- **Validation** — RFC §3.1 parameter constraints.

## License

[MIT](LICENSE).