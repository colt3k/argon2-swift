# Test suite and runner

Purpose: document the verification suite that pins the engine to the RFC
9106 §5 vectors, the Go reference implementation, and the vault/PHC
behaviors. 22 tests total; all passed on 2026-09-25 (release configuration,
0 failures, 0.88s, via `./run_tests.sh -c release`).

Sources: `Tests/Argon2Tests/*.swift`, `run_tests.sh`.

## Test classes

### `RFC9106Test` — `Tests/Argon2Tests/RFC9106Test.swift` (6 tests)

RFC 9106 §5.2 accreditation vectors. Common inputs for all six:
`password = 0x01 × 32`, `salt = 0x02 × 16`, `secret = 0x03 × 8`,
`ad = 0x04 × 12`, `t = 3`, `m = 32`, `p = 4`, `taglen = 32`, `v = 19`.

| Test | Method | Expected output (hex) |
| --- | --- | --- |
| `testArgon2dTag` | `Argon2.deriveKey` (variant `.d`) | `512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb` |
| `testArgon2iTag` | `Argon2.deriveKey` (variant `.i`) | `c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8` |
| `testArgon2idTag` | `Argon2.deriveKey` (variant `.id`) | `0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659` |
| `testArgon2dH0` | `Argon2Engine.h0Digest` (mode 0) | `b8819791a0359660bb7709c85fa48f04d5d82c05c5f215ccdb885491717cf757082c28b951be381410b5fc2eb7274033b9fdc7ae672bcaac5d179097a4af3109` |
| `testArgon2iH0` | `Argon2Engine.h0Digest` (mode 1) | `c46065815276a0b3e731731c902f1fd80cf776907fbb7b6a5ca72e7b56011feeca446c86dd75b9469a5e6879dec4b72d0863fb939b982e5f397cc7d164fddaa9` |
| `testArgon2idH0` | `Argon2Engine.h0Digest` (mode 2) | `2889de487eb42ae500c0007ed9252f1069eadec40d5765b485de6dc2437a67b8546a2f0acc1a0882db8fcf74714b472e94df421a5da1112ffa11434370a1e997` |

This class is the only in-tree consumer of `Argon2Engine.h0Digest`.

### `ParityTest` — `Tests/Argon2Tests/ParityTest.swift` (1 test, 3 vectors)

Keyless argon2id parity against `golang.org/x/crypto/argon2` at the common
password-hashing configuration: `t = 3`, `m = 65536` (64 MiB), `p = 4`,
`keyLen = 32`. All three vectors pass in `testArgon2IdMatchesGoLibrary`:

| # | password (UTF-8) | salt | expected tag (hex) |
| --- | --- | --- | --- |
| 1 | `"D2YZUNMIUD43GE4K7EADYFCYPY"` | `00 01 02 ... 0F` (16 bytes ascending) | `90177c0a7e53373be8c62fc9a99625aae40616439c338bbdb86ebb142484d486` |
| 2 | `"ABC123XYZ789"` | `00 × 16` | `618afcb1dc5ebbafe975eeb829af5b738b487398ffc053fe0166a5328b2c915b` |
| 3 | `"Z" × 32` | `FF × 16` | `bf0d3ccecd6e41abbb4dc07bbe9ca154cb70c391ee714775d71ed79c140415d9` |

(The vectors were captured from the Go library; the Go reference itself is
external and not verifiable from this tree.)

### `PHCTest` — `Tests/Argon2Tests/PHCTest.swift` (3 tests)

| Test | Asserts |
| --- | --- |
| `testEncodeDecodeRoundTrip` | encode of `(.id, t=2, m=19456, p=1, out=32)` starts with `$argon2id$v=19$m=19456,t=2,p=1$`; `decode(encode(x)) == x`; re-deriving with the decoded params/salt reproduces the tag |
| `testKnownVectorEncoding` | `(.i, t=1, m=8, p=1, out=4)`, salt `01 02 03 04`, tag `DE AD BE EF` → exactly `$argon2i$v=19$m=8,t=1,p=1$AQIDBA$3q2+7w` |
| `testDecodeRejectsMalformed` | rejects `"not-a-phc-string"`, unknown variant `argon2xyz`, `v=18`, and missing `p` field (4 inputs) |

### `ValidationTest` — `Tests/Argon2Tests/ValidationTest.swift` (7 tests)

| Test | Input | Expected |
| --- | --- | --- |
| `testRejectsMemoryBelowMinimum` | `t=1, m=4, p=1` | throws (m < 8p) |
| `testRejectsUnsupportedVersion` | `version: 18` | throws |
| `testRejectsOutputShorterThan4Bytes` | `outputLength: 2` | throws |
| `testRejectsZeroTime` | `timeCost: 0` | throws |
| `testRejectsZeroParallelism` | `parallelism: 0` | throws |
| `testAcceptsMinimalValid` | `t=1, m=8, p=1, out=4` | passes |
| `testDeriveKeyValidatesParams` | `Argon2.deriveKey` with `m=4, p=1` | throws (validation happens inside `deriveKey`) |

### `VaultTest` — `Tests/Argon2Tests/VaultTest.swift` (5 tests)

Shared fixture: `PasswordVault(params: .id, t=2, m=10240, p=1, out=32)`
(light parameters, `VaultTest.swift:6-9`).

| Test | Asserts |
| --- | --- |
| `testEncryptDecryptRoundTrip` | `decrypt(encrypt(x, pw), pw) == x` |
| `testRecordIsSelfDescribing` | a record opened by a vault with *different* params `(.id, t=1, m=8192, p=1, out=32)` decrypts correctly |
| `testWrongPasswordFailsAuthentication` | wrong password → `Argon2Error == .authenticationFailed` |
| `testTamperedCiphertextFailsAuthentication` | XOR `0xFF` into the last record byte → `.authenticationFailed` |
| `testTruncatedRecordRejected` | 3-byte record → `.malformedCiphertext` |

## Runner — `run_tests.sh`

Bash script (`set -euo pipefail`, `run_tests.sh:1-3`). Options:

| Option | Effect | Default |
| --- | --- | --- |
| `-c, --config <debug\|release>` | build configuration | `release` |
| `-f, --filter <substring>` | run only tests whose `swift test list` name matches the ERE `<substring>` (passed as `-XCTest <selectors>`) | all tests |
| `-l, --list` | print `swift test list` and exit | — |
| `-h, --help` | usage text | — |

Behavior: builds with
`swift build -c <config> --build-tests -Xswiftc -enable-testing`, locates
the first `.build/<config>/*.xctest` bundle, and runs it directly with
`xcrun xctest` (plus `-XCTest <selectors>` when filtering). Rationale stated
in the script comments: SwiftPM pipes the xctest stdout and drops buffered
chunks, truncating printed test output; invoking the bundle directly
inherits stdout. `-enable-testing` is required because the tests use
`@testable import Argon2` (`run_tests.sh:52-70`).

Plain `swift build` and `swift test` also work (`README.md:145-150`); both
were exercised during spec verification (build via `run_tests.sh`, which is
the same SwiftPM build).
