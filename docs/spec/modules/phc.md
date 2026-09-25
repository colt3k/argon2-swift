# PHC string — `Argon2PHC`, `PHCBase64`

Purpose: encode/decode Argon2 records in the PHC string format
`$argon2id$v=19$m=65536,t=3,p=4$<salt-b64>$<tag-b64>`, where salt and tag use
standard base64 **without padding** (`PHC.swift:1-11`).

Sources: `Sources/Argon2/PHC.swift`.

## Public API — `Argon2PHC`

`public struct Argon2PHC: Equatable, Sendable` (`PHC.swift:12-13`).

| Member | Kind | Signature / values | Source |
| --- | --- | --- | --- |
| `params` | `public let` | `Argon2Params` | `PHC.swift:13` |
| `salt` | `public let` | `Data` | `PHC.swift:14` |
| `tag` | `public let` | `Data` | `PHC.swift:15` |
| `init(params:salt:tag:)` | public | `init(params: Argon2Params, salt: Data, tag: Data)` — no validation at construction | `PHC.swift:17-21` |
| `encode()` | public | `func encode() -> String` | `PHC.swift:24-34` |
| `decode(_:)` | public static | `static func decode(_ string: String) throws -> Argon2PHC` | `PHC.swift:38-83` |

### `encode()` — complete output grammar

```
$<variant>$v=<version>$m=<memoryCostKilobytes>,t=<timeCost>,p=<parallelism>$<saltB64>$<tagB64>
```

- `<variant>`: exactly one of `argon2d` (`.d`), `argon2i` (`.i`),
  `argon2id` (`.id`) — full list, `PHC.swift:26-30`.
- `<version>`: decimal rendering of `params.version` (default `0x13` → `19`).
- Cost fields always in the fixed order `m`, `t`, `p`, all decimal.
- `<saltB64>` / `<tagB64>`: `PHCBase64.encodeNoPad` (base64 with `=`
  stripped).

Example (deterministic, from `PHCTest.testKnownVectorEncoding`): params
`(.i, t=1, m=8, p=1, out=4)`, salt `01 02 03 04`, tag `DE AD BE EF` encode
to `$argon2i$v=19$m=8,t=1,p=1$AQIDBA$3q2+7w`.

### `decode(_:)` — parsing rules and complete rejection list

1. Split on `"$"`; require **exactly 6 parts** with `parts[0]` empty
   (i.e. the string must start with `$`). Else `malformedPHC("expected 6
   '$'-separated fields")` (`PHC.swift:39-42`).
2. `parts[1]` must be exactly one of `argon2d`, `argon2i`, `argon2id`; else
   `malformedPHC("unknown variant '<parts[1]>'")` (`PHC.swift:44-50`).
3. `parts[2]` must have prefix `v=` followed by a parseable `UInt32`; else
   `malformedPHC("bad version field '<parts[2]>'")`. (Any version parses
   here; `validate()` later rejects everything except `0x13`.)
   (`PHC.swift:52-54`)
4. `parts[3]` is split on `","`; every field must be `k=v` with
   `k ∈ {m, t, p}` (decimal `UInt32`). Else:
   - not two `k=v` halves → `malformedPHC("bad cost field '<field>'")`
   - unknown key → `malformedPHC("unknown cost field '<kv[0]>'")`
   - non-numeric value → `UInt32` init returns nil → the field is simply not
     assigned, and step 5 fails with `malformedPHC("missing m/t/p cost
     fields")`.
   Rejected order is accepted (e.g. `p=1,m=8,t=2` parses); duplicate keys
   take the **last** occurrence (loop assigns in order,
   `PHC.swift:59-70`).
5. All three of `m`, `t`, `p` must be present, else
   `malformedPHC("missing m/t/p cost fields")` (`PHC.swift:71-73`).
6. `parts[4]` / `parts[5]` are decoded as base64 without padding
   (`PHCBase64.decodeNoPad`), which can throw `malformedPHC("invalid base64
   length")` or `malformedPHC("invalid base64")`.
7. `outputLength` is recovered as `tag.count` (`PHC.swift:79`).
8. `params.validate()` runs on the reconstructed params, so `decode` also
   throws `Argon2Error.invalidParameters` for: version ≠ `0x13`
   (e.g. `v=18`), `t < 1`, `p < 1`, tag < 4 bytes, `m < 8 * p`
   (`PHC.swift:81`, see [facade.md](facade.md)).

## Internal API — `PHCBase64`

`enum PHCBase64` (internal, `PHC.swift:87-104`):

| Symbol | Behavior | Source |
| --- | --- | --- |
| `encodeNoPad(_ data: Data) -> String` | `data.base64EncodedString()` with all `=` removed | `PHC.swift:88-90` |
| `decodeNoPad(_ s: String) throws -> Data` | Appends padding so `count % 4 ∈ {0, 2, 3}` (`"=="` for 2, `"="` for 3); `count % 4 == 1` → `malformedPHC("invalid base64 length")`; then `Data(base64Encoded:)`, nil → `malformedPHC("invalid base64")` | `PHC.swift:92-104` |

## Internal Behavior

`encode` and `decode` are exact inverses for valid PHC strings (round-trip
covered by `PHCTest.testEncodeDecodeRoundTrip`). `decode` performs no
cryptographic check that `tag` actually derives from `params` + `salt` —
that is the caller's job via `Argon2.verify`.

## Dependencies

Calls: `PHCBase64`, `Argon2Params` (init + `validate()`), `Argon2Variant`,
`Argon2Error`.
Called by: package users (no in-tree callers besides tests).

## Data

Pure string parsing; no I/O.
