# Engine — `Argon2Engine`

Purpose: the Argon2 core algorithm — a byte-for-byte port of
`golang.org/x/crypto/argon2` (`Argon2Engine.swift:1-7`). Supports all three
variants plus the optional secret key (`K`) and associated data (`X`).

Source: `Sources/Argon2/Argon2Engine.swift`. Visibility: internal (`enum
Argon2Engine`, no `public`).

## Public (module) API

| Symbol | Signature | Parameters | Returns | Source |
| --- | --- | --- | --- | --- |
| `derive` | `static func derive(password: [UInt8], salt: [UInt8], secret: [UInt8], ad: [UInt8], time: UInt32, memory: UInt32, threads: UInt32, keyLen: UInt32, mode: Int) -> [UInt8]` | `mode`: one of `argon2d` (0), `argon2i` (1), `argon2id` (2). No validation performed here — callers validate first | `keyLen` bytes | `Argon2Engine.swift:19-34` |
| `h0Digest` | `static func h0Digest(password: [UInt8], salt: [UInt8], secret: [UInt8], ad: [UInt8], time: UInt32, memory: UInt32, threads: UInt32, keyLen: UInt32, mode: Int) -> [UInt8]` | same | the 64-byte pre-hashing digest `H_0` (RFC 9106 Figure 1) | `Argon2Engine.swift:37-44` |

Internal helpers: `initHash`, `initBlocks`, `processBlocks`,
`processSegment`, `extractKey`, `indexAlpha`, `phi`,
`processBlockStandalone`, `processBlockXORFlat`, `applyBlamka`,
`blamkaGeneric`, `blamkaMul` (all static, listed with their locations below).

## Constants (literal values)

| Constant | Value | Source |
| --- | --- | --- |
| `version` | `0x13` | `Argon2Engine.swift:10` |
| `blockLength` | `128` (words; 128 × 8 = 1024-byte block) | `Argon2Engine.swift:11` |
| `syncPoints` | `4` | `Argon2Engine.swift:12` |
| `argon2d` | `0` | `Argon2Engine.swift:14` |
| `argon2i` | `1` | `Argon2Engine.swift:15` |
| `argon2id` | `2` | `Argon2Engine.swift:16` |
| BLAMKA rotation constants | `32, 40, 48, 1` per round pair | `blamkaGeneric`, `Argon2Engine.swift:293-401` |
| BLAMKA multiplier | `2` (in `blamkaMul`) | `Argon2Engine.swift:412-414` |

## Internal Behavior

### `derive` (`Argon2Engine.swift:19-34`)

1. `initHash` computes `H_0`.
2. Memory adjustment (wrapping arithmetic):
   `mem = (mem / (4 &* threads)) &* (4 &* threads)` — rounds `m` down to a
   multiple of `4 * threads`; then `if mem < 2 &* 4 &* threads { mem = 2 &* 4
   &* threads }` — i.e. `mem` is raised to the minimum `8 * threads`
   (`Argon2Engine.swift:25-30`).
3. `initBlocks` fills memory, `processBlocks` runs the main loop,
   `extractKey` derives the output.

### `initHash` (`Argon2Engine.swift:48-79`)

`H_0 = BLAKE2b-512` over the concatenation:

```
LE32(threads) || LE32(keyLen) || LE32(memory) || LE32(time)
|| LE32(0x13) || LE32(mode)
|| LE32(len(password)) || password
|| LE32(len(salt))     || salt
|| LE32(len(secret))   || secret
|| LE32(len(ad))       || ad
```

The result is stored in a 72-byte buffer: the 64-byte digest followed by 8
zero bytes. Those 8 bytes are reused in `initBlocks` as the counter/lane
fields. `h0Digest` returns only the first 64 bytes.

### `initBlocks` (`Argon2Engine.swift:82-100`)

Memory `B` is a flat `[UInt64]` of `memory * 128` words. For each lane
`0..<threads`, let `j = lane * (memory / threads)`:

- `h0[68] = lane` (LE32 at offset 64+4), `h0[64] = 0` → `B[j*128 ..< (j+1)*128]
  = LE64 words of blake2bHash(outLen: 1024, h0)`.
- `h0[64] = 1` → `B[(j+1)*128 ..< (j+2)*128]` likewise.

So the first two blocks of every lane come from a 1024-byte extended-length
BLAKE2b over `H_0` with counter 0 then 1.

### `processBlocks` / `processSegment` (`Argon2Engine.swift:104-167`)

Loop order: pass `n` in `0..<time`, then slice `0..<4` (syncPoints), then
lane `0..<threads`, calling `processSegment` for each.

Per segment:

- `lanes = memory / threads` (blocks per lane), `segments = lanes / 4`.
- Data-independence switch: `useDataIndependent = (mode == argon2i) ||
  (mode == argon2id && n == 0 && slice < 2)` (`Argon2Engine.swift:125`) —
  argon2id uses data-independent addressing only for the first half of pass 0.
- When data-independent, the address block's header words are set once:
  `inBlock[0]=n, inBlock[1]=lane, inBlock[2]=slice, inBlock[3]=memory,
  inBlock[4]=time, inBlock[5]=mode` (`Argon2Engine.swift:126-133`).
- First block of the first segment (`n == 0 && slice == 0`): `index` starts at
  `2` (blocks 0 and 1 were already filled by `initBlocks`); for argon2i and
  argon2id, two `processBlockStandalone` rounds run first, each after
  `inBlock[6] &+= 1`, producing address words for the first 128 blocks
  (`Argon2Engine.swift:135-142`).
- For each subsequent block, `index` runs `index ..< segments`:
  - `prev = offset - 1`, with wrap to `offset - 1 + lanes` when
    `index == 0 && slice == 0` (`Argon2Engine.swift:146-149`).
  - Data-independent mode: every 128 blocks (`index % blockLength == 0`) two
    `processBlockStandalone` rounds refill the 128 address words after
    `inBlock[6] &+= 1`; the address random word is
    `addresses[index % blockLength]` (`Argon2Engine.swift:150-156`).
  - Data-dependent mode: `random = B[prev * blockLength]` — the first word of
    the previous block (`Argon2Engine.swift:157-159`).
  - `newOffset = indexAlpha(random, ...)` then
    `processBlockXORFlat(&B, offset, prev, newOffset)`
    (`Argon2Engine.swift:160-163`).

### `indexAlpha` / `phi` (`Argon2Engine.swift:187-216`)

Reference lane: `refLane = (rand >> 32) % threads`, forced to the current
`lane` when `n == 0 && slice == 0`.

Bounds: `m = 3 * segments`, `s = ((slice + 1) % 4) * segments`; if
`lane == refLane` then `m += index`. For pass 0: `m = slice * segments`,
`s = 0`, and `m += index` when `slice == 0 || lane == refLane`. Finally,
`m -= 1` when `index == 0 || lane == refLane`.

`phi`: `p = rand & 0xFFFFFFFF; p = (p &* p) >> 32; p = (p &* m) >> 32;`
returns `lane * lanes + ((s &+ m &- (p &+ 1)) % lanes)`.

### `extractKey` (`Argon2Engine.swift:169-183`)

The last block of memory is the XOR fold: for `lane in 0..<(threads - 1)`,
`B[finalBlock + i] ^= B[lastOfLane + i]` where `lastOfLane = lane * lanes +
lanes - 1`. The folded 1024-byte block (LE64-encoded) is hashed with
`Blake2b.blake2bHash(outLen: keyLen, block)` to produce the tag.

### BLAMKA (`Argon2Engine.swift:218-414`)

- `processBlockStandalone(out, in1, in2)`: `out = in1 ^ in2 ^ G'(in1 ^ in2)`
  on standalone 128-word blocks (data-independent address generation).
- `processBlockXORFlat(B, out, in1, in2)`: the accumulate step on flat
  memory, `B[out] ^= B[in1] ^ B[in2] ^ G'(B[in1] ^ B[in2])`.
- `applyBlamka(t)`: eight consecutive 16-word column groups
  (`base in stride(0, 128, 16)`), then eight strided 16-word row groups
  (`i in stride(0, 128/8, by: 2)`, each group taking words `i, i+1` from each
  of the eight 16-word columns, offsets `0, 16, 32, ..., 112`).
- `blamkaGeneric(t)`: the `G'` mixing function over 16 words `v00...v15`,
  ported verbatim from Go's `blamka_generic.go`. Each of the 16 rounds is
  `vX = vX &+ vY &+ blamkaMul(vX, vY)` followed by
  `vZ ^= vX; vZ = rotl64(vZ, 32)` (or 40 / 48 / 1), matching the column/row
  pairing in the reference.
- `blamkaMul(a, b)`: `2 &* UInt64(UInt32(truncatingIfNeeded: a)) &*
  UInt64(UInt32(truncatingIfNeeded: b))` — i.e. `2 * (a mod 2^32) * (b mod
  2^32)` wrapping (`Argon2Engine.swift:409-414`).

## Dependencies

Calls: `Blake2b` (constructor, `write`, `sum`, `reset`, `blake2bHash`),
`putLE32`, `putLE64`, `leUint64`, `rotl64`, `appendLE32`
(`ByteHelpers.swift`).
Called by: `Argon2.deriveKey`, `PasswordVault.deriveKey`, and (for `h0Digest`)
`RFC9106Test`.

## Data

Pure in-memory computation. Memory footprint per derivation:
`memory * 1024` bytes plus per-segment scratch (`addresses`, `inBlock`,
`zero` — 3 × 128 words each, allocated per `processSegment` call).
