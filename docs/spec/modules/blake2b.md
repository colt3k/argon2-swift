# BLAKE2b — `Blake2b`

Purpose: a stateful, incremental BLAKE2b digest plus the extended-length
`blake2bHash` used by Argon2 to derive the key from a 1024-byte block.
Ported from `golang.org/x/crypto/blake2b` and
`golang.org/x/crypto/argon2/blake2b.go` (`Blake2b.swift:1-5,177-179`).

Source: `Sources/Argon2/Blake2b.swift`. Visibility: internal (`final class
Blake2b`, no `public`).

## API

| Symbol | Signature | Parameters | Returns | Source |
| --- | --- | --- | --- | --- |
| `init(size:)` | `init(size: Int)` | digest length in bytes (only `4` and `64` are used in this codebase; any value 1...64 works) | new digest | `Blake2b.swift:38-43` |
| `reset` | `func reset()` | — | re-initializes state (`h = iv`, `h[0] ^= size \| (1 << 16) \| (1 << 24)`, `offset = 0`, counters 0) | `Blake2b.swift:45-51` |
| `write` | `func write(_ p: [UInt8])` | input bytes, buffered in 128-byte blocks; a trailing full block is held back (Go's `Compress`/`sum` semantics — the last block is compressed at finalize, never inline) | — | `Blake2b.swift:53-85` |
| `sum` | `func sum() -> [UInt8]` | — | `size` bytes, little-endian, **without mutating running state** (state is copied before finalizing, matching Go) | `Blake2b.swift:89-116` |
| `hashBlocks` | `static func hashBlocks(_ h: inout [UInt64], _ c0: inout UInt64, _ c1: inout UInt64, flag: UInt64, blocks: [UInt8])` | `flag` 0 for intermediate blocks, `0xFFFFFFFFFFFFFFFF` for the final block; `c0`/`c1` are the running byte counters, updated in place | compresses each 128-byte block: per block `c0 &+= 128` (carry into `c1`), 12 rounds of the `G` mixing function over the 12×16 `precomputed` sigma tables, then `h[i] ^= v[i] ^ v[i+8]` | `Blake2b.swift:121-162` |
| `g` | `static func g(_ v: inout [UInt64], _ a: Int, _ b: Int, _ c: Int, _ d: Int, _ x: UInt64, _ y: UInt64)` | — | the BLAKE2b column/diagonal mixing step with wrapping arithmetic and `rotl64` by 32/40/48/1 | `Blake2b.swift:165-175` |
| `blake2bHash(outLen:_:)` | `static func blake2bHash(outLen: Int, _ input: [UInt8]) -> [UInt8]` | `outLen`: any value; `input`: hashed after a 4-byte LE length prefix | `outLen` bytes | `Blake2b.swift:180-226` |

## Constants (literal values)

| Constant | Value | Source |
| --- | --- | --- |
| `blockSize` | `128` | `Blake2b.swift:8` |
| `size512` | `64` | `Blake2b.swift:9` |
| `iv[0..7]` | `0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1, 0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179` | `Blake2b.swift:11-14` |
| `precomputed` | 12 × 16 sigma permutation table (first row `[0, 2, 4, 6, 1, 3, 5, 7, 8, 10, 12, 14, 9, 11, 13, 15]`, rows repeat with period 10) | `Blake2b.swift:16-29` |
| Parameter block | `h[0] ^= size \| (1 << 16) \| (1 << 24)` — key length is 0 (no keyed BLAKE2b); no fanout/depth flag bits set | `Blake2b.swift:47` |

## Internal Behavior

### `write` buffering (`Blake2b.swift:53-85`)

- If a partial block is pending and the new input fits, append and stop.
- Otherwise top up the partial block, compress it, and continue with the
  remainder.
- For inputs longer than one block, compress `floor((n) / 128) * 128` bytes
  but **hold back the final 128-byte block** when the remainder is exactly a
  multiple of 128 (`if p.count == nn { nn -= blockSize }`,
  `Blake2b.swift:72-75`). The held-back block is compressed only during
  `sum()`.

### `sum` (`Blake2b.swift:89-116`)

Copies the pending partial block, copies `h`, `c0`, `c1`, decrements the
counter by `blockSize - offset` (with carry), compresses the final block with
`flag = 0xFFFFFFFFFFFFFFFF`, and emits the first `size` bytes of the 64-byte
LE-encoded state. The instance's state is left untouched, so `sum` can be
called repeatedly (this is what `blake2bHash` relies on for the 32-byte
chaining).

### `blake2bHash` — extended length (`Blake2b.swift:180-226`)

This is the BLAKE2X-style construction Argon2 uses. It hashes
`LE32(outLen) || input`:

1. `outLen < 64`: single digest with `Blake2b(size: outLen)`.
2. `outLen == 64`: single digest with `Blake2b(size: 64)`.
3. `outLen > 64`: digest with `Blake2b(size: 64)`; the first 32 output bytes
   are the first 32 bytes of that digest. Then chain: `out[32..64] =
   first 32 bytes of BLAKE2b-64(prev 32-byte buffer)`, repeated while
   `total - outOffset > 64`. The final tail (if `total % 64 > 0`) is a
   `Blake2b(size: total - 32 * r)` digest where
   `r = ((total + 31) / 32) - 2`, over the last chained buffer; its first
   `total - outOffset` bytes finish the output (`Blake2b.swift:205-224`).

In the Argon2 codebase this function is called only with `outLen: 1024`
(`Argon2Engine.initBlocks`) and with `outLen: keyLen`
(`Argon2Engine.extractKey`); the `outLen ≤ 64` paths
(`Blake2b.swift:183-198`) exist for completeness.

## Dependencies

Calls: `leUint64`, `rotl64`, `putLE32` (`ByteHelpers.swift`).
Called by: `Argon2Engine` (`initHash`, `initBlocks`, `extractKey`); nothing
else in the tree.

## Data

Pure in-memory; no I/O.
