# hashsigs-go

Hash-based signatures implementation in Go, featuring WOTS+ (Winternitz One-Time Signature Plus).

This is a line-by-line port of [hashsigs-ts](https://github.com/quipnetwork/hashsigs-ts).
It is **byte-for-byte functionally equivalent**: the same seeds produce the same keys,
the same signatures and the same verification results, and every error carries the exact
message text the TypeScript implementation throws. Equivalence is not asserted, it is
[proven by a differential harness](#parity-with-the-typescript-implementation) that runs
both implementations over the same inputs and diffs the output.

## License

SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2024 quip.network

This program is free software: you can redistribute it and/or modify it under the terms of
the GNU Affero General Public License as published by the Free Software Foundation, either
version 3 of the License, or (at your option) any later version.

## Installation

```bash
go get github.com/quipnetwork/hashsigs-go
```

## Usage

```go
package main

import (
	"crypto/rand"
	"fmt"
	"log"

	hashsigs "github.com/quipnetwork/hashsigs-go"
)

func main() {
	wots, err := hashsigs.New(hashsigs.Keccak256)
	if err != nil {
		log.Fatal(err)
	}

	privateSeed := make([]byte, wots.HashLen)
	publicSeed := make([]byte, wots.HashLen)
	rand.Read(privateSeed)
	rand.Read(publicSeed)

	keyPair, err := wots.GenerateKeyPair(privateSeed, publicSeed)
	if err != nil {
		log.Fatal(err)
	}

	// WOTS+ signs a digest, not a message: it must be exactly MessageLen bytes.
	messageHash := hashsigs.Keccak256([]byte("Hello World"))

	// A WOTS+ private key must sign AT MOST ONE message. Signing twice leaks
	// enough of the key to forge signatures.
	signature, err := wots.Sign(keyPair.PrivateKey, publicSeed, messageHash)
	if err != nil {
		log.Fatal(err)
	}

	isValid, err := wots.Verify(keyPair.PublicKey, messageHash, signature)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("valid:", isValid)
}
```

## API

| Go | TypeScript |
| --- | --- |
| `New(hashFn, ...Option) (*WOTSPlus, error)` | `new WOTSPlus(hashFunction, hashLen?, chainLen?)` |
| `WithHashLen(int)` / `WithChainLen(int)` | constructor arguments 2 and 3 |
| `(*WOTSPlus).GenerateKeyPair(privateSeed, publicSeed) (*KeyPair, error)` | `generateKeyPair` |
| `(*WOTSPlus).Sign(privateKey, publicSeed, message) ([][]byte, error)` | `sign` |
| `(*WOTSPlus).Verify(publicKey, message, signature) (bool, error)` | `verify` |
| `(*WOTSPlus).VerifyWithRandomizationElements(publicKeyHash, message, signature, elements) (bool, error)` | `verifyWithRandomizationElements` |
| `(*WOTSPlus).GenerateRandomizationElements(publicSeed) [][]byte` | `generateRandomizationElements` |
| `HashFunction func([]byte) []byte` | `type HashFunction = (data: Uint8Array) => Uint8Array` |
| `Keccak256` | `keccak_256` from `@noble/hashes` |
| sentinel errors in `errors.go` | `throw new Error(...)` |

Structural differences, and only these:

- **Errors instead of exceptions.** Everything that `throw`s in TypeScript returns an
  `error` in Go. The message text is identical, so `err.Error()` equals the JavaScript
  `Error.message`. Errors are also matchable with `errors.Is`, e.g.
  `errors.Is(err, hashsigs.ErrInvalidMessageLen)`.
- **Constructor returns an error** rather than throwing, so `New` has two return values.
- **Derived parameters are exported read-only fields** (`HashLen`, `ChainLen`,
  `NumSignatureChunks`, `SignatureSize`, `PublicKeySize`, ...) matching the TypeScript
  `public readonly` properties. `LgChainLen` is a `float64` because the original computes
  it with `Math.log2` and never rounds it.
- **No barrel file.** The TypeScript `src/index.ts` re-export has no Go equivalent; the
  package root *is* the public API.

## Parity with the TypeScript implementation

`parity/compare.sh` runs the original TypeScript source and this Go port over an identical
corpus and diffs the results:

```bash
HASHSIGS_TS_REPO=/path/to/hashsigs-ts ./parity/compare.sh
```

The corpus is 140 cases: 100 pseudorandom seed round trips (key pair, randomization
elements, signature, verification, tamper check), 8 edge-case messages (all zero, all
0xff, ramps, alternating nibbles), 5 degenerate seeds (empty, 1 byte, 31, 33, 96 bytes),
3 `ChainLen=4` cases, 12 constructor parameter sets and 12 validation failures. Both sides
emit the same JSON document; the harness requires `diff` to report no differences.

The TypeScript side imports `src/wotsplus.ts` **directly** (via Node's native type
stripping), so the comparison is against the real source and not a transcription of it.

The last verified run produced two 1,361,715-byte documents with identical SHA-256
`f1f0dd47930fe7287a9100a01840d70894fdfeecf7e31096fbdf3d65dda2e9ec`. That output is
committed as `testdata/parity_ts.json`, so `go test ./...` re-checks parity against the
frozen golden file with no Node.js installed. When `HASHSIGS_TS_REPO` is set, the test
suite additionally re-runs the TypeScript implementation live.

The upstream test vectors in `test/test_vectors/wotsplus_keccak256.json` are copied
verbatim (SHA-256 `5e960bc3b4e6153cf42ad7c70424d9361a55f19f694eef7cb2cb7f16f7d2b041`) and
`vectors_test.go` both replays them and regenerates every field from the seeds.

## Preserved quirks

The port reproduces the original's behaviour, including behaviour that is arguably wrong.
Each of these is marked with a `PARITY:` comment at the site in the code.

1. `toBaseW` is hardcoded to base 16 (nibble extraction) and ignores `ChainLen`. With
   `ChainLen=4` it therefore emits values up to 15 into a chain of length 4, and signing
   most messages fails with "steps + index must be less than ChainLen".
2. `chain` reads `randomizationElements[i+index]`, so only elements 1..`ChainLen`-1 of the
   67 generated elements are ever used.
3. `LgChainLen` stays a float (`Math.log2(16)` = 4.0) and is used in float arithmetic.
4. Seed lengths are not validated by `GenerateKeyPair`; a bad seed length surfaces later as
   a public key length error at verification time.
5. `ChainLen=0` passes the power-of-two test (`0 & -1 == 0`) and is rejected by the
   "either 4 or 16" test, so it reports the second message, not the first.
6. Derived parameters are computed before validation runs.
7. `chain` with `steps == 0` returns its input unchanged.
8. The checksum shift uses signed 32-bit semantics.

## Registered divergences

Everything the Go port does differently from the TypeScript original, and why. No
difference outside this table is intentional.

| # | Divergence | Why it is unavoidable or preferable | Observable impact |
|---|---|---|---|
| 1 | Failures are returned as `error` values instead of thrown exceptions. | Go has no exceptions. | Callers check a returned `error` instead of `try`/`catch`. The message text of every failure the TypeScript library raises itself is preserved verbatim. |
| 2 | `New` returns `(*WOTSPlus, error)`; the TypeScript constructor throws. | Same as 1, applied to construction. | Invalid parameters are rejected at the same point with the same message; the caller receives it as a value. |
| 3 | Failures raised by the JavaScript *engine* rather than by the library — an out-of-range `Uint8Array.set`, indexing a missing randomization element — become `ErrSegmentOffsetOutOfBounds` and `ErrMissingRandomizationElement`. | Those messages are produced by V8, not by `wotsplus.ts`, so there is no library text to preserve. | The same inputs are rejected at the same point; the message text differs, because in the original it was never the library's text. |
| 4 | Optional constructor arguments become functional options (`WithHashLen`, `WithChainLen`). | Go has no optional parameters. | Construction syntax differs; defaults and validation order are identical. |
| 5 | `src/index.ts` (a re-export barrel) has no counterpart. | The Go package root is the public surface. | Import path differs; the exported set is the same. |
| 6 | Values returned by `Sign` and `GenerateKeyPair` are independent copies. In the original, `chain` with zero steps returns its input, so two returned chunks can alias one buffer. | Aliasing that is invisible in the original becomes a mutation hazard once callers hold the slices. Copying cannot change any produced byte. | Mutating one returned chunk no longer affects another. Asserted by `params_test.go`. |
| 7 | Derived parameters are computed in `float64` and converted to `int` only after validation succeeds. | Go leaves float-to-int conversion undefined for NaN and out-of-range values; JavaScript coerces. Converting late keeps the undefined case unreachable. | None. Every configuration the original rejects is rejected here, with the same message, before any conversion happens. |
| 8 | `@noble/hashes` → `golang.org/x/crypto/sha3` (`NewLegacyKeccak256`). | The original hashes with original Keccak, not FIPS-202 SHA-3; the two differ by one padding byte and share a name. | None — verified byte-identical over the whole parity corpus, which is the only reason this row is not a defect. |
| 9 | npm + tsup + vitest → Go modules + `go test`. | Target toolchain. | No build step; the module is consumed by import path. `go.sum` replaces `package-lock.json` as the reproducibility pin. |

## Limitations

- **Platforms executed:** darwin/arm64 (Apple silicon) only — build, full race-enabled
  suite, fuzzing, cold-module-cache build, and the live differential against Node.
- **Platforms not executed:** linux/amd64, linux/arm64 and windows/amd64. They are covered
  by `.github/workflows/ci.yml` but that matrix has not been run here. The code contains no
  cgo, no assembly and no build constraints, so the platform surface is narrow — but
  narrow is not verified.
- **The parity corpus is a sample, not a proof.** 140 cases chosen to be adversarial; it
  does not enumerate the message space.
- **Fuzzing was time-boxed** (roughly 280k executions across two targets, no crashers). It
  is a smoke test, not a bound.
- **The TypeScript side is executed through Node's native type stripping** (Node >= 22.6),
  reading `src/wotsplus.ts` directly. A `tsc`/`tsup`-compiled bundle was not separately
  differentially tested; it is the same source, but that equivalence is reasoning, not
  measurement.
- **Upstream fixture defect, preserved and asserted, not fixed:** in
  `test/test_vectors/wotsplus_keccak256.json` the `publicKeySegments` field is a verbatim
  duplicate of `randomizationElements` in all five vectors. The TypeScript suite never
  reads that field. `vectors_test.go` regenerates the true segments from the seeds and
  asserts the duplication explicitly, so a corrected fixture will fail loudly instead of
  passing quietly.

## Development

```bash
make test       # go test -race ./...
make cover      # coverage report, fails below 80%
make lint       # gofmt check + go vet
make fuzz       # 30s of fuzzing per target
make bench      # benchmarks
make parity     # differential comparison against the TypeScript source
make check      # lint + test + cover
```

### Code Coverage

The project maintains the same minimum threshold as the TypeScript original: **80%**
statements. `make cover` writes `coverage.out` plus an HTML report at `coverage.html` and
exits non-zero below the threshold.

## Repository

- GitHub: [https://github.com/quipnetwork/hashsigs-go](https://github.com/quipnetwork/hashsigs-go)
- Upstream TypeScript: [https://github.com/quipnetwork/hashsigs-ts](https://github.com/quipnetwork/hashsigs-ts)

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

Please ensure `make check` passes before submitting a PR. Changes that alter observable
behaviour must keep parity with the TypeScript implementation, or explicitly update
`testdata/parity_ts.json` with a justification.
