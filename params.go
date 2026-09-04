// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024 quip.network
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.

package hashsigs

import "math"

// Defaults mirror the TypeScript constructor signature:
//
//	constructor(hashFunction: HashFunction, hashLen?: number, chainLen: number = 16)
const (
	// DefaultHashLen is the `hashLen ?? 32` fallback of the TypeScript constructor.
	DefaultHashLen = 32
	// DefaultChainLen is the `chainLen: number = 16` default of the TypeScript constructor.
	DefaultChainLen = 16
)

// HashFunction defines the shape of hash functions that can be used.
//
// TypeScript: export interface HashFunction { (data: Uint8Array): Uint8Array }
//
// Implementations must not retain or mutate data, and must return a freshly
// allocated slice on every call.
type HashFunction func(data []byte) []byte

// KeyPair is the { publicKey, privateKey } object returned by
// WOTSPlus.generateKeyPair in the TypeScript original.
type KeyPair struct {
	// PublicKey is publicSeed || hash(publicKeySegments) and is
	// PublicKeySize bytes long.
	PublicKey []byte
	// PrivateKey is hash(privateSeed || publicSeed) and is HashLen bytes long.
	PrivateKey []byte
}

// WOTSPlus implements the WOTS+ one-time signature scheme.
//
// All exported fields are derived once by New and must be treated as
// read-only; they correspond to the `public readonly` members of the
// TypeScript class. A WOTSPlus value is safe for concurrent use provided the
// injected HashFunction is.
type WOTSPlus struct {
	hashFn HashFunction

	// HashLen: The WOTS+ `n` security parameter which is the size
	// of the hash function output in bytes.
	// This is 32 for keccak256 (256 / 8 = 32)
	HashLen int

	// MessageLen: The WOTS+ `m` parameter which is the size
	// of the message to be signed in bytes
	// (and also the size of our hash function)
	//
	// This is 32 for keccak256 (256 / 8 = 32)
	//
	// Note that this is not the message length itself as, like
	// with most signatures, we hash the message and then compute
	// the signature on the hash of the message.
	MessageLen int

	// ChainLen: The WOTS+ `w`(internitz) parameter.
	// This corresponds to the number of hash chains for each public
	// key segment and the base-w representation of the message
	// and checksum.
	//
	// A larger value means a smaller signature size but a longer
	// computation time.
	//
	// For XMSS (rfc8391) this value is limited to 4 or 16 because
	// they simplify the algorithm and offer the best trade-offs.
	ChainLen int

	// LgChainLen is lg(ChainLen) so we don't calculate it repeatedly.
	//
	// PARITY: this is a floating point value in the TypeScript original
	// (Math.log2) and is kept as float64 here so that every derived
	// computation rounds identically.
	LgChainLen float64

	// NumMessageChunks: the `len_1` parameter which is the number of
	// message chunks. This is
	// ceil(8n / lg(w)) -> ceil(8 * HashLen / lg(ChainLen))
	// or ceil(32*8 / lg(16)) -> 256 / 4 = 64
	// Python:  math.ceil(32*8 / math.log(16,2))
	NumMessageChunks int

	// NumChecksumChunks: the `len_2` parameter which is the number of
	// checksum chunks. This is
	// floor(lg(len_1 * (w - 1)) / lg(w)) + 1
	// -> floor(lg(NumMessageChunks * (ChainLen - 1)) / lg(ChainLen)) + 1
	// -> floor(lg(64 * 15) / lg(16)) + 1 = 3
	// Python: math.floor(math.log(64 * 15, 2) / math.log(16, 2)) + 1
	NumChecksumChunks int

	// NumSignatureChunks is NumMessageChunks + NumChecksumChunks.
	NumSignatureChunks int

	// SignatureSize: The size of the signature in bytes.
	SignatureSize int

	// PublicKeySize: The size of the public key in bytes.
	PublicKeySize int
}

// config holds the optional constructor arguments of the TypeScript class.
type config struct {
	hashLen  int
	chainLen int
}

// Option configures the optional `hashLen` and `chainLen` constructor
// arguments of the TypeScript class.
type Option func(*config)

// WithHashLen sets the WOTS+ `n` parameter (the TypeScript `hashLen?`
// argument). It defaults to DefaultHashLen.
func WithHashLen(hashLen int) Option {
	return func(c *config) { c.hashLen = hashLen }
}

// WithChainLen sets the WOTS+ `w` parameter (the TypeScript `chainLen`
// argument). It defaults to DefaultChainLen.
func WithChainLen(chainLen int) Option {
	return func(c *config) { c.chainLen = chainLen }
}

// New constructs a WOTSPlus instance, mirroring
// `new WOTSPlus(hashFunction, hashLen?, chainLen = 16)`.
//
// It returns an error instead of throwing; see errors.go for the message
// mapping.
func New(hashFunction HashFunction, opts ...Option) (*WOTSPlus, error) {
	if hashFunction == nil {
		return nil, ErrNilHashFunction
	}

	cfg := config{hashLen: DefaultHashLen, chainLen: DefaultChainLen}
	for _, opt := range opts {
		opt(&cfg)
	}

	w := &WOTSPlus{
		hashFn: hashFunction,
		// Initialize core parameters
		HashLen:    cfg.hashLen,
		MessageLen: cfg.hashLen,
		ChainLen:   cfg.chainLen,
		LgChainLen: math.Log2(float64(cfg.chainLen)),
	}

	// Compute derived parameters.
	//
	// PARITY: the TypeScript constructor performs these computations with
	// IEEE-754 doubles *before* validating, so they are reproduced with
	// float64 here rather than with integer arithmetic. They are kept in
	// float form until validateParameters has passed, because for rejected
	// parameters the intermediates can be NaN or +/-Inf (for example
	// chainLen = 0 yields lg(0) = -Inf) and converting those to int is
	// unspecified in Go. The values are never observable in that case: the
	// TypeScript constructor throws before returning the instance.
	numMessageChunks := math.Ceil(float64(8*w.HashLen) / w.LgChainLen)

	// Calculate numChecksumChunks
	checksumBits := math.Floor(
		math.Log2(numMessageChunks*float64(w.ChainLen-1))/
			math.Log2(float64(w.ChainLen)),
	) + 1

	// Validate parameters
	if err := w.validateParameters(); err != nil {
		return nil, err
	}

	w.NumMessageChunks = int(numMessageChunks)
	w.NumChecksumChunks = int(checksumBits)

	// Calculate remaining parameters
	w.NumSignatureChunks = w.NumMessageChunks + w.NumChecksumChunks
	w.SignatureSize = w.NumSignatureChunks * w.HashLen
	w.PublicKeySize = w.HashLen * 2

	return w, nil
}

// validateParameters mirrors the private validateParameters() method,
// preserving both the checks and their order.
func (w *WOTSPlus) validateParameters() error {
	// Ensure chainLen is a power of 2
	//
	// PARITY: as in TypeScript, chainLen == 0 passes this test
	// (0 & -1 == 0) and is only rejected by the XMSS check below. The
	// check order is preserved so the reported error matches.
	if w.ChainLen&(w.ChainLen-1) != 0 {
		return ErrChainLenNotPowerOfTwo
	}

	// Ensure hashLen is positive
	if w.HashLen <= 0 {
		return ErrHashLenNotPositive
	}

	// Additional validations as needed
	if w.ChainLen != 16 && w.ChainLen != 4 {
		return ErrChainLenUnsupported
	}

	return nil
}
