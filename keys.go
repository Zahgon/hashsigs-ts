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

import (
	"bytes"
	"fmt"
)

// GenerateKeyPair generates a WOTS+ key pair from a private and a public seed.
//
// PARITY: as in the TypeScript original, the seed lengths are not validated.
func (w *WOTSPlus) GenerateKeyPair(privateSeed, publicSeed []byte) (*KeyPair, error) {
	combinedSeed := concat(privateSeed, publicSeed)
	privateKey := w.hash(combinedSeed)

	randomizationElements := w.GenerateRandomizationElements(publicSeed)
	functionKey := randomizationElements[0]

	publicKeySegments := make([]byte, w.NumSignatureChunks*w.HashLen)

	for i := 0; i < w.NumSignatureChunks; i++ {
		secretKeySegment := w.hash(concat(functionKey, w.prf(privateKey, i+1)))
		segment, err := w.chain(secretKeySegment, randomizationElements, 0, w.ChainLen-1)
		if err != nil {
			return nil, err
		}

		// Copy segment to the correct position in publicKeySegments
		copy(publicKeySegments[i*w.HashLen:], segment)
	}

	publicKeyHash := w.hash(publicKeySegments)

	// Combine publicSeed and publicKeyHash to form the complete public key
	publicKey := concat(publicSeed, publicKeyHash)

	return &KeyPair{PublicKey: publicKey, PrivateKey: privateKey}, nil
}

// Sign signs a message with a WOTS+ private key.
//
// The message must already be a hash of MessageLen bytes. The returned
// signature holds NumSignatureChunks chunks of HashLen bytes.
//
// WOTS+ is a one-time signature scheme: never sign two messages with the same
// private key.
func (w *WOTSPlus) Sign(
	privateKey []byte,
	publicSeed []byte,
	message []byte,
) ([][]byte, error) {
	if len(privateKey) != w.HashLen {
		return nil, &wrappedError{
			msg: fmt.Sprintf("private key length must be %d bytes", w.HashLen),
			err: ErrInvalidPrivateKeyLen,
		}
	}
	if len(message) != w.MessageLen {
		return nil, &wrappedError{
			msg: fmt.Sprintf("message length must be %d bytes", w.MessageLen),
			err: ErrInvalidMessageLen,
		}
	}

	randomizationElements := w.GenerateRandomizationElements(publicSeed)
	functionKey := randomizationElements[0]

	signature := make([][]byte, w.NumSignatureChunks)
	chainSegments := w.computeMessageHashChainIndexes(message)

	for i := 0; i < len(chainSegments); i++ {
		chainIdx := chainSegments[i]
		secretKeySegment := w.hash(concat(functionKey, w.prf(privateKey, i+1)))
		segment, err := w.chain(secretKeySegment, randomizationElements, 0, chainIdx)
		if err != nil {
			return nil, err
		}
		// chain returns its input unchanged when chainIdx == 0; clone so a
		// caller mutating the signature cannot reach shared state.
		signature[i] = clone(segment)
	}

	return signature, nil
}

// Verify verifies a WOTS+ signature.
//  1. The first part of the publicKey is a public seed used to regenerate the
//     randomization elements. (`r` from the paper).
//  2. The second part of the publicKey is the hash of the NumMessageChunks +
//     NumChecksumChunks public key segments.
//  3. Convert the Message to "base-w" representation (or base of ChainLen
//     representation).
//  4. Compute and add the checksum.
//  5. Run the chain function on each segment to reproduce each public key
//     segment.
//  6. Hash all public key segments together to recreate the original public
//     key.
func (w *WOTSPlus) Verify(
	publicKey []byte,
	message []byte,
	signature [][]byte,
) (bool, error) {
	if len(publicKey) != w.PublicKeySize {
		return false, &wrappedError{
			msg: fmt.Sprintf("public key length must be %d bytes", w.PublicKeySize),
			err: ErrInvalidPublicKeyLen,
		}
	}

	// Uint8Array.prototype.slice copies; clone to match.
	publicSeed := clone(publicKey[0:w.HashLen])
	publicKeyHash := clone(publicKey[w.HashLen:w.PublicKeySize])

	randomizationElements := w.GenerateRandomizationElements(publicSeed)

	return w.VerifyWithRandomizationElements(
		publicKeyHash,
		message,
		signature,
		randomizationElements,
	)
}

// VerifyWithRandomizationElements verifies a WOTS+ signature against a public
// key hash using randomization elements that the caller already derived from
// the public seed (see GenerateRandomizationElements). See Verify for the
// step by step description.
func (w *WOTSPlus) VerifyWithRandomizationElements(
	publicKeyHash []byte,
	message []byte,
	signature [][]byte,
	randomizationElements [][]byte,
) (bool, error) {
	if len(publicKeyHash) != w.HashLen {
		return false, &wrappedError{
			msg: fmt.Sprintf("public key hash length must be %d bytes", w.HashLen),
			err: ErrInvalidPublicKeyHashLen,
		}
	}
	if len(message) != w.MessageLen {
		return false, &wrappedError{
			msg: fmt.Sprintf("message length must be %d bytes", w.MessageLen),
			err: ErrInvalidMessageLen,
		}
	}
	if len(signature) != w.NumSignatureChunks {
		return false, &wrappedError{
			// PARITY: this message has no "bytes" suffix in the original.
			msg: fmt.Sprintf("signature length must be %d", w.NumSignatureChunks),
			err: ErrInvalidSignatureLen,
		}
	}

	chainSegments := w.computeMessageHashChainIndexes(message)
	publicKeySegments := make([]byte, w.NumSignatureChunks*w.HashLen)

	// Compute each public key segment. These are done by taking the
	// signature, which is prevChainOut at chainIdx - 1, and completing the
	// hash chain via the chain function to recompute the public key segment.
	for i := 0; i < len(chainSegments); i++ {
		chainIdx := chainSegments[i]
		numIterations := w.ChainLen - chainIdx - 1
		prevChainOut := signature[i]

		segment, err := w.chain(prevChainOut, randomizationElements, chainIdx, numIterations)
		if err != nil {
			return false, err
		}
		// PARITY: Uint8Array.prototype.set throws a RangeError when the
		// source does not fit at the offset; segment is only ever longer
		// than HashLen when numIterations is 0 and the caller supplied an
		// over-long signature chunk.
		if len(segment) > len(publicKeySegments)-i*w.HashLen {
			return false, ErrSegmentOffsetOutOfBounds
		}
		copy(publicKeySegments[i*w.HashLen:], segment)
	}

	computedHash := w.hash(publicKeySegments)
	return bytes.Equal(computedHash, publicKeyHash), nil
}
