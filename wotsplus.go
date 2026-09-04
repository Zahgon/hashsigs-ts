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

// hash is the WOTS+ `F` hash function.
func (w *WOTSPlus) hash(data []byte) []byte {
	return w.hashFn(data)
}

// prf generates randomization elements from seed and index.
// Similar to XMSS RFC 8391 section 5.1
// NOTE: while sha256 and ripemd160 are available in solidity,
// they are implemented as precompiled contracts and are more expensive for gas.
func (w *WOTSPlus) prf(seed []byte, index int) []byte {
	// Create a buffer with prefix (0x03), seed, and index
	buffer := make([]byte, 1+len(seed)+2)
	buffer[0] = 0x03       // prefix to domain separate
	copy(buffer[1:], seed) // the seed input
	// Set index as 2 bytes (uint16)
	buffer[len(seed)+1] = byte((index >> 8) & 0xFF)
	buffer[len(seed)+2] = byte(index & 0xFF)

	return w.hash(buffer)
}

// GenerateRandomizationElements generates randomization elements from a seed.
// Similar to XMSS RFC 8391 section 5.1
//
// The returned slice holds NumSignatureChunks elements. Element 0 doubles as
// the WOTS+ function key; elements 1..ChainLen-1 are the values consumed by
// the hash chains.
func (w *WOTSPlus) GenerateRandomizationElements(publicSeed []byte) [][]byte {
	elements := make([][]byte, 0, w.NumSignatureChunks)
	for i := 0; i < w.NumSignatureChunks; i++ {
		elements = append(elements, w.prf(publicSeed, i))
	}
	return elements
}

// chain is the c_k^i function,
// the hash of (prevChainOut XOR randomization element at index).
// As a practical matter, we generate the randomization elements
// via a seed like in XMSS(rfc8391) with a defined PRF.
//
// PARITY: the randomization element consumed on iteration i is
// randomizationElements[i+index], exactly as in the TypeScript original.
// Only elements 1..ChainLen-1 are ever read, even though
// NumSignatureChunks elements are generated.
//
// PARITY: with steps == 0 the input slice is returned unchanged (the
// TypeScript original returns the same reference). Callers must copy the
// result before mutating it; every call site in this package does.
func (w *WOTSPlus) chain(
	prevChainOut []byte,
	randomizationElements [][]byte,
	index int,
	steps int,
) ([]byte, error) {
	if index+steps >= w.ChainLen {
		return nil, ErrChainOverflow
	}

	chainOut := prevChainOut
	for i := 1; i <= steps; i++ {
		// DIVERGENCE: TypeScript reads past the end of the array and fails
		// with a TypeError inside xor; Go would panic, so the bound is
		// checked explicitly. The set of accepted inputs is unchanged.
		if i+index < 0 || i+index >= len(randomizationElements) {
			return nil, ErrMissingRandomizationElement
		}
		xored, err := xor(chainOut, randomizationElements[i+index])
		if err != nil {
			return nil, err
		}
		chainOut = w.hash(xored)
	}
	return chainOut, nil
}

// xor computes the bitwise XOR of two byte arrays.
func xor(a, b []byte) ([]byte, error) {
	if len(a) != len(b) {
		return nil, ErrUnequalLength
	}
	result := make([]byte, len(a))
	for i := 0; i < len(a); i++ {
		result[i] = a[i] ^ b[i]
	}
	return result, nil
}

// concat mirrors `new Uint8Array([...a, ...b])`: it always allocates a new
// slice, so neither input can be aliased or mutated by the result.
func concat(a, b []byte) []byte {
	out := make([]byte, len(a)+len(b))
	copy(out, a)
	copy(out[len(a):], b)
	return out
}

// clone mirrors the copying behavior of Uint8Array.prototype.slice, which Go
// slice expressions do not provide.
func clone(b []byte) []byte {
	out := make([]byte, len(b))
	copy(out, b)
	return out
}
