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

// The expected values in this file were read out of the TypeScript
// implementation; see parity/ts_dump.mjs and testdata/parity_ts.json.

package hashsigs

import (
	"bytes"
	"errors"
	"testing"
)

func TestDerivedParameters(t *testing.T) {
	tests := []struct {
		name               string
		opts               []Option
		hashLen            int
		messageLen         int
		chainLen           int
		lgChainLen         float64
		numMessageChunks   int
		numChecksumChunks  int
		numSignatureChunks int
		signatureSize      int
		publicKeySize      int
	}{
		{"defaults", nil, 32, 32, 16, 4, 64, 3, 67, 2144, 64},
		{"chain length 4", []Option{WithChainLen(4)}, 32, 32, 4, 2, 128, 5, 133, 4256, 64},
		{"hash length 64", []Option{WithHashLen(64)}, 64, 64, 16, 4, 128, 3, 131, 8384, 128},
		{"hash length 1", []Option{WithHashLen(1)}, 1, 1, 16, 4, 2, 2, 4, 4, 2},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w, err := New(Keccak256, tc.opts...)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			checks := []struct {
				field string
				got   int
				want  int
			}{
				{"HashLen", w.HashLen, tc.hashLen},
				{"MessageLen", w.MessageLen, tc.messageLen},
				{"ChainLen", w.ChainLen, tc.chainLen},
				{"NumMessageChunks", w.NumMessageChunks, tc.numMessageChunks},
				{"NumChecksumChunks", w.NumChecksumChunks, tc.numChecksumChunks},
				{"NumSignatureChunks", w.NumSignatureChunks, tc.numSignatureChunks},
				{"SignatureSize", w.SignatureSize, tc.signatureSize},
				{"PublicKeySize", w.PublicKeySize, tc.publicKeySize},
			}
			for _, c := range checks {
				if c.got != c.want {
					t.Errorf("%s = %d, want %d", c.field, c.got, c.want)
				}
			}
			if w.LgChainLen != tc.lgChainLen {
				t.Errorf("LgChainLen = %v, want %v", w.LgChainLen, tc.lgChainLen)
			}
		})
	}
}

// PARITY: toBaseW is hardcoded to base 16 and ignores ChainLen, and reads
// past the end of the message contribute 0 rather than failing. Both are
// reproduced from the TypeScript original.
func TestToBaseWQuirks(t *testing.T) {
	t.Run("splits bytes into nibbles", func(t *testing.T) {
		w := newDefault(t)
		out := make([]int, 4)
		w.toBaseW([]byte{0xab, 0xcd}, 4, out, 0)
		want := []int{0xa, 0xb, 0xc, 0xd}
		for i := range want {
			if out[i] != want[i] {
				t.Fatalf("toBaseW = %v, want %v", out, want)
			}
		}
	})

	t.Run("honours the offset", func(t *testing.T) {
		w := newDefault(t)
		out := make([]int, 4)
		w.toBaseW([]byte{0xab}, 2, out, 2)
		if out[0] != 0 || out[1] != 0 || out[2] != 0xa || out[3] != 0xb {
			t.Fatalf("toBaseW = %v, want [0 0 10 11]", out)
		}
	})

	t.Run("chain length 4 still emits nibbles", func(t *testing.T) {
		w, err := New(Keccak256, WithChainLen(4))
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		out := make([]int, w.NumMessageChunks)
		w.toBaseW([]byte{0xab}, w.NumMessageChunks, out, 0)
		if out[0] != 0xa || out[1] != 0xb {
			t.Errorf("out[0:2] = %v, want [10 11]; base 16 output is expected even at ChainLen 4", out[:2])
		}
	})

	t.Run("reads past the message yield zero", func(t *testing.T) {
		w, err := New(Keccak256, WithChainLen(4))
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		message := filledBytes(32, 0xff)
		out := make([]int, w.NumMessageChunks)
		w.toBaseW(message, w.NumMessageChunks, out, 0)
		for i := 0; i < 64; i++ {
			if out[i] != 0xf {
				t.Fatalf("out[%d] = %d, want 15", i, out[i])
			}
		}
		for i := 64; i < w.NumMessageChunks; i++ {
			if out[i] != 0 {
				t.Fatalf("out[%d] = %d, want 0 for reads past the end of the message", i, out[i])
			}
		}
	})
}

// PARITY: at ChainLen 4 the base-16 chain indexes exceed the chain length, so
// signing fails for any message with a nibble of 4 or more. This matches the
// TypeScript original exactly; see the w4_* cases in testdata/parity_ts.json.
func TestChainLenFourBehavior(t *testing.T) {
	w, err := New(Keccak256, WithChainLen(4))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	privateSeed := numberTo32Bytes(11)
	publicSeed := numberTo32Bytes(12)

	kp, err := w.GenerateKeyPair(privateSeed, publicSeed)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	if len(kp.PublicKey) != w.PublicKeySize {
		t.Fatalf("public key length = %d, want %d", len(kp.PublicKey), w.PublicKeySize)
	}

	t.Run("high nibbles overflow the chain", func(t *testing.T) {
		_, err := w.Sign(kp.PrivateKey, publicSeed, rampMessage(w.MessageLen))
		assertError(t, err, ErrChainOverflow, "steps + index must be less than ChainLen")
	})

	t.Run("low nibbles round trip", func(t *testing.T) {
		message := filledBytes(32, 0x03)
		signature, err := w.Sign(kp.PrivateKey, publicSeed, message)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		if len(signature) != w.NumSignatureChunks {
			t.Fatalf("signature has %d chunks, want %d", len(signature), w.NumSignatureChunks)
		}
		isValid, err := w.Verify(kp.PublicKey, message, signature)
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if !isValid {
			t.Error("valid ChainLen 4 signature failed to verify")
		}
	})
}

// PARITY: chain reads randomizationElements[i+index], so only elements
// 1..ChainLen-1 ever matter even though NumSignatureChunks are generated.
func TestOnlyFirstChainLenRandomizationElementsAreUsed(t *testing.T) {
	w := newDefault(t)
	publicSeed := numberTo32Bytes(2)
	privateSeed := numberTo32Bytes(1)

	kp, err := w.GenerateKeyPair(privateSeed, publicSeed)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	message := rampMessage(w.MessageLen)
	signature, err := w.Sign(kp.PrivateKey, publicSeed, message)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	tampered := w.GenerateRandomizationElements(publicSeed)
	for i := w.ChainLen; i < len(tampered); i++ {
		tampered[i] = filledBytes(w.HashLen, 0xaa)
	}

	publicKeyHash := kp.PublicKey[w.HashLen:w.PublicKeySize]
	isValid, err := w.VerifyWithRandomizationElements(publicKeyHash, message, signature, tampered)
	if err != nil {
		t.Fatalf("VerifyWithRandomizationElements: %v", err)
	}
	if !isValid {
		t.Error("verification depends on randomization elements beyond ChainLen-1, unlike the original")
	}
}

func TestPRF(t *testing.T) {
	w := newDefault(t)
	seed := numberTo32Bytes(2)

	t.Run("domain separated and index encoded big endian", func(t *testing.T) {
		buffer := make([]byte, 0, 1+len(seed)+2)
		buffer = append(buffer, 0x03)
		buffer = append(buffer, seed...)
		buffer = append(buffer, 0x01, 0x02)
		if !bytes.Equal(w.prf(seed, 0x0102), Keccak256(buffer)) {
			t.Error("prf is not hash(0x03 || seed || uint16be(index))")
		}
	})

	t.Run("distinct indexes give distinct outputs", func(t *testing.T) {
		if bytes.Equal(w.prf(seed, 1), w.prf(seed, 2)) {
			t.Error("prf collides across indexes")
		}
	})
}

func TestGenerateRandomizationElements(t *testing.T) {
	w := newDefault(t)
	elements := w.GenerateRandomizationElements(numberTo32Bytes(2))
	if len(elements) != w.NumSignatureChunks {
		t.Fatalf("got %d elements, want %d", len(elements), w.NumSignatureChunks)
	}
	for i, element := range elements {
		if len(element) != w.HashLen {
			t.Fatalf("element %d has length %d, want %d", i, len(element), w.HashLen)
		}
	}
}

func TestChecksumIsIncludedInChainIndexes(t *testing.T) {
	w := newDefault(t)
	indexes := w.computeMessageHashChainIndexes(make([]byte, w.MessageLen))
	if len(indexes) != w.NumSignatureChunks {
		t.Fatalf("got %d chain indexes, want %d", len(indexes), w.NumSignatureChunks)
	}
	// An all-zero message maximises the checksum: 64 chunks * 15 = 960 = 0x3c0.
	want := []int{0, 0x3, 0xc, 0x0}
	for i, chunk := range indexes[:w.NumMessageChunks] {
		if chunk != 0 {
			t.Fatalf("message chunk %d = %d, want 0", i, chunk)
		}
	}
	for i := 0; i < w.NumChecksumChunks; i++ {
		if got := indexes[w.NumMessageChunks+i]; got != want[i+1] {
			t.Errorf("checksum chunk %d = %d, want %d", i, got, want[i+1])
		}
	}
}

func TestSignatureShape(t *testing.T) {
	w := newDefault(t)
	publicSeed := numberTo32Bytes(2)
	kp, err := w.GenerateKeyPair(numberTo32Bytes(1), publicSeed)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	signature, err := w.Sign(kp.PrivateKey, publicSeed, rampMessage(w.MessageLen))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(signature) != w.NumSignatureChunks {
		t.Fatalf("signature has %d chunks, want %d", len(signature), w.NumSignatureChunks)
	}
	total := 0
	for i, chunk := range signature {
		if len(chunk) != w.HashLen {
			t.Fatalf("chunk %d has length %d, want %d", i, len(chunk), w.HashLen)
		}
		total += len(chunk)
	}
	if total != w.SignatureSize {
		t.Errorf("signature size = %d, want %d", total, w.SignatureSize)
	}
}

// Mutating a returned signature must not corrupt any state the library keeps,
// and must not be observable through a second call.
func TestReturnedValuesAreIndependent(t *testing.T) {
	w := newDefault(t)
	publicSeed := numberTo32Bytes(3)
	kp, err := w.GenerateKeyPair(numberTo32Bytes(4), publicSeed)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	message := rampMessage(w.MessageLen)

	first, err := w.Sign(kp.PrivateKey, publicSeed, message)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	reference := make([][]byte, len(first))
	for i := range first {
		reference[i] = clone(first[i])
	}
	for i := range first {
		first[i][0] ^= 0xff
	}

	second, err := w.Sign(kp.PrivateKey, publicSeed, message)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	for i := range second {
		if !bytes.Equal(second[i], reference[i]) {
			t.Fatalf("chunk %d changed after the previous signature was mutated", i)
		}
	}
}

func TestSeedsAreNotValidated(t *testing.T) {
	w := newDefault(t)
	// PARITY: the original validates neither seed, so short, empty and long
	// seeds are all accepted by GenerateKeyPair.
	for _, seedLen := range []int{0, 1, 3, 31, 33, 96} {
		seed := filledBytes(seedLen, 0xab)
		kp, err := w.GenerateKeyPair(seed, seed)
		if err != nil {
			t.Fatalf("GenerateKeyPair with %d byte seeds: %v", seedLen, err)
		}
		if len(kp.PrivateKey) != w.HashLen {
			t.Errorf("private key length = %d, want %d", len(kp.PrivateKey), w.HashLen)
		}
		if want := seedLen + w.HashLen; len(kp.PublicKey) != want {
			t.Errorf("public key length = %d, want %d", len(kp.PublicKey), want)
		}
		// A public seed that is not HashLen bytes produces a public key that
		// Verify rejects on length, exactly as in the original.
		if seedLen != w.HashLen {
			_, err := w.Verify(kp.PublicKey, make([]byte, w.MessageLen), nil)
			if !errors.Is(err, ErrInvalidPublicKeyLen) {
				t.Errorf("Verify error = %v, want ErrInvalidPublicKeyLen", err)
			}
		}
	}
}

func filledBytes(n int, v byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = v
	}
	return b
}
