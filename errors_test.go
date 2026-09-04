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

// Every message asserted in this file is copied from a `throw new Error(...)`
// in src/wotsplus.ts. They are part of the observable behavior of the library
// and must stay character-for-character identical across the port.

package hashsigs

import (
	"bytes"
	"errors"
	"testing"
)

func TestConstructorErrors(t *testing.T) {
	tests := []struct {
		name     string
		opts     []Option
		sentinel error
		message  string
	}{
		{
			name:     "chain length not a power of two",
			opts:     []Option{WithChainLen(3)},
			sentinel: ErrChainLenNotPowerOfTwo,
			message:  "ChainLen must be a power of 2",
		},
		{
			name:     "hash length zero",
			opts:     []Option{WithHashLen(0)},
			sentinel: ErrHashLenNotPositive,
			message:  "HashLen must be positive",
		},
		{
			name:     "hash length negative",
			opts:     []Option{WithHashLen(-8)},
			sentinel: ErrHashLenNotPositive,
			message:  "HashLen must be positive",
		},
		{
			name:     "power of two but unsupported",
			opts:     []Option{WithChainLen(8)},
			sentinel: ErrChainLenUnsupported,
			message:  "ChainLen must be either 4 or 16 for XMSS compatibility",
		},
		{
			name:     "chain length 32",
			opts:     []Option{WithChainLen(32)},
			sentinel: ErrChainLenUnsupported,
			message:  "ChainLen must be either 4 or 16 for XMSS compatibility",
		},
		{
			// PARITY: 0 & -1 == 0, so zero passes the power-of-two test in
			// the original and is rejected by the XMSS test instead.
			name:     "chain length zero skips the power of two check",
			opts:     []Option{WithChainLen(0)},
			sentinel: ErrChainLenUnsupported,
			message:  "ChainLen must be either 4 or 16 for XMSS compatibility",
		},
		{
			// PARITY: the power-of-two check runs before the hash length
			// check, so it wins when both are invalid.
			name:     "chain length is checked before hash length",
			opts:     []Option{WithChainLen(3), WithHashLen(0)},
			sentinel: ErrChainLenNotPowerOfTwo,
			message:  "ChainLen must be a power of 2",
		},
		{
			// PARITY: the hash length check runs before the XMSS check.
			name:     "hash length is checked before the XMSS check",
			opts:     []Option{WithChainLen(8), WithHashLen(0)},
			sentinel: ErrHashLenNotPositive,
			message:  "HashLen must be positive",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w, err := New(Keccak256, tc.opts...)
			if err == nil {
				t.Fatalf("New succeeded, want error %q", tc.message)
			}
			if w != nil {
				t.Error("New returned a non-nil instance alongside an error")
			}
			if !errors.Is(err, tc.sentinel) {
				t.Errorf("errors.Is(%v, %v) = false", err, tc.sentinel)
			}
			if err.Error() != tc.message {
				t.Errorf("message = %q, want %q", err.Error(), tc.message)
			}
		})
	}
}

func TestNilHashFunction(t *testing.T) {
	if _, err := New(nil); !errors.Is(err, ErrNilHashFunction) {
		t.Errorf("New(nil) error = %v, want ErrNilHashFunction", err)
	}
}

func TestSignErrors(t *testing.T) {
	w := newDefault(t)
	seed := numberTo32Bytes(1)
	message := rampMessage(w.MessageLen)

	tests := []struct {
		name       string
		privateKey []byte
		message    []byte
		sentinel   error
		want       string
	}{
		{"short private key", make([]byte, 31), message, ErrInvalidPrivateKeyLen, "private key length must be 32 bytes"},
		{"long private key", make([]byte, 33), message, ErrInvalidPrivateKeyLen, "private key length must be 32 bytes"},
		{"empty private key", nil, message, ErrInvalidPrivateKeyLen, "private key length must be 32 bytes"},
		{"short message", seed, make([]byte, 31), ErrInvalidMessageLen, "message length must be 32 bytes"},
		{"long message", seed, make([]byte, 64), ErrInvalidMessageLen, "message length must be 32 bytes"},
		{"private key is checked first", make([]byte, 31), make([]byte, 31), ErrInvalidPrivateKeyLen, "private key length must be 32 bytes"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sig, err := w.Sign(tc.privateKey, seed, tc.message)
			if sig != nil {
				t.Error("Sign returned a signature alongside an error")
			}
			assertError(t, err, tc.sentinel, tc.want)
		})
	}
}

func TestVerifyErrors(t *testing.T) {
	w := newDefault(t)
	message := rampMessage(w.MessageLen)
	signature := make([][]byte, w.NumSignatureChunks)
	for i := range signature {
		signature[i] = make([]byte, w.HashLen)
	}

	t.Run("short public key", func(t *testing.T) {
		_, err := w.Verify(make([]byte, 63), message, signature)
		assertError(t, err, ErrInvalidPublicKeyLen, "public key length must be 64 bytes")
	})

	t.Run("long public key", func(t *testing.T) {
		_, err := w.Verify(make([]byte, 65), message, signature)
		assertError(t, err, ErrInvalidPublicKeyLen, "public key length must be 64 bytes")
	})

	t.Run("public key is checked before message", func(t *testing.T) {
		_, err := w.Verify(nil, nil, nil)
		assertError(t, err, ErrInvalidPublicKeyLen, "public key length must be 64 bytes")
	})
}

func TestVerifyWithRandomizationElementsErrors(t *testing.T) {
	w := newDefault(t)
	message := rampMessage(w.MessageLen)
	elements := w.GenerateRandomizationElements(numberTo32Bytes(2))
	signature := make([][]byte, w.NumSignatureChunks)
	for i := range signature {
		signature[i] = make([]byte, w.HashLen)
	}

	tests := []struct {
		name          string
		publicKeyHash []byte
		message       []byte
		signature     [][]byte
		sentinel      error
		want          string
	}{
		{"short public key hash", make([]byte, 31), message, signature, ErrInvalidPublicKeyHashLen, "public key hash length must be 32 bytes"},
		{"long public key hash", make([]byte, 64), message, signature, ErrInvalidPublicKeyHashLen, "public key hash length must be 32 bytes"},
		{"short message", make([]byte, 32), make([]byte, 16), signature, ErrInvalidMessageLen, "message length must be 32 bytes"},
		{"too few signature chunks", make([]byte, 32), message, signature[:66], ErrInvalidSignatureLen, "signature length must be 67"},
		{"too many signature chunks", make([]byte, 32), message, append(append([][]byte{}, signature...), make([]byte, 32)), ErrInvalidSignatureLen, "signature length must be 67"},
		{"nil signature", make([]byte, 32), message, nil, ErrInvalidSignatureLen, "signature length must be 67"},
		{"checks run in source order", make([]byte, 31), make([]byte, 16), nil, ErrInvalidPublicKeyHashLen, "public key hash length must be 32 bytes"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ok, err := w.VerifyWithRandomizationElements(tc.publicKeyHash, tc.message, tc.signature, elements)
			if ok {
				t.Error("verification reported success alongside an error")
			}
			assertError(t, err, tc.sentinel, tc.want)
		})
	}
}

func TestChainErrors(t *testing.T) {
	w := newDefault(t)
	elements := w.GenerateRandomizationElements(numberTo32Bytes(2))
	start := make([]byte, w.HashLen)

	t.Run("steps plus index reaches chain length", func(t *testing.T) {
		_, err := w.chain(start, elements, 0, w.ChainLen)
		assertError(t, err, ErrChainOverflow, "steps + index must be less than ChainLen")
	})

	t.Run("index at chain length", func(t *testing.T) {
		_, err := w.chain(start, elements, w.ChainLen, 0)
		assertError(t, err, ErrChainOverflow, "steps + index must be less than ChainLen")
	})

	t.Run("maximum walk is accepted", func(t *testing.T) {
		if _, err := w.chain(start, elements, 0, w.ChainLen-1); err != nil {
			t.Fatalf("chain: %v", err)
		}
	})

	t.Run("zero steps returns the input unchanged", func(t *testing.T) {
		out, err := w.chain(start, elements, 0, 0)
		if err != nil {
			t.Fatalf("chain: %v", err)
		}
		if &out[0] != &start[0] {
			t.Error("chain with zero steps must return its input, matching the original")
		}
	})

	t.Run("mismatched randomization element length", func(t *testing.T) {
		bad := make([][]byte, len(elements))
		copy(bad, elements)
		bad[1] = make([]byte, 16)
		_, err := w.chain(start, bad, 0, 1)
		assertError(t, err, ErrUnequalLength, "Arrays must have equal length")
	})

	t.Run("too few randomization elements", func(t *testing.T) {
		_, err := w.chain(start, elements[:1], 0, 1)
		if !errors.Is(err, ErrMissingRandomizationElement) {
			t.Errorf("error = %v, want ErrMissingRandomizationElement", err)
		}
	})
}

// TestVerifyPropagatesChainFailures covers the two failure modes that the
// TypeScript implementation surfaces as a TypeError and a RangeError rather
// than as a thrown Error with a message of its own. Both are only reachable
// through hand-built arguments, never through Sign output.
func TestVerifyPropagatesChainFailures(t *testing.T) {
	w := newDefault(t)
	message := make([]byte, w.MessageLen)
	publicKeyHash := make([]byte, w.HashLen)

	t.Run("too few randomization elements", func(t *testing.T) {
		signature := make([][]byte, w.NumSignatureChunks)
		for i := range signature {
			signature[i] = make([]byte, w.HashLen)
		}
		// An all-zero message walks the full chain, so chain reaches
		// randomizationElements[1] and finds nothing there.
		elements := w.GenerateRandomizationElements(publicKeyHash)[:1]
		_, err := w.VerifyWithRandomizationElements(publicKeyHash, message, signature, elements)
		if !errors.Is(err, ErrMissingRandomizationElement) {
			t.Errorf("error = %v, want ErrMissingRandomizationElement", err)
		}
	})

	t.Run("over long signature chunk at a zero step index", func(t *testing.T) {
		// PARITY: an all-0xff message puts every message chunk at
		// ChainLen-1, so numIterations is 0 and chain returns the caller's
		// chunk verbatim. A chunk longer than the whole segment buffer then
		// overflows the destination, which is a RangeError in TypeScript.
		allOnes := bytes.Repeat([]byte{0xff}, w.MessageLen)
		if idx := w.computeMessageHashChainIndexes(allOnes); idx[0] != w.ChainLen-1 {
			t.Fatalf("chain index 0 = %d, want %d", idx[0], w.ChainLen-1)
		}

		signature := make([][]byte, w.NumSignatureChunks)
		for i := range signature {
			signature[i] = make([]byte, w.HashLen)
		}
		signature[0] = make([]byte, w.NumSignatureChunks*w.HashLen+1)

		elements := w.GenerateRandomizationElements(publicKeyHash)
		_, err := w.VerifyWithRandomizationElements(publicKeyHash, allOnes, signature, elements)
		assertError(t, err, ErrSegmentOffsetOutOfBounds, "offset is out of bounds")
	})
}

func TestXorErrors(t *testing.T) {
	if _, err := xor(make([]byte, 4), make([]byte, 5)); err == nil || err.Error() != "Arrays must have equal length" {
		t.Errorf("xor error = %v, want %q", err, "Arrays must have equal length")
	}
	out, err := xor([]byte{0x0f, 0xf0}, []byte{0xff, 0x0f})
	if err != nil {
		t.Fatalf("xor: %v", err)
	}
	if out[0] != 0xf0 || out[1] != 0xff {
		t.Errorf("xor = %x, want f0ff", out)
	}
}

func assertError(t *testing.T, err error, sentinel error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("no error, want %q", want)
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("errors.Is(%v, %v) = false", err, sentinel)
	}
	if err.Error() != want {
		t.Errorf("message = %q, want %q", err.Error(), want)
	}
}
