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
	"testing"
)

// FuzzRoundTrip checks that arbitrary seeds and messages either round trip or
// fail with an error, and never panic. The TypeScript original has the same
// contract: it either returns or throws.
func FuzzRoundTrip(f *testing.F) {
	f.Add([]byte{1}, []byte{2}, make([]byte, 32))
	f.Add(make([]byte, 32), make([]byte, 32), make([]byte, 32))
	f.Add([]byte{}, []byte{}, bytes.Repeat([]byte{0xff}, 32))
	f.Add(bytes.Repeat([]byte{0xaa}, 96), bytes.Repeat([]byte{0xbb}, 32), bytes.Repeat([]byte{0x0f}, 32))

	f.Fuzz(func(t *testing.T, privateSeed, publicSeed, message []byte) {
		w := newDefault(t)

		kp, err := w.GenerateKeyPair(privateSeed, publicSeed)
		if err != nil {
			t.Fatalf("GenerateKeyPair must not fail: %v", err)
		}

		signature, err := w.Sign(kp.PrivateKey, publicSeed, message)
		if err != nil {
			if len(message) == w.MessageLen {
				t.Fatalf("Sign failed for a well formed message: %v", err)
			}
			return
		}

		isValid, err := w.Verify(kp.PublicKey, message, signature)
		if err != nil {
			if len(publicSeed) == w.HashLen {
				t.Fatalf("Verify failed for a well formed public key: %v", err)
			}
			return
		}
		if !isValid {
			t.Fatal("a freshly produced signature failed to verify")
		}

		publicKeyHash := kp.PublicKey[w.HashLen:w.PublicKeySize]
		isValid, err = w.VerifyWithRandomizationElements(
			publicKeyHash,
			message,
			signature,
			w.GenerateRandomizationElements(publicSeed),
		)
		if err != nil {
			t.Fatalf("VerifyWithRandomizationElements: %v", err)
		}
		if !isValid {
			t.Fatal("a freshly produced signature failed randomized verification")
		}
	})
}

// FuzzVerifyDoesNotPanic feeds untrusted material to the verification path,
// which is the part of the API exposed to attacker-controlled input.
func FuzzVerifyDoesNotPanic(f *testing.F) {
	f.Add(make([]byte, 64), make([]byte, 32), make([]byte, 32), 67)
	f.Add(make([]byte, 63), make([]byte, 31), make([]byte, 1), 0)
	f.Add(make([]byte, 64), make([]byte, 32), make([]byte, 33), 68)

	f.Fuzz(func(t *testing.T, publicKey, message, chunk []byte, numChunks int) {
		if numChunks < 0 || numChunks > 200 {
			t.Skip()
		}
		w := newDefault(t)

		signature := make([][]byte, numChunks)
		for i := range signature {
			signature[i] = chunk
		}

		isValid, err := w.Verify(publicKey, message, signature)
		if err != nil && isValid {
			t.Fatal("Verify reported success alongside an error")
		}

		if len(publicKey) >= w.HashLen {
			isValid, err = w.VerifyWithRandomizationElements(
				publicKey[:w.HashLen],
				message,
				signature,
				w.GenerateRandomizationElements(message),
			)
			if err != nil && isValid {
				t.Fatal("VerifyWithRandomizationElements reported success alongside an error")
			}
		}
	})
}
