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

// This file ports src/wotsplus.test.ts. There is one Go test per `it(...)`
// block, in the original order and with the original assertions.

package hashsigs

import (
	"bytes"
	"fmt"
	"testing"
)

// it('should generate key pair')
func TestGenerateKeyPair(t *testing.T) {
	w := newDefault(t)
	privateSeed := numberTo32Bytes(1)
	publicSeed := numberTo32Bytes(2)

	kp, err := w.GenerateKeyPair(privateSeed, publicSeed)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	if len(kp.PublicKey) != w.PublicKeySize {
		t.Errorf("public key length = %d, want %d", len(kp.PublicKey), w.PublicKeySize)
	}
	if !bytes.Equal(publicSeed, kp.PublicKey[:w.HashLen]) {
		t.Errorf("public key prefix = %x, want public seed %x", kp.PublicKey[:w.HashLen], publicSeed)
	}
	if bytes.Equal(kp.PrivateKey, make([]byte, 32)) {
		t.Error("private key must not be all zero")
	}
}

// it('should fail to verify empty signature')
func TestFailToVerifyEmptySignature(t *testing.T) {
	w := newDefault(t)
	kp, err := w.GenerateKeyPair(numberTo32Bytes(1), numberTo32Bytes(2))
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	message := rampMessage(w.MessageLen)

	emptySignature := make([][]byte, w.NumSignatureChunks)
	for i := range emptySignature {
		emptySignature[i] = make([]byte, w.HashLen)
	}

	isValid, err := w.Verify(kp.PublicKey, message, emptySignature)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if isValid {
		t.Error("empty signature verified as valid")
	}
}

// it('should verify valid signature')
func TestVerifyValidSignature(t *testing.T) {
	w := newDefault(t)
	privateSeed := numberTo32Bytes(1)
	publicSeed := numberTo32Bytes(2)

	kp, err := w.GenerateKeyPair(privateSeed, publicSeed)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	message := rampMessage(w.MessageLen)

	signature, err := w.Sign(kp.PrivateKey, publicSeed, message)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	isValid, err := w.Verify(kp.PublicKey, message, signature)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !isValid {
		t.Error("valid signature failed to verify")
	}
}

// it('should verify valid signature with randomization elements')
func TestVerifyValidSignatureWithRandomizationElements(t *testing.T) {
	w := newDefault(t)
	privateSeed := numberTo32Bytes(1)
	publicSeed := numberTo32Bytes(2)

	kp, err := w.GenerateKeyPair(privateSeed, publicSeed)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	message := rampMessage(w.MessageLen)

	signature, err := w.Sign(kp.PrivateKey, publicSeed, message)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if !bytes.Equal(publicSeed, kp.PublicKey[:w.HashLen]) {
		t.Fatalf("public key prefix = %x, want public seed %x", kp.PublicKey[:w.HashLen], publicSeed)
	}
	publicKeyHash := kp.PublicKey[w.HashLen : w.HashLen*2]

	randomizationElements := w.GenerateRandomizationElements(publicSeed)

	isValid, err := w.VerifyWithRandomizationElements(
		publicKeyHash,
		message,
		signature,
		randomizationElements,
	)
	if err != nil {
		t.Fatalf("VerifyWithRandomizationElements: %v", err)
	}
	if !isValid {
		t.Error("valid signature failed to verify")
	}
}

// it('should verify many signatures')
//
// PARITY: the loop condition in the TypeScript original is
// `for (let i = 1; i < 1; i++)`, so the body never executes. The dead loop is
// preserved here for a faithful port; TestVerifyManySignaturesExtended below
// is the live version.
func TestVerifyManySignatures(t *testing.T) {
	w := newDefault(t)
	for i := int32(1); i < 1; i++ {
		privateSeed := numberTo32Bytes(i)
		publicSeed := numberTo32Bytes(i + 1)

		kp, err := w.GenerateKeyPair(privateSeed, publicSeed)
		if err != nil {
			t.Fatalf("GenerateKeyPair: %v", err)
		}

		messageHash := Keccak256([]byte(fmt.Sprintf("Hello World%d", i)))

		signature, err := w.Sign(kp.PrivateKey, publicSeed, messageHash)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		isValid, err := w.Verify(kp.PublicKey, messageHash, signature)
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if !isValid {
			t.Errorf("signature %d failed to verify", i)
		}
	}
}

// it('should verify many signatures with randomization elements')
//
// PARITY: dead loop in the original, as above. Note that this test uses
// publicSeed = numberToUint8Array(i) while the previous one uses i+1; the
// difference is preserved.
func TestVerifyManySignaturesWithRandomizationElements(t *testing.T) {
	w := newDefault(t)
	for i := int32(1); i < 1; i++ {
		privateSeed := numberTo32Bytes(i)
		publicSeed := numberTo32Bytes(i)

		kp, err := w.GenerateKeyPair(privateSeed, publicSeed)
		if err != nil {
			t.Fatalf("GenerateKeyPair: %v", err)
		}

		messageHash := Keccak256([]byte(fmt.Sprintf("Hello World%d", i)))

		signature, err := w.Sign(kp.PrivateKey, publicSeed, messageHash)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}

		publicKeyHash := kp.PublicKey[w.HashLen : w.HashLen*2]
		randomizationElements := w.GenerateRandomizationElements(publicSeed)

		isValid, err := w.VerifyWithRandomizationElements(
			publicKeyHash,
			messageHash,
			signature,
			randomizationElements,
		)
		if err != nil {
			t.Fatalf("VerifyWithRandomizationElements: %v", err)
		}
		if !isValid {
			t.Errorf("signature %d failed to verify", i)
		}
	}
}

// TestVerifyManySignaturesExtended is the live version of the two dead loops
// above. It is an addition, not part of the ported suite.
func TestVerifyManySignaturesExtended(t *testing.T) {
	w := newDefault(t)
	for i := int32(1); i < 64; i++ {
		privateSeed := numberTo32Bytes(i)
		publicSeed := numberTo32Bytes(i + 1)

		kp, err := w.GenerateKeyPair(privateSeed, publicSeed)
		if err != nil {
			t.Fatalf("GenerateKeyPair: %v", err)
		}

		messageHash := Keccak256([]byte(fmt.Sprintf("Hello World%d", i)))

		signature, err := w.Sign(kp.PrivateKey, publicSeed, messageHash)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}

		isValid, err := w.Verify(kp.PublicKey, messageHash, signature)
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if !isValid {
			t.Fatalf("signature %d failed to verify", i)
		}

		publicKeyHash := kp.PublicKey[w.HashLen : w.HashLen*2]
		isValidWithRand, err := w.VerifyWithRandomizationElements(
			publicKeyHash,
			messageHash,
			signature,
			w.GenerateRandomizationElements(publicSeed),
		)
		if err != nil {
			t.Fatalf("VerifyWithRandomizationElements: %v", err)
		}
		if !isValidWithRand {
			t.Fatalf("signature %d failed randomized verification", i)
		}

		tampered := Keccak256([]byte(fmt.Sprintf("Hello World%d!", i)))
		isValid, err = w.Verify(kp.PublicKey, tampered, signature)
		if err == nil && isValid {
			t.Fatalf("signature %d verified against a different message", i)
		}
	}
}
