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

package hashsigs_test

import (
	"crypto/rand"
	"fmt"
	"log"

	hashsigs "github.com/quipnetwork/hashsigs-go"
)

func Example() {
	wots, err := hashsigs.New(hashsigs.Keccak256)
	if err != nil {
		log.Fatal(err)
	}

	privateSeed := make([]byte, wots.HashLen)
	publicSeed := make([]byte, wots.HashLen)
	if _, err := rand.Read(privateSeed); err != nil {
		log.Fatal(err)
	}
	if _, err := rand.Read(publicSeed); err != nil {
		log.Fatal(err)
	}

	keyPair, err := wots.GenerateKeyPair(privateSeed, publicSeed)
	if err != nil {
		log.Fatal(err)
	}

	// WOTS+ signs a digest, not a message: it must be exactly MessageLen bytes.
	messageHash := hashsigs.Keccak256([]byte("Hello World"))

	// A private key must sign at most one message.
	signature, err := wots.Sign(keyPair.PrivateKey, publicSeed, messageHash)
	if err != nil {
		log.Fatal(err)
	}

	isValid, err := wots.Verify(keyPair.PublicKey, messageHash, signature)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("public key bytes:", len(keyPair.PublicKey))
	fmt.Println("signature chunks:", len(signature))
	fmt.Println("valid:", isValid)
	// Output:
	// public key bytes: 64
	// signature chunks: 67
	// valid: true
}

// The randomization elements are derived from the public seed alone, so a
// verifier that checks many signatures under the same public seed can derive
// them once and reuse them.
func ExampleWOTSPlus_VerifyWithRandomizationElements() {
	wots, err := hashsigs.New(hashsigs.Keccak256)
	if err != nil {
		log.Fatal(err)
	}

	privateSeed := hashsigs.Keccak256([]byte("private seed"))
	publicSeed := hashsigs.Keccak256([]byte("public seed"))

	keyPair, err := wots.GenerateKeyPair(privateSeed, publicSeed)
	if err != nil {
		log.Fatal(err)
	}

	messageHash := hashsigs.Keccak256([]byte("Hello World"))
	signature, err := wots.Sign(keyPair.PrivateKey, publicSeed, messageHash)
	if err != nil {
		log.Fatal(err)
	}

	randomizationElements := wots.GenerateRandomizationElements(publicSeed)
	publicKeyHash := keyPair.PublicKey[wots.HashLen:wots.PublicKeySize]

	isValid, err := wots.VerifyWithRandomizationElements(
		publicKeyHash,
		messageHash,
		signature,
		randomizationElements,
	)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("valid:", isValid)
	// Output:
	// valid: true
}

func ExampleNew_chainLen() {
	wots, err := hashsigs.New(hashsigs.Keccak256, hashsigs.WithChainLen(4))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("signature chunks:", wots.NumSignatureChunks)

	if _, err := hashsigs.New(hashsigs.Keccak256, hashsigs.WithChainLen(8)); err != nil {
		fmt.Println("error:", err)
	}
	// Output:
	// signature chunks: 133
	// error: ChainLen must be either 4 or 16 for XMSS compatibility
}
