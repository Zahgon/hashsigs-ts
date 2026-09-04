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

import "testing"

func benchFixture(b *testing.B) (*WOTSPlus, *KeyPair, []byte, []byte, [][]byte) {
	b.Helper()
	w, err := New(Keccak256)
	if err != nil {
		b.Fatalf("New: %v", err)
	}
	publicSeed := Keccak256([]byte("public seed"))
	kp, err := w.GenerateKeyPair(Keccak256([]byte("private seed")), publicSeed)
	if err != nil {
		b.Fatalf("GenerateKeyPair: %v", err)
	}
	message := Keccak256([]byte("Hello World"))
	signature, err := w.Sign(kp.PrivateKey, publicSeed, message)
	if err != nil {
		b.Fatalf("Sign: %v", err)
	}
	return w, kp, publicSeed, message, signature
}

func BenchmarkGenerateKeyPair(b *testing.B) {
	w, _, publicSeed, _, _ := benchFixture(b)
	privateSeed := Keccak256([]byte("private seed"))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := w.GenerateKeyPair(privateSeed, publicSeed); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSign(b *testing.B) {
	w, kp, publicSeed, message, _ := benchFixture(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := w.Sign(kp.PrivateKey, publicSeed, message); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerify(b *testing.B) {
	w, kp, _, message, signature := benchFixture(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := w.Verify(kp.PublicKey, message, signature); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyWithRandomizationElements(b *testing.B) {
	w, kp, publicSeed, message, signature := benchFixture(b)
	elements := w.GenerateRandomizationElements(publicSeed)
	publicKeyHash := kp.PublicKey[w.HashLen:w.PublicKeySize]
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := w.VerifyWithRandomizationElements(publicKeyHash, message, signature, elements); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkGenerateRandomizationElements(b *testing.B) {
	w, _, publicSeed, _, _ := benchFixture(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w.GenerateRandomizationElements(publicSeed)
	}
}
