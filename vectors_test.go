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
	"encoding/json"
	"os"
	"sort"
	"testing"
)

const vectorsPath = "test/test_vectors/wotsplus_keccak256.json"

type testVector struct {
	PrivateKey            string   `json:"privateKey"`
	PublicSeed            string   `json:"publicSeed"`
	PublicKeySegments     []string `json:"publicKeySegments"`
	RandomizationElements []string `json:"randomizationElements"`
	PublicKey             string   `json:"publicKey"`
	Message               string   `json:"message"`
	Signature             []string `json:"signature"`
}

func loadVectors(t *testing.T) (map[string]testVector, []string) {
	t.Helper()
	raw, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatalf("read %s: %v", vectorsPath, err)
	}
	var vectors map[string]testVector
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatalf("parse %s: %v", vectorsPath, err)
	}
	if len(vectors) == 0 {
		t.Fatalf("%s contains no vectors", vectorsPath)
	}
	// Go map iteration order is randomized; sort so failures are reproducible.
	names := make([]string, 0, len(vectors))
	for name := range vectors {
		names = append(names, name)
	}
	sort.Strings(names)
	return vectors, names
}

// it('should verify test vectors from JSON file')
func TestVectorsFromJSON(t *testing.T) {
	w := newDefault(t)
	vectors, names := loadVectors(t)

	for _, vectorName := range names {
		vector := vectors[vectorName]

		publicKey := hexToBytes(t, vector.PublicKey)
		message := hexToBytes(t, vector.Message)
		signature := hexToChunks(t, vector.Signature)
		randomizationElements := hexToChunks(t, vector.RandomizationElements)

		isValid, err := w.Verify(publicKey, message, signature)
		if err != nil {
			t.Fatalf("Standard verification errored for %s: %v", vectorName, err)
		}
		if !isValid {
			t.Errorf("Standard verification failed for %s", vectorName)
		}

		publicKeyHash := publicKey[w.HashLen:w.PublicKeySize]
		isValidWithRand, err := w.VerifyWithRandomizationElements(
			publicKeyHash,
			message,
			signature,
			randomizationElements,
		)
		if err != nil {
			t.Fatalf("Randomized verification errored for %s: %v", vectorName, err)
		}
		if !isValidWithRand {
			t.Errorf("Randomized verification failed for %s", vectorName)
		}
	}
}

// TestVectorsRegenerate is stronger than the ported suite: it re-derives every
// field of each vector from privateKey and publicSeed and requires
// byte-for-byte equality. This is what pins the Go port to the TypeScript
// output rather than merely to a self-consistent scheme.
func TestVectorsRegenerate(t *testing.T) {
	w := newDefault(t)
	vectors, names := loadVectors(t)

	for _, vectorName := range names {
		vector := vectors[vectorName]

		privateKey := hexToBytes(t, vector.PrivateKey)
		publicSeed := hexToBytes(t, vector.PublicSeed)
		message := hexToBytes(t, vector.Message)
		wantPublicKey := hexToBytes(t, vector.PublicKey)
		wantSignature := hexToChunks(t, vector.Signature)
		wantElements := hexToChunks(t, vector.RandomizationElements)
		wantSegments := hexToChunks(t, vector.PublicKeySegments)

		gotElements := w.GenerateRandomizationElements(publicSeed)
		if len(gotElements) != len(wantElements) {
			t.Fatalf("%s: %d randomization elements, want %d", vectorName, len(gotElements), len(wantElements))
		}
		for i := range wantElements {
			if !bytes.Equal(gotElements[i], wantElements[i]) {
				t.Fatalf("%s: randomization element %d = %x, want %x", vectorName, i, gotElements[i], wantElements[i])
			}
		}

		gotSignature, err := w.Sign(privateKey, publicSeed, message)
		if err != nil {
			t.Fatalf("%s: Sign: %v", vectorName, err)
		}
		if len(gotSignature) != len(wantSignature) {
			t.Fatalf("%s: %d signature chunks, want %d", vectorName, len(gotSignature), len(wantSignature))
		}
		for i := range wantSignature {
			if !bytes.Equal(gotSignature[i], wantSignature[i]) {
				t.Fatalf("%s: signature chunk %d = %x, want %x", vectorName, i, gotSignature[i], wantSignature[i])
			}
		}

		// The `publicKeySegments` field of the fixture is a verbatim copy of
		// `randomizationElements`, i.e. the generator that produced the
		// fixture wrote the wrong array. The TypeScript suite never reads
		// the field, so the defect is inert; it is asserted here so that a
		// future regenerated fixture is noticed rather than silently
		// changing meaning.
		for i := range wantSegments {
			if !bytes.Equal(wantSegments[i], wantElements[i]) {
				t.Fatalf("%s: fixture publicKeySegments no longer duplicates randomizationElements at %d", vectorName, i)
			}
		}

		gotSegments := w.publicKeySegmentsFromPrivateKey(t, privateKey, publicSeed)
		gotPublicKey := concat(publicSeed, w.hash(flatten(gotSegments)))
		if !bytes.Equal(gotPublicKey, wantPublicKey) {
			t.Fatalf("%s: public key = %x, want %x", vectorName, gotPublicKey, wantPublicKey)
		}
	}
}

func (w *WOTSPlus) publicKeySegmentsFromPrivateKey(t *testing.T, privateKey, publicSeed []byte) [][]byte {
	t.Helper()
	elements := w.GenerateRandomizationElements(publicSeed)
	functionKey := elements[0]
	segments := make([][]byte, w.NumSignatureChunks)
	for i := 0; i < w.NumSignatureChunks; i++ {
		secretKeySegment := w.hash(concat(functionKey, w.prf(privateKey, i+1)))
		segment, err := w.chain(secretKeySegment, elements, 0, w.ChainLen-1)
		if err != nil {
			t.Fatalf("chain: %v", err)
		}
		segments[i] = segment
	}
	return segments
}

func flatten(chunks [][]byte) []byte {
	var out []byte
	for _, c := range chunks {
		out = append(out, c...)
	}
	return out
}
