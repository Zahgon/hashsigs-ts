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

// Package paritydump builds a document describing the observable behavior of
// this package for a fixed set of inputs. parity/ts_dump.mjs builds the same
// document from the TypeScript original; the two must be byte identical.
package paritydump

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"

	hashsigs "github.com/quipnetwork/hashsigs-go"
)

type paramsOut struct {
	HashLen            int     `json:"hashLen"`
	MessageLen         int     `json:"messageLen"`
	ChainLen           int     `json:"chainLen"`
	LgChainLen         float64 `json:"lgChainLen"`
	NumMessageChunks   int     `json:"numMessageChunks"`
	NumChecksumChunks  int     `json:"numChecksumChunks"`
	NumSignatureChunks int     `json:"numSignatureChunks"`
	SignatureSize      int     `json:"signatureSize"`
	PublicKeySize      int     `json:"publicKeySize"`
}

type caseOut struct {
	Name                  string     `json:"name"`
	Params                *paramsOut `json:"params"`
	PrivateSeed           string     `json:"privateSeed"`
	PublicSeed            string     `json:"publicSeed"`
	Message               string     `json:"message"`
	PrivateKey            *string    `json:"privateKey"`
	PublicKey             *string    `json:"publicKey"`
	RandomizationElements []string   `json:"randomizationElements"`
	Signature             []string   `json:"signature"`
	SignError             *string    `json:"signError"`
	Verify                *bool      `json:"verify"`
	VerifyError           *string    `json:"verifyError"`
	VerifyWithElements    *bool      `json:"verifyWithElements"`
	VerifyTampered        *bool      `json:"verifyTampered"`
	VerifyEmptySignature  *bool      `json:"verifyEmptySignature"`
}

type constructorCase struct {
	Name   string     `json:"name"`
	Error  *string    `json:"error"`
	Params *paramsOut `json:"params"`
}

type validationCase struct {
	Name   string  `json:"name"`
	Error  *string `json:"error"`
	Result any     `json:"result"`
}

type Document struct {
	Cases            []caseOut         `json:"cases"`
	ConstructorCases []constructorCase `json:"constructorCases"`
	ValidationCases  []validationCase  `json:"validationCases"`
}

func toHex(b []byte) string { return "0x" + hex.EncodeToString(b) }

func hexAll(chunks [][]byte) []string {
	out := make([]string, len(chunks))
	for i, c := range chunks {
		out[i] = toHex(c)
	}
	return out
}

func strPtr(s string) *string { return &s }
func boolPtr(b bool) *bool    { return &b }

func errPtr(err error) *string {
	if err == nil {
		return nil
	}
	return strPtr(err.Error())
}

// numberToUint8Array ports the helper of the same name from wotsplus.test.ts.
// The shift is on int32 because JavaScript's `>>` is a signed 32 bit shift.
func numberToUint8Array(num int32) []byte {
	arr := make([]byte, 32)
	for i := 0; i < 32; i++ {
		arr[31-i] = byte(num & 0xff)
		num >>= 8
	}
	return arr
}

func filled(n int, v byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = v
	}
	return b
}

func rampBy(n, step int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i * step)
	}
	return b
}

func dumpParams(w *hashsigs.WOTSPlus) *paramsOut {
	return &paramsOut{
		HashLen:            w.HashLen,
		MessageLen:         w.MessageLen,
		ChainLen:           w.ChainLen,
		LgChainLen:         w.LgChainLen,
		NumMessageChunks:   w.NumMessageChunks,
		NumChecksumChunks:  w.NumChecksumChunks,
		NumSignatureChunks: w.NumSignatureChunks,
		SignatureSize:      w.SignatureSize,
		PublicKeySize:      w.PublicKeySize,
	}
}

func runCase(name string, chainLen int, privateSeed, publicSeed, message []byte) caseOut {
	w, err := hashsigs.New(hashsigs.Keccak256, hashsigs.WithChainLen(chainLen))
	if err != nil {
		panic(err)
	}

	out := caseOut{
		Name:        name,
		Params:      dumpParams(w),
		PrivateSeed: toHex(privateSeed),
		PublicSeed:  toHex(publicSeed),
		Message:     toHex(message),
	}

	kp, err := w.GenerateKeyPair(privateSeed, publicSeed)
	if err != nil {
		panic(err)
	}
	out.PrivateKey = strPtr(toHex(kp.PrivateKey))
	out.PublicKey = strPtr(toHex(kp.PublicKey))

	randomizationElements := w.GenerateRandomizationElements(publicSeed)
	out.RandomizationElements = hexAll(randomizationElements)

	signature, signErr := w.Sign(kp.PrivateKey, publicSeed, message)
	if signErr != nil {
		out.SignError = errPtr(signErr)
		return out
	}
	out.Signature = hexAll(signature)

	// The TypeScript dump wraps all four verification calls in a single
	// try block, so the first failure leaves the remaining fields null.
	valid, err := w.Verify(kp.PublicKey, message, signature)
	if err != nil {
		out.VerifyError = errPtr(err)
		return out
	}
	out.Verify = boolPtr(valid)

	validWithElements, err := w.VerifyWithRandomizationElements(
		kp.PublicKey[w.HashLen:w.PublicKeySize],
		message,
		signature,
		randomizationElements,
	)
	if err != nil {
		out.VerifyError = errPtr(err)
		return out
	}
	out.VerifyWithElements = boolPtr(validWithElements)

	tampered := make([]byte, len(message))
	copy(tampered, message)
	if len(tampered) > 0 {
		tampered[0] ^= 0xff
	}
	validTampered, err := w.Verify(kp.PublicKey, tampered, signature)
	if err != nil {
		out.VerifyError = errPtr(err)
		return out
	}
	out.VerifyTampered = boolPtr(validTampered)

	empty := make([][]byte, w.NumSignatureChunks)
	for i := range empty {
		empty[i] = make([]byte, w.HashLen)
	}
	validEmpty, err := w.Verify(kp.PublicKey, message, empty)
	if err != nil {
		out.VerifyError = errPtr(err)
		return out
	}
	out.VerifyEmptySignature = boolPtr(validEmpty)

	return out
}

func buildCases() []caseOut {
	var cases []caseOut

	for i := int32(1); i <= 100; i++ {
		message := hashsigs.Keccak256([]byte(fmt.Sprintf("Hello World%d", i)))
		cases = append(cases, runCase(
			fmt.Sprintf("seed%d", i),
			16,
			numberToUint8Array(i),
			numberToUint8Array(i+1),
			message,
		))
	}

	edgeMessages := []struct {
		name    string
		message []byte
	}{
		{"zero", make([]byte, 32)},
		{"ones", filled(32, 0xff)},
		{"ramp1", rampBy(32, 1)},
		{"ramp2", rampBy(32, 2)},
		{"ramp3", rampBy(32, 3)},
		{"ramp4", rampBy(32, 4)},
		{"nibbleHigh", filled(32, 0xf0)},
		{"nibbleLow", filled(32, 0x0f)},
	}
	for _, em := range edgeMessages {
		cases = append(cases, runCase(
			"edge_"+em.name,
			16,
			numberToUint8Array(7),
			numberToUint8Array(9),
			em.message,
		))
	}

	cases = append(cases, runCase("zero_seeds", 16, make([]byte, 32), make([]byte, 32), make([]byte, 32)))
	cases = append(cases, runCase("empty_seeds", 16, []byte{}, []byte{}, make([]byte, 32)))
	cases = append(cases, runCase("short_seeds", 16, []byte{1, 2, 3}, []byte{4, 5}, make([]byte, 32)))
	cases = append(cases, runCase("long_seeds", 16, filled(96, 0xab), filled(80, 0xcd), make([]byte, 32)))
	cases = append(cases, runCase("negative_seed_index", 16, numberToUint8Array(-1), numberToUint8Array(-2), make([]byte, 32)))

	w4Messages := []struct {
		name    string
		message []byte
	}{
		{"zero", make([]byte, 32)},
		{"ramp1", rampBy(32, 1)},
		{"lowNibbles", filled(32, 0x03)},
	}
	for _, em := range w4Messages {
		cases = append(cases, runCase(
			"w4_"+em.name,
			4,
			numberToUint8Array(11),
			numberToUint8Array(12),
			em.message,
		))
	}

	return cases
}

func buildConstructorCases() []constructorCase {
	specs := []struct {
		name     string
		hashLen  int
		useHash  bool
		chainLen int
	}{
		{"default", 0, false, 16},
		{"w4", 0, false, 4},
		{"hashLen64", 64, true, 16},
		{"hashLen1", 1, true, 16},
		{"hashLen0", 0, true, 16},
		{"hashLenNegative", -8, true, 16},
		{"chainLen3", 0, false, 3},
		{"chainLen8", 0, false, 8},
		{"chainLen32", 0, false, 32},
		{"chainLen0", 0, false, 0},
		{"chainLen3AndHashLen0", 0, true, 3},
		{"chainLen8AndHashLen0", 0, true, 8},
	}

	out := make([]constructorCase, 0, len(specs))
	for _, spec := range specs {
		opts := []hashsigs.Option{hashsigs.WithChainLen(spec.chainLen)}
		if spec.useHash {
			opts = append(opts, hashsigs.WithHashLen(spec.hashLen))
		}
		w, err := hashsigs.New(hashsigs.Keccak256, opts...)
		if err != nil {
			out = append(out, constructorCase{Name: spec.name, Error: errPtr(err)})
			continue
		}
		out = append(out, constructorCase{Name: spec.name, Params: dumpParams(w)})
	}
	return out
}

func buildValidationCases() []validationCase {
	w, err := hashsigs.New(hashsigs.Keccak256)
	if err != nil {
		panic(err)
	}
	publicSeed := numberToUint8Array(2)
	kp, err := w.GenerateKeyPair(numberToUint8Array(1), publicSeed)
	if err != nil {
		panic(err)
	}
	message := rampBy(32, 1)
	signature, err := w.Sign(kp.PrivateKey, publicSeed, message)
	if err != nil {
		panic(err)
	}
	elements := w.GenerateRandomizationElements(publicSeed)

	var out []validationCase
	record := func(name string, result any, err error) {
		if err != nil {
			out = append(out, validationCase{Name: name, Error: errPtr(err)})
			return
		}
		out = append(out, validationCase{Name: name, Result: result})
	}
	recordSign := func(name string, privateKey, message []byte) {
		sig, err := w.Sign(privateKey, publicSeed, message)
		if err != nil {
			record(name, nil, err)
			return
		}
		record(name, hexAll(sig), nil)
	}
	recordVerify := func(name string, publicKey, message []byte, sig [][]byte) {
		ok, err := w.Verify(publicKey, message, sig)
		if err != nil {
			record(name, nil, err)
			return
		}
		record(name, ok, nil)
	}
	recordVerifyElements := func(name string, publicKeyHash, message []byte, sig [][]byte) {
		ok, err := w.VerifyWithRandomizationElements(publicKeyHash, message, sig, elements)
		if err != nil {
			record(name, nil, err)
			return
		}
		record(name, ok, nil)
	}

	publicKeyHash := kp.PublicKey[32:64]

	recordSign("sign_short_private_key", kp.PrivateKey[:31], message)
	recordSign("sign_long_private_key", make([]byte, 33), message)
	recordSign("sign_short_message", kp.PrivateKey, message[:31])
	recordSign("sign_long_message", kp.PrivateKey, make([]byte, 64))
	recordSign("sign_both_invalid", make([]byte, 31), make([]byte, 31))
	recordVerify("verify_short_public_key", kp.PublicKey[:63], message, signature)
	recordVerify("verify_long_public_key", make([]byte, 65), message, signature)
	recordVerifyElements("verify_elements_short_hash", make([]byte, 31), message, signature)
	recordVerifyElements("verify_elements_short_message", publicKeyHash, make([]byte, 16), signature)
	recordVerifyElements("verify_elements_short_signature", publicKeyHash, message, signature[:66])
	recordVerifyElements("verify_elements_long_signature", publicKeyHash, message,
		append(append([][]byte{}, signature...), make([]byte, 32)))
	recordVerifyElements("verify_elements_all_invalid", make([]byte, 31), make([]byte, 16), signature[:2])

	return out
}

// Build assembles the full parity document.
func Build() Document {
	return Document{
		Cases:            buildCases(),
		ConstructorCases: buildConstructorCases(),
		ValidationCases:  buildValidationCases(),
	}
}

// Encode writes doc exactly as JSON.stringify(doc, null, 2) would, including
// the trailing newline, so the output can be diffed against ts_dump.mjs.
func Encode(w io.Writer, doc Document) error {
	enc := json.NewEncoder(w)
	// JSON.stringify does not escape HTML characters; Go does by default.
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}
