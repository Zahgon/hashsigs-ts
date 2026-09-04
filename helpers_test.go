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
	"encoding/hex"
	"strings"
	"testing"
)

// numberTo32Bytes ports the numberToUint8Array helper of wotsplus.test.ts.
// The shift is performed on int32 because JavaScript's `>>` is a signed 32
// bit operation.
func numberTo32Bytes(num int32) []byte {
	arr := make([]byte, 32)
	for i := 0; i < 32; i++ {
		arr[31-i] = byte(num & 0xff)
		num >>= 8
	}
	return arr
}

// hexToBytes ports the hexToUint8Array helper of wotsplus.test.ts.
//
// DIVERGENCE (test helper only, the library is unaffected): the TypeScript
// helper silently turns malformed hex into zero bytes via parseInt returning
// NaN, which would mask a corrupted fixture. This one fails the test instead.
func hexToBytes(t *testing.T, s string) []byte {
	t.Helper()
	s = strings.TrimPrefix(s, "0x")
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("invalid hex %q: %v", s, err)
	}
	return b
}

func hexToChunks(t *testing.T, in []string) [][]byte {
	t.Helper()
	out := make([][]byte, len(in))
	for i, s := range in {
		out[i] = hexToBytes(t, s)
	}
	return out
}

// newDefault builds the `new WOTSPlus(keccak_256)` instance used by every
// test in wotsplus.test.ts.
func newDefault(t *testing.T) *WOTSPlus {
	t.Helper()
	w, err := New(Keccak256)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return w
}

// rampMessage builds the `message[i] = i` test message of wotsplus.test.ts.
func rampMessage(n int) []byte {
	msg := make([]byte, n)
	for i := range msg {
		msg[i] = byte(i)
	}
	return msg
}
