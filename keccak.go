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

import "golang.org/x/crypto/sha3"

// Keccak256 is a HashFunction using legacy Keccak-256, the variant used by
// Ethereum. It matches `keccak_256` from @noble/hashes/sha3, the hash the
// TypeScript original is instantiated with and the one the committed test
// vectors were produced with.
//
// This is NOT SHA3-256: the two differ in their padding rule and produce
// different digests.
//
// A fresh hash state is allocated per call, so Keccak256 is safe for
// concurrent use.
func Keccak256(data []byte) []byte {
	h := sha3.NewLegacyKeccak256()
	h.Write(data)
	return h.Sum(nil)
}
