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

// toBaseW converts a message to base-w representation (or base of ChainLen
// representation). These numbers are used to index into each hash chain which
// is rooted at a secret key segment and produces a public key segment at the
// end of the chain. Verification of a signature means using these index into
// each hash chain to recompute the corresponding public key segment.
//
// PARITY: the TypeScript implementation is hardcoded to base 16 (it always
// splits a byte into two nibbles via `>> 4` and `& 0xF`) and ignores
// ChainLen. That is reproduced verbatim, so a ChainLen of 4 produces the same
// non-spec-conforming output here as it does there.
//
// PARITY: when numChunks requires more bytes than the message holds, the
// TypeScript implementation reads `undefined` and the bitwise operators
// coerce it to 0 (ToInt32(NaN) == 0). Reads past the end of the message
// therefore contribute 0 here as well, rather than panicking. This is
// reachable with ChainLen == 4, where numChunks is 128 for a 32 byte message.
func (w *WOTSPlus) toBaseW(
	message []byte,
	numChunks int,
	basew []int,
	offset int,
) {
	index := 0
	for i := 0; i < numChunks; i++ {
		var b byte
		if index < len(message) {
			b = message[index]
		}
		if i%2 == 0 {
			basew[offset+i] = int((b >> 4) & 0xF)
		} else {
			basew[offset+i] = int(b & 0xF)
			index++
		}
	}
}

// checksum computes the checksum for the chain indexes, appending it in
// base-w representation starting at NumMessageChunks. It mutates
// chainIndexes in place, as the TypeScript original does.
func (w *WOTSPlus) checksum(chainIndexes []int) {
	sum := 0
	// Sum up the first NUM_MESSAGE_CHUNKS elements
	for i := 0; i < w.NumMessageChunks; i++ {
		sum += w.ChainLen - 1 - chainIndexes[i]
	}

	// Convert checksum to base-w representation
	// Start filling from NUM_MESSAGE_CHUNKS position
	for i := 0; i < w.NumChecksumChunks; i++ {
		// PARITY: JavaScript's `>>` is a signed 32 bit shift whose count is
		// the operand converted with ToUint32 and masked to 5 bits. The
		// shift count is computed in floating point there because
		// lgChainLen is a float; both steps are reproduced exactly.
		shift := uint32(float64(w.NumChecksumChunks-1-i)*w.LgChainLen) & 31
		chainIndexes[w.NumMessageChunks+i] = int(int32(sum)>>shift) & (w.ChainLen - 1)
	}
}

// computeMessageHashChainIndexes computes the message hash chain indexes.
// We convert the message to base-w representation (or base of ChainLen
// representation). We attach the checksum, also in base-w representation, to
// the end of the hash chain index list.
func (w *WOTSPlus) computeMessageHashChainIndexes(message []byte) []int {
	chainIndexes := make([]int, w.NumMessageChunks+w.NumChecksumChunks)

	// Convert message to base-w representation
	w.toBaseW(message, w.NumMessageChunks, chainIndexes, 0)

	// Compute and add checksum
	w.checksum(chainIndexes)

	return chainIndexes
}
