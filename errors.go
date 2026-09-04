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

import "errors"

// Every error below corresponds to a `throw` in the TypeScript original. The
// rendered message of each error is character-for-character identical to the
// message of the TypeScript Error it replaces, so that behavior (including
// diagnostics) is preserved across the port.
var (
	// ErrChainLenNotPowerOfTwo mirrors: throw new Error("ChainLen must be a power of 2")
	ErrChainLenNotPowerOfTwo = errors.New("ChainLen must be a power of 2")

	// ErrHashLenNotPositive mirrors: throw new Error("HashLen must be positive")
	ErrHashLenNotPositive = errors.New("HashLen must be positive")

	// ErrChainLenUnsupported mirrors:
	// throw new Error("ChainLen must be either 4 or 16 for XMSS compatibility")
	ErrChainLenUnsupported = errors.New("ChainLen must be either 4 or 16 for XMSS compatibility")

	// ErrChainOverflow mirrors:
	// throw new Error("steps + index must be less than ChainLen")
	ErrChainOverflow = errors.New("steps + index must be less than ChainLen")

	// ErrUnequalLength mirrors: throw new Error('Arrays must have equal length')
	ErrUnequalLength = errors.New("Arrays must have equal length")

	// ErrInvalidPrivateKeyLen mirrors:
	// throw new Error(`private key length must be ${this.hashLen} bytes`)
	ErrInvalidPrivateKeyLen = errors.New("invalid private key length")

	// ErrInvalidMessageLen mirrors:
	// throw new Error(`message length must be ${this.messageLen} bytes`)
	ErrInvalidMessageLen = errors.New("invalid message length")

	// ErrInvalidPublicKeyLen mirrors:
	// throw new Error(`public key length must be ${this.publicKeySize} bytes`)
	ErrInvalidPublicKeyLen = errors.New("invalid public key length")

	// ErrInvalidPublicKeyHashLen mirrors:
	// throw new Error(`public key hash length must be ${this.hashLen} bytes`)
	ErrInvalidPublicKeyHashLen = errors.New("invalid public key hash length")

	// ErrInvalidSignatureLen mirrors:
	// throw new Error(`signature length must be ${this.numSignatureChunks}`)
	ErrInvalidSignatureLen = errors.New("invalid signature length")

	// ErrNilHashFunction is returned by New when no hash function is supplied.
	//
	// DIVERGENCE: the TypeScript constructor accepts any value and fails later
	// with a TypeError on the first hash invocation. Go would panic on a nil
	// func call, so the condition is detected eagerly instead. Both
	// implementations reject the same inputs; only the timing differs.
	ErrNilHashFunction = errors.New("hash function must not be nil")

	// ErrSegmentOffsetOutOfBounds mirrors the RangeError thrown by
	// `Uint8Array.prototype.set` when the source does not fit at the
	// requested offset. It is reachable only with over-long signature
	// chunks in the final chain position.
	ErrSegmentOffsetOutOfBounds = errors.New("offset is out of bounds")

	// ErrMissingRandomizationElement is returned when the randomization
	// element slice is too short for the requested chain walk.
	//
	// DIVERGENCE: the TypeScript original indexes past the end of the array,
	// yielding `undefined`, and then throws a TypeError from `xor` when it
	// reads `.length` of `undefined`. Go would panic on the out-of-range
	// index, so an explicit error is returned instead. Both implementations
	// reject the same inputs.
	ErrMissingRandomizationElement = errors.New("randomization element index out of range")
)

// errStringf renders a message identical to the TypeScript template literal
// while keeping the sentinel wrapped for errors.Is.
type wrappedError struct {
	msg string
	err error
}

func (e *wrappedError) Error() string { return e.msg }
func (e *wrappedError) Unwrap() error { return e.err }
