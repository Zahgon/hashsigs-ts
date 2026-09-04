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

// Package hashsigs implements hash-based signatures, featuring WOTS+
// (Winternitz One-Time Signature Plus).
//
// This package is a behavior-preserving port of the TypeScript reference
// implementation at https://github.com/quipnetwork/hashsigs-ts. It is
// byte-for-byte compatible with that implementation: for identical inputs it
// produces identical private keys, public keys, randomization elements,
// signatures and verification results.
//
// The hash function is injected by the caller, mirroring the TypeScript
// constructor. The canonical instantiation uses keccak256:
//
//	w, err := hashsigs.New(hashsigs.Keccak256)
//	if err != nil {
//	    return err
//	}
//	kp, err := w.GenerateKeyPair(privateSeed, publicSeed)
//	if err != nil {
//	    return err
//	}
//	sig, err := w.Sign(kp.PrivateKey, publicSeed, messageHash)
//	if err != nil {
//	    return err
//	}
//	ok, err := w.Verify(kp.PublicKey, messageHash, sig)
//
// WOTS+ is a one-time signature scheme: a given private key must be used to
// sign at most one message. Signing two different messages with the same key
// allows an attacker to forge signatures.
//
// Comments marked "PARITY:" document places where this port intentionally
// reproduces behavior of the TypeScript original that would otherwise look
// like a bug. See the "Differences from the TypeScript original" section of
// the README for the complete list.
package hashsigs
