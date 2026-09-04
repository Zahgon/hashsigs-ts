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

// Dumps the observable behavior of the TypeScript implementation for a fixed
// set of inputs. parity/gen_vectors.go produces the same document from the Go
// port and parity/compare.sh diffs the two.
//
// Usage: node ts_dump.mjs <path-to-hashsigs-ts-repo> > out.json
//
// Requires Node >= 22.6 (TypeScript type stripping) and the TypeScript repo's
// node_modules to be installed.

import { pathToFileURL } from "node:url";
import { resolve } from "node:path";

const repo = process.argv[2];
if (!repo) {
  console.error("usage: node ts_dump.mjs <path-to-hashsigs-ts-repo>");
  process.exit(2);
}

const { WOTSPlus } = await import(
  pathToFileURL(resolve(repo, "src/wotsplus.ts")).href
);
const { keccak_256 } = await import(
  pathToFileURL(resolve(repo, "node_modules/@noble/hashes/sha3.js")).href
);

const hex = (u8) =>
  "0x" +
  Array.from(u8)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

const hexAll = (arr) => arr.map(hex);

// Ported verbatim from the numberToUint8Array helper in wotsplus.test.ts.
const numberToUint8Array = (num) => {
  const arr = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    arr[31 - i] = num & 0xff;
    num = num >> 8;
  }
  return arr;
};

const params = (w) => ({
  hashLen: w.hashLen,
  messageLen: w.messageLen,
  chainLen: w.chainLen,
  lgChainLen: w.lgChainLen,
  numMessageChunks: w.numMessageChunks,
  numChecksumChunks: w.numChecksumChunks,
  numSignatureChunks: w.numSignatureChunks,
  signatureSize: w.signatureSize,
  publicKeySize: w.publicKeySize,
});

const errMessage = (e) => (e instanceof Error ? e.message : String(e));

function runCase(name, chainLen, privateSeed, publicSeed, message) {
  const w = new WOTSPlus(keccak_256, undefined, chainLen);
  const out = {
    name,
    params: params(w),
    privateSeed: hex(privateSeed),
    publicSeed: hex(publicSeed),
    message: hex(message),
    privateKey: null,
    publicKey: null,
    randomizationElements: null,
    signature: null,
    signError: null,
    verify: null,
    verifyError: null,
    verifyWithElements: null,
    verifyTampered: null,
    verifyEmptySignature: null,
  };

  const { publicKey, privateKey } = w.generateKeyPair(privateSeed, publicSeed);
  out.privateKey = hex(privateKey);
  out.publicKey = hex(publicKey);

  const randomizationElements = w.generateRandomizationElements(publicSeed);
  out.randomizationElements = hexAll(randomizationElements);

  let signature = null;
  try {
    signature = w.sign(privateKey, publicSeed, message);
    out.signature = hexAll(signature);
  } catch (e) {
    out.signError = errMessage(e);
  }

  if (signature !== null) {
    try {
      out.verify = w.verify(publicKey, message, signature);
      out.verifyWithElements = w.verifyWithRandomizationElements(
        publicKey.slice(w.hashLen, w.publicKeySize),
        message,
        signature,
        randomizationElements,
      );

      const tampered = new Uint8Array(message);
      tampered[0] ^= 0xff;
      out.verifyTampered = w.verify(publicKey, tampered, signature);

      const empty = Array.from({ length: w.numSignatureChunks }, () =>
        new Uint8Array(w.hashLen),
      );
      out.verifyEmptySignature = w.verify(publicKey, message, empty);
    } catch (e) {
      out.verifyError = errMessage(e);
    }
  }

  return out;
}

const cases = [];

// Round trips over many seeds, mirroring the "many signatures" test.
for (let i = 1; i <= 100; i++) {
  const message = keccak_256(new TextEncoder().encode(`Hello World${i}`));
  cases.push(
    runCase(
      `seed${i}`,
      16,
      numberToUint8Array(i),
      numberToUint8Array(i + 1),
      message,
    ),
  );
}

// Edge case messages, including the ones used by the committed fixtures.
const edgeMessages = {
  zero: new Uint8Array(32),
  ones: new Uint8Array(32).fill(0xff),
  ramp1: Uint8Array.from({ length: 32 }, (_, i) => i),
  ramp2: Uint8Array.from({ length: 32 }, (_, i) => (i * 2) & 0xff),
  ramp3: Uint8Array.from({ length: 32 }, (_, i) => (i * 3) & 0xff),
  ramp4: Uint8Array.from({ length: 32 }, (_, i) => (i * 4) & 0xff),
  nibbleHigh: Uint8Array.from({ length: 32 }, () => 0xf0),
  nibbleLow: Uint8Array.from({ length: 32 }, () => 0x0f),
};
for (const [name, message] of Object.entries(edgeMessages)) {
  cases.push(
    runCase(
      `edge_${name}`,
      16,
      numberToUint8Array(7),
      numberToUint8Array(9),
      message,
    ),
  );
}

// Degenerate seeds: the original performs no seed length validation.
cases.push(
  runCase("zero_seeds", 16, new Uint8Array(32), new Uint8Array(32), new Uint8Array(32)),
);
cases.push(
  runCase("empty_seeds", 16, new Uint8Array(0), new Uint8Array(0), new Uint8Array(32)),
);
cases.push(
  runCase(
    "short_seeds",
    16,
    Uint8Array.from([1, 2, 3]),
    Uint8Array.from([4, 5]),
    new Uint8Array(32),
  ),
);
cases.push(
  runCase(
    "long_seeds",
    16,
    new Uint8Array(96).fill(0xab),
    new Uint8Array(80).fill(0xcd),
    new Uint8Array(32),
  ),
);
cases.push(
  runCase(
    "negative_seed_index",
    16,
    numberToUint8Array(-1),
    numberToUint8Array(-2),
    new Uint8Array(32),
  ),
);

// ChainLen = 4 exercises the hardcoded base-16 toBaseW and the resulting
// out-of-range chain indexes.
for (const [name, message] of Object.entries({
  zero: new Uint8Array(32),
  ramp1: Uint8Array.from({ length: 32 }, (_, i) => i),
  lowNibbles: Uint8Array.from({ length: 32 }, () => 0x03),
})) {
  cases.push(
    runCase(
      `w4_${name}`,
      4,
      numberToUint8Array(11),
      numberToUint8Array(12),
      message,
    ),
  );
}

// Constructor rejections.
const constructorCases = [];
for (const [name, hashLen, chainLen] of [
  ["default", undefined, 16],
  ["w4", undefined, 4],
  ["hashLen64", 64, 16],
  ["hashLen1", 1, 16],
  ["hashLen0", 0, 16],
  ["hashLenNegative", -8, 16],
  ["chainLen3", undefined, 3],
  ["chainLen8", undefined, 8],
  ["chainLen32", undefined, 32],
  ["chainLen0", undefined, 0],
  ["chainLen3AndHashLen0", 0, 3],
  ["chainLen8AndHashLen0", 0, 8],
]) {
  try {
    const w = new WOTSPlus(keccak_256, hashLen, chainLen);
    constructorCases.push({ name, error: null, params: params(w) });
  } catch (e) {
    constructorCases.push({ name, error: errMessage(e), params: null });
  }
}

// Argument validation on the signing and verification entry points.
const validationCases = [];
{
  const w = new WOTSPlus(keccak_256);
  const publicSeed = numberToUint8Array(2);
  const { publicKey, privateKey } = w.generateKeyPair(
    numberToUint8Array(1),
    publicSeed,
  );
  const message = Uint8Array.from({ length: 32 }, (_, i) => i);
  const signature = w.sign(privateKey, publicSeed, message);
  const elements = w.generateRandomizationElements(publicSeed);
  const record = (name, fn) => {
    try {
      validationCases.push({ name, error: null, result: fn() });
    } catch (e) {
      validationCases.push({ name, error: errMessage(e), result: null });
    }
  };

  record("sign_short_private_key", () =>
    hexAll(w.sign(privateKey.slice(0, 31), publicSeed, message)),
  );
  record("sign_long_private_key", () =>
    hexAll(w.sign(new Uint8Array(33), publicSeed, message)),
  );
  record("sign_short_message", () =>
    hexAll(w.sign(privateKey, publicSeed, message.slice(0, 31))),
  );
  record("sign_long_message", () =>
    hexAll(w.sign(privateKey, publicSeed, new Uint8Array(64))),
  );
  record("sign_both_invalid", () =>
    hexAll(w.sign(new Uint8Array(31), publicSeed, new Uint8Array(31))),
  );
  record("verify_short_public_key", () =>
    w.verify(publicKey.slice(0, 63), message, signature),
  );
  record("verify_long_public_key", () =>
    w.verify(new Uint8Array(65), message, signature),
  );
  record("verify_elements_short_hash", () =>
    w.verifyWithRandomizationElements(
      new Uint8Array(31),
      message,
      signature,
      elements,
    ),
  );
  record("verify_elements_short_message", () =>
    w.verifyWithRandomizationElements(
      publicKey.slice(32, 64),
      new Uint8Array(16),
      signature,
      elements,
    ),
  );
  record("verify_elements_short_signature", () =>
    w.verifyWithRandomizationElements(
      publicKey.slice(32, 64),
      message,
      signature.slice(0, 66),
      elements,
    ),
  );
  record("verify_elements_long_signature", () =>
    w.verifyWithRandomizationElements(
      publicKey.slice(32, 64),
      message,
      [...signature, new Uint8Array(32)],
      elements,
    ),
  );
  record("verify_elements_all_invalid", () =>
    w.verifyWithRandomizationElements(
      new Uint8Array(31),
      new Uint8Array(16),
      signature.slice(0, 2),
      elements,
    ),
  );
}

process.stdout.write(
  JSON.stringify({ cases, constructorCases, validationCases }, null, 2) + "\n",
);
