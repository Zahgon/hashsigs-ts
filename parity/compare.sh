#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024 quip.network
#
# Differential test against the TypeScript original.
#
# Runs the TypeScript implementation and the Go port over the same inputs and
# requires the two JSON dumps to be byte identical. Any behavioral difference
# - a digest, a boolean, a derived parameter or an error message - shows up as
# a diff.
#
# Usage: parity/compare.sh [path-to-hashsigs-ts-repo]
#
# Requires Node >= 22.6 (for TypeScript type stripping) and the TypeScript
# repo's node_modules to be installed.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ts_repo="${1:-${HASHSIGS_TS_REPO:-}}"

if [[ -z "${ts_repo}" ]]; then
  echo "usage: parity/compare.sh <path-to-hashsigs-ts-repo>" >&2
  echo "   or: HASHSIGS_TS_REPO=<path> parity/compare.sh" >&2
  exit 2
fi

if [[ ! -f "${ts_repo}/src/wotsplus.ts" ]]; then
  echo "error: ${ts_repo}/src/wotsplus.ts not found" >&2
  exit 2
fi

if [[ ! -d "${ts_repo}/node_modules/@noble/hashes" ]]; then
  echo "error: @noble/hashes not installed in ${ts_repo}; run 'npm install' there" >&2
  exit 2
fi

workdir="$(mktemp -d)"
trap 'rm -rf "${workdir}"' EXIT

echo "==> dumping TypeScript behavior"
node "${repo_root}/parity/ts_dump.mjs" "${ts_repo}" >"${workdir}/ts.json"

echo "==> dumping Go behavior"
(cd "${repo_root}" && go run ./parity) >"${workdir}/go.json"

echo "==> comparing"
if diff -u "${workdir}/ts.json" "${workdir}/go.json" >"${workdir}/diff.txt"; then
  cases=$(grep -c '"name":' "${workdir}/ts.json")
  bytes=$(wc -c <"${workdir}/ts.json" | tr -d ' ')
  echo "PASS: outputs are byte identical (${cases} cases, ${bytes} bytes)"
else
  echo "FAIL: the Go port diverges from the TypeScript original" >&2
  head -n 100 "${workdir}/diff.txt" >&2
  exit 1
fi
