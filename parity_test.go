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

// This is an external test package so that it can import internal/paritydump,
// which itself imports the library under test.

package hashsigs_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/quipnetwork/hashsigs-go/internal/paritydump"
)

// goldenPath holds the output of parity/ts_dump.mjs run against the
// TypeScript original. Committing it lets the equivalence claim be checked
// offline, without Node or the TypeScript repository.
const goldenPath = "testdata/parity_ts.json"

func goDump(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := paritydump.Encode(&buf, paritydump.Build()); err != nil {
		t.Fatalf("encode parity dump: %v", err)
	}
	return buf.Bytes()
}

// TestParityAgainstTypeScriptGolden is the primary equivalence gate: the Go
// port must reproduce the recorded behavior of the TypeScript original byte
// for byte, across key generation, signing, verification, derived parameters
// and error messages.
func TestParityAgainstTypeScriptGolden(t *testing.T) {
	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read %s: %v", goldenPath, err)
	}

	got := goDump(t)
	if bytes.Equal(got, want) {
		return
	}

	failed := filepath.Join(t.TempDir(), "go_parity.json")
	if writeErr := os.WriteFile(failed, got, 0o644); writeErr != nil {
		t.Logf("could not save the Go dump: %v", writeErr)
	}
	t.Fatalf("Go behavior diverges from the recorded TypeScript behavior.\n"+
		"Go dump written to %s\nCompare with: diff %s %s", failed, goldenPath, failed)
}

// TestParityAgainstLiveTypeScript regenerates the golden file from the real
// TypeScript sources. It is skipped unless HASHSIGS_TS_REPO points at a
// checkout of hashsigs-ts with node_modules installed, and Node is on PATH.
func TestParityAgainstLiveTypeScript(t *testing.T) {
	tsRepo := os.Getenv("HASHSIGS_TS_REPO")
	if tsRepo == "" {
		t.Skip("HASHSIGS_TS_REPO is not set; skipping the live differential test")
	}
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not installed; skipping the live differential test")
	}
	if _, err := os.Stat(filepath.Join(tsRepo, "src/wotsplus.ts")); err != nil {
		t.Skipf("%s does not look like a hashsigs-ts checkout: %v", tsRepo, err)
	}

	cmd := exec.Command(node, "parity/ts_dump.mjs", tsRepo)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("ts_dump.mjs failed: %v\n%s", err, stderr.String())
	}

	if !bytes.Equal(goDump(t), stdout.Bytes()) {
		t.Fatal("Go behavior diverges from the live TypeScript implementation; run parity/compare.sh for a diff")
	}

	golden, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read %s: %v", goldenPath, err)
	}
	if !bytes.Equal(golden, stdout.Bytes()) {
		t.Errorf("%s is stale; regenerate it with: node parity/ts_dump.mjs %s > %s", goldenPath, tsRepo, goldenPath)
	}
}
