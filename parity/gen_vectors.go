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

// Command gen_vectors dumps the observable behavior of the Go port for the
// same inputs as parity/ts_dump.mjs, in the same JSON document shape and the
// same order, so that the two outputs can be compared byte for byte.
//
// Usage: go run ./parity > out.json
package main

import (
	"fmt"
	"os"

	"github.com/quipnetwork/hashsigs-go/internal/paritydump"
)

func main() {
	if err := paritydump.Encode(os.Stdout, paritydump.Build()); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
