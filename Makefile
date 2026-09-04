.DEFAULT_GOAL := check

COVER_THRESHOLD := 80
FUZZTIME ?= 30s

.PHONY: check
check: lint test cover

.PHONY: build
build:
	go build ./...

.PHONY: test
test:
	go test -race ./...

# Coverage is measured over the library and its internal packages. The `parity`
# package is a `main` shim invoked by parity/compare.sh, not library code.
.PHONY: cover
cover:
	go test -coverprofile=coverage.out -covermode=atomic -coverpkg=./,./internal/... .
	go tool cover -html=coverage.out -o coverage.html
	@go tool cover -func=coverage.out | awk -v threshold=$(COVER_THRESHOLD) '\
		/^total:/ { \
			gsub("%", "", $$3); \
			printf "total coverage: %.1f%% (threshold %d%%)\n", $$3, threshold; \
			if ($$3 + 0 < threshold) { print "coverage below threshold"; exit 1 } \
		}'

.PHONY: lint
lint:
	@gofmt -l . | grep . && { echo "gofmt found unformatted files"; exit 1; } || echo "gofmt: clean"
	go vet ./...

.PHONY: fuzz
fuzz:
	go test -run XXX -fuzz FuzzRoundTrip -fuzztime $(FUZZTIME) .
	go test -run XXX -fuzz FuzzVerifyDoesNotPanic -fuzztime $(FUZZTIME) .

.PHONY: bench
bench:
	go test -run XXX -bench . -benchmem ./...

# Differential comparison against the TypeScript implementation.
# Requires Node.js >= 22.6 and HASHSIGS_TS_REPO pointing at a hashsigs-ts checkout.
.PHONY: parity
parity:
	./parity/compare.sh

# Refresh the committed golden parity document from the TypeScript implementation.
.PHONY: parity-update
parity-update:
	node parity/ts_dump.mjs > testdata/parity_ts.json
	go run ./parity | diff -u testdata/parity_ts.json - && echo "golden updated and verified"

.PHONY: clean
clean:
	rm -f coverage.out coverage.html
	go clean -testcache
