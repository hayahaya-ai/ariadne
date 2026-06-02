BIN ?= bin/ariadne
GOCACHE ?= /private/tmp/ariadne-gocache

.PHONY: test build doctor scan-fixture clean

test:
	GOCACHE=$(GOCACHE) go test ./...

build:
	mkdir -p bin
	GOCACHE=$(GOCACHE) go build -o $(BIN) ./cmd/ariadne

doctor:
	GOCACHE=$(GOCACHE) go run ./cmd/ariadne doctor --mode endpoint

scan-fixture:
	GOCACHE=$(GOCACHE) go run ./cmd/ariadne scan --mode repo --path testdata/fixtures/unsafe-codex

clean:
	rm -rf bin coverage.out report.json report.md ariadne.sarif
