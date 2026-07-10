BIN ?= bin/ariadne
GOCACHE ?= /private/tmp/ariadne-prove-gocache

.PHONY: check fmt test vet build eval stories prove scan clean

check: fmt vet test build

fmt:
	test -z "$$(gofmt -l cmd internal)"

test:
	GOCACHE=$(GOCACHE) go test ./...

vet:
	GOCACHE=$(GOCACHE) go vet ./...

build:
	mkdir -p bin
	GOCACHE=$(GOCACHE) go build -o $(BIN) ./cmd/ariadne

eval:
	GOCACHE=$(GOCACHE) go run ./cmd/ariadne eval

stories:
	GOCACHE=$(GOCACHE) go run ./cmd/ariadne stories list

prove:
	GOCACHE=$(GOCACHE) go run ./cmd/ariadne prove --story local-agent-secret-exposed

scan:
	GOCACHE=$(GOCACHE) go run ./cmd/ariadne scan --targets testdata/realpath/targets.txt

clean:
	rm -rf bin coverage.out
