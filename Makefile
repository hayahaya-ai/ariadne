PROJECT ?= ariadne-prove
ROOT_BIN ?= bin/ariadne
GOCACHE ?= /private/tmp/ariadne-gocache

.PHONY: check fmt test vet build root-build product-build verify-first-run stories inventory prove assess scan clean

check: fmt vet test build

fmt:
	test -z "$$(gofmt -l cmd)"
	$(MAKE) -C $(PROJECT) fmt

test:
	GOCACHE=$(GOCACHE) go test ./cmd/ariadne
	$(MAKE) -C $(PROJECT) test

vet:
	GOCACHE=$(GOCACHE) go vet ./cmd/ariadne
	$(MAKE) -C $(PROJECT) vet

build: product-build root-build

product-build:
	$(MAKE) -C $(PROJECT) build

root-build:
	mkdir -p bin
	GOCACHE=$(GOCACHE) go build -o $(ROOT_BIN) ./cmd/ariadne

verify-first-run: build
	ARIADNE_BIN=$(ROOT_BIN) bash scripts/verify-first-run.sh

stories: build
	$(ROOT_BIN) stories list

inventory: build
	$(ROOT_BIN) inventory --path $(PROJECT)/testdata/realpath/messy-ai-surfaces

prove: build
	$(ROOT_BIN) prove --path $(PROJECT)/testdata/realpath/combined-risk

assess: build
	$(ROOT_BIN) assess --path $(PROJECT)/testdata/realpath/combined-risk --format action

scan: build
	$(ROOT_BIN) scan --targets $(PROJECT)/testdata/realpath/targets.txt

clean:
	$(MAKE) -C $(PROJECT) clean
	rm -rf bin
