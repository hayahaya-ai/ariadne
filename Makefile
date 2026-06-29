PROJECT ?= ariadne-prove
BIN ?= $(PROJECT)/bin/ariadne
GOCACHE ?= /private/tmp/ariadne-gocache

.PHONY: check fmt test vet build stories inventory prove scan clean

check:
	$(MAKE) -C $(PROJECT) check

fmt:
	$(MAKE) -C $(PROJECT) fmt

test:
	$(MAKE) -C $(PROJECT) test

vet:
	$(MAKE) -C $(PROJECT) vet

build:
	$(MAKE) -C $(PROJECT) build

stories:
	$(MAKE) -C $(PROJECT) stories

inventory:
	cd $(PROJECT) && GOCACHE=$(GOCACHE) go run ./cmd/ariadne inventory --path testdata/realpath/messy-ai-surfaces

prove:
	cd $(PROJECT) && GOCACHE=$(GOCACHE) go run ./cmd/ariadne prove --path testdata/realpath/combined-risk

scan:
	$(MAKE) -C $(PROJECT) scan

clean:
	$(MAKE) -C $(PROJECT) clean
