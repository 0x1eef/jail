GO ?= go

fmt:
	$(GO) fmt ./...

build:
	$(GO) build -o bin/jls ./cmd/jls

test:
	$(GO) test test/root/*

release:
	ci/release ${REL}

.PHONY: test release
