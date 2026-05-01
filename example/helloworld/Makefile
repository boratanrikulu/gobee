# helloworld — gobee end-to-end demo
#
# Pipeline:
#   1. gobee translate ./bpf/src    → bpf/src/counter.bpf.c + bpf/counter_bindings.go
#   2. make -C bpf/src bpf-all      → bpf/bin/<arch>/counter.bpf.o
#   3. go build .                   → ./helloworld (bpf package embeds the .o)

BIN := helloworld

# Resolve `gobee` the way a real user would: from $PATH after a
# `go install github.com/boratanrikulu/gobee/cmd/gobee@latest`. Inside
# this repo, `make` installs from the local source tree first so dev
# edits land instantly. `go install` builds for the host OS+arch, which
# avoids the macOS/lima binary-mismatch trap.
#
# We prefer a $PATH lookup, then fall back to $GOBIN / $GOPATH/bin
# (where `go install` actually wrote the binary).
GOBIN := $(or $(shell go env GOBIN),$(shell go env GOPATH)/bin)
GOBEE := $(or $(shell command -v gobee 2>/dev/null),$(GOBIN)/gobee)

.PHONY: all build translate compile clean install-gobee

all: build

install-gobee:
	@command -v gobee >/dev/null 2>&1 || { echo "==> installing gobee from ../.."; cd ../.. && go install ./cmd/gobee; }

translate: install-gobee
	$(GOBEE) translate --bindings-dir ./bpf ./bpf/src

compile: translate
	$(MAKE) -C bpf/src bpf-all

build: compile
	go build -o $(BIN) .

clean:
	$(MAKE) -C bpf/src bpf-clean
	@rm -f $(BIN) bpf/src/counter.bpf.c bpf/src/counter.bpf.c.map bpf/counter_bindings.go
