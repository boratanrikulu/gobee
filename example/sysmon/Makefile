BIN := sysmon

# Resolve `gobee` from $PATH; install from local source if missing.
# See example/helloworld/Makefile for the full rationale.
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
	@rm -f $(BIN) bpf/src/sysmon.bpf.c bpf/src/sysmon.bpf.c.map bpf/sysmon_bindings.go
