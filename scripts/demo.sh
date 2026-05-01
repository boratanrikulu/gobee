#!/usr/bin/env bash
#
# demo.sh — Show current gobee progress: Go subset → BPF C transpilation.
# Runs anywhere (no clang or kernel needed).
#
# Usage: ./scripts/demo.sh
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$(pwd)"

# Pretty-print helpers.
sep() { printf '\n\033[1;36m──── %s ────\033[0m\n\n' "$1"; }
hdr() { printf '\033[1;33m%s\033[0m\n' "$1"; }
note() { printf '\033[2m%s\033[0m\n' "$1"; }

# ─────────────────────────────────────────────────────────────────────
sep "1. Build gobee"
go build -o bin/gobee ./cmd/gobee
hdr "$ ./bin/gobee version"
./bin/gobee version
hdr "$ ./bin/gobee help"
./bin/gobee help

# ─────────────────────────────────────────────────────────────────────
sep "2. Kernel-side input — written in Go (type-safe, gopls-friendly)"
DEMO_DIR="$(mktemp -d -t gobee-demo-XXXXXX)"
trap 'rm -rf "$DEMO_DIR"' EXIT
cp testdata/golden/helloworld.go "$DEMO_DIR/counter.go"
hdr "$ cat $DEMO_DIR/counter.go"
cat "$DEMO_DIR/counter.go"

# ─────────────────────────────────────────────────────────────────────
sep "3. Transpile with gobee"
hdr "$ ./bin/gobee translate $DEMO_DIR"
"$ROOT/bin/gobee" translate "$DEMO_DIR"

# ─────────────────────────────────────────────────────────────────────
sep "4. Emitted BPF C — drop-in for any libbpf workflow"
hdr "$ cat $DEMO_DIR/counter.bpf.c"
cat "$DEMO_DIR/counter.bpf.c"

# ─────────────────────────────────────────────────────────────────────
sep "5. Validator rejects unsupported Go constructs"
BAD_DIR="$(mktemp -d -t gobee-demo-bad-XXXXXX)"
trap 'rm -rf "$DEMO_DIR" "$BAD_DIR"' EXIT
cat > "$BAD_DIR/bad.go" <<'GO'
//go:build ignore

package main

import "github.com/boratanrikulu/gobee/bpf"

//bpf:license GPL

//bpf:section xdp
func Run(ctx *bpf.XdpMd) bpf.XdpAction {
	var s string = "this is not allowed"
	for _, b := range []byte(s) {
		_ = b
	}
	go func() {}()
	defer func() {}()
	return bpf.XdpPass
}

func main() {}
GO
hdr "$ cat $BAD_DIR/bad.go    # contains: string, range, slice, goroutine, defer"
cat "$BAD_DIR/bad.go"
echo
hdr "$ ./bin/gobee translate $BAD_DIR    # expected to fail with diagnostics"
note "(non-zero exit is the desired behavior)"
"$ROOT/bin/gobee" translate "$BAD_DIR" || true

# ─────────────────────────────────────────────────────────────────────
sep "6. Test suite"
hdr "$ go test ./..."
go test -count=1 ./... 2>&1 | tail -8

sep "Done."
note "Next step (Day 6, not yet wired): hello-world example/ that compiles"
note "the emitted .bpf.c with clang and loads it via cilium/ebpf — same"
note "pattern as gecit's Makefile + go:embed + ebpf.NewCollectionFromReader."
