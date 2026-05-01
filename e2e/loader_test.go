//go:build linux && integration

// Package e2e holds verifier-acceptance tests. Each test loads a real
// .bpf.o (built by the example Makefiles) into the host kernel, which
// runs the BPF verifier — the one part of the toolchain that gobee
// can't simulate. Without these tests we'd ship code that translates
// and compiles cleanly but gets rejected at load time.
//
// Run on Linux with:
//
//	make examples-build       # produce the .bpf.o files
//	go test -tags=integration ./e2e/...
//
// CI runs this on ubuntu-24.04 (kernel 6.x). Locally, lima is fine.
package e2e

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

// TestLoadCuratedExamples picks up every .bpf.o produced under
// example/*/bpf/bin/<arch>/ and asks the kernel to load it. This
// exercises:
//
//   - clang's BPF target produced a valid ELF
//   - gobee's emitted helpers / map decls match what cilium/ebpf expects
//   - the verifier accepts the program (no out-of-bounds, no missing
//     bounds checks, no unsafe pointer arith)
//
// We don't attach or drive traffic — verifier acceptance is the
// contract the unit tests can't cover.
func TestLoadCuratedExamples(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("remove memlock: %v", err)
	}

	objs, err := findArchObjects()
	if err != nil {
		t.Fatalf("find .bpf.o files: %v", err)
	}
	if len(objs) == 0 {
		t.Skipf("no .bpf.o files under example/*/bpf/bin/%s/ — run `make examples-build` first", runtime.GOARCH)
	}

	for _, path := range objs {
		path := path
		t.Run(testNameFor(path), func(t *testing.T) {
			f, err := os.Open(path)
			if err != nil {
				t.Fatalf("open %s: %v", path, err)
			}
			defer f.Close()

			spec, err := ebpf.LoadCollectionSpecFromReader(f)
			if err != nil {
				t.Fatalf("load spec %s: %v", path, err)
			}

			coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
				Programs: ebpf.ProgramOptions{
					LogLevel: ebpf.LogLevelInstruction,
				},
			})
			if err != nil {
				var verr *ebpf.VerifierError
				if errors.As(err, &verr) {
					t.Fatalf("verifier rejected %s:\n%s", path, strings.Join(verr.Log, "\n"))
				}
				t.Fatalf("new collection %s: %v", path, err)
			}
			coll.Close()
		})
	}
}

// findArchObjects returns every .bpf.o under example/*/bpf/bin/<arch>/.
// arch is mapped from runtime.GOARCH because the Makefile uses libbpf-
// style names (x86 / arm64) instead of Go's amd64 / arm64.
func findArchObjects() ([]string, error) {
	archDir := map[string]string{
		"amd64": "x86",
		"arm64": "arm64",
	}[runtime.GOARCH]
	if archDir == "" {
		return nil, fmt.Errorf("unsupported GOARCH %q", runtime.GOARCH)
	}
	pattern := filepath.Join("..", "example", "*", "bpf", "bin", archDir, "*.bpf.o")
	return filepath.Glob(pattern)
}

func testNameFor(path string) string {
	// Turn ".../example/sysmon/bpf/bin/arm64/sysmon.bpf.o" into
	// "sysmon" so test names stay readable.
	rel, err := filepath.Rel("..", path)
	if err != nil {
		return path
	}
	parts := strings.Split(rel, string(filepath.Separator))
	for i, p := range parts {
		if p == "example" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return rel
}
