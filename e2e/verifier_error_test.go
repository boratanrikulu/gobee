//go:build linux && integration

package e2e

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/boratanrikulu/gobee/diagnose"
)

// TestVerifierErrorAnnotation builds a deliberately-broken kernel-side
// program (Lookup followed by an unchecked dereference), loads it, and
// asserts that gobee's annotation pipeline turns the resulting verifier
// log into Go source positions.
//
// The test mirrors what users get out of generated bindings: parse the
// embedded sourcemap, run AnnotateLines on the verifier log, expect at
// least one "→ broken.go:<line>:<col>" annotation in the result.
func TestVerifierErrorAnnotation(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("remove memlock: %v", err)
	}

	repoRoot := repoRootDir(t)
	srcDir := filepath.Join(repoRoot, "e2e", "broken", "bpf", "src")
	binDir := filepath.Join(repoRoot, "e2e", "broken", "bpf", "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("mkdir bin: %v", err)
	}

	// Translate. Skips bindings (we use the .bpf.c.map directly).
	gobee := filepath.Join(repoRoot, "bin", "gobee")
	if _, err := os.Stat(gobee); err != nil {
		t.Skipf("bin/gobee not built (run `make build`): %v", err)
	}
	out, err := exec.Command(gobee, "translate", srcDir).CombinedOutput()
	if err != nil {
		t.Fatalf("gobee translate: %v\n%s", err, out)
	}

	// Compile with clang.
	cFile := filepath.Join(srcDir, "broken.bpf.c")
	oFile := filepath.Join(binDir, "broken.bpf.o")
	clang, err := exec.LookPath("clang")
	if err != nil {
		t.Skipf("clang not found: %v", err)
	}
	multiarchInc := fmt.Sprintf("-I/usr/include/%s-linux-gnu", uname())
	out, err = exec.Command(clang, "-target", "bpfel", "-O2", "-g", "-Wall", multiarchInc, "-c", cFile, "-o", oFile).CombinedOutput()
	if err != nil {
		t.Fatalf("clang: %v\n%s", err, out)
	}

	// Try to load: expect a VerifierError.
	f, err := os.Open(oFile)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	spec, err := ebpf.LoadCollectionSpecFromReader(f)
	if err != nil {
		t.Fatalf("load spec: %v", err)
	}

	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{LogLevel: ebpf.LogLevelInstruction},
	})
	if err == nil {
		coll.Close()
		t.Fatal("expected verifier rejection; load succeeded")
	}

	var verr *ebpf.VerifierError
	if !errors.As(err, &verr) {
		t.Fatalf("expected *ebpf.VerifierError, got %T: %v", err, err)
	}

	// Parse the sourcemap gobee just wrote and run the same annotation
	// pipeline that Load<Stem> uses internally.
	mapBytes, err := os.ReadFile(filepath.Join(srcDir, "broken.bpf.c.map"))
	if err != nil {
		t.Fatalf("read sourcemap: %v", err)
	}
	sm, err := diagnose.ParseSourceMapBytes(mapBytes)
	if err != nil {
		t.Fatalf("parse sourcemap: %v", err)
	}
	annotated := diagnose.AnnotateLines(verr.Log, sm)
	joined := strings.Join(annotated, "\n")

	if !strings.Contains(joined, "broken.go:") {
		t.Errorf("annotated log missing broken.go reference:\n%s", joined)
	}
	if !strings.Contains(joined, "→ ") {
		t.Errorf("annotated log missing arrow markers:\n%s", joined)
	}
}

// uname returns the kernel-side arch name used in /usr/include paths.
// runtime.GOARCH gives Go's name (amd64, arm64); the multiarch include
// dirs use Linux's (x86_64, aarch64).
func uname() string {
	switch runtime.GOARCH {
	case "amd64":
		return "x86_64"
	case "arm64":
		return "aarch64"
	}
	return runtime.GOARCH
}

func repoRootDir(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	// e2e/ sits one level under the repo root.
	return filepath.Dir(wd)
}
