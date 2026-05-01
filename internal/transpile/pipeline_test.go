package transpile

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRun_TranslateGolden(t *testing.T) {
	dir := t.TempDir()
	src, err := os.ReadFile("../../testdata/golden/helloworld.go")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "counter.go"), src, 0o644); err != nil {
		t.Fatal(err)
	}

	var stderr bytes.Buffer
	results, err := Run(RunOptions{InputDir: dir, Stderr: &stderr})
	if err != nil {
		t.Fatalf("Run: %v\nstderr:\n%s", err, stderr.String())
	}
	if len(results) != 1 {
		t.Fatalf("len(results) = %d, want 1", len(results))
	}
	r := results[0]
	if r.Stem != "counter" {
		t.Errorf("stem = %q, want counter", r.Stem)
	}
	if !strings.HasSuffix(r.CFile, "counter.bpf.c") {
		t.Errorf("cFile = %q, want suffix counter.bpf.c", r.CFile)
	}

	body, err := os.ReadFile(r.CFile)
	if err != nil {
		t.Fatal(err)
	}
	c := string(body)
	for _, want := range []string{
		`SEC("xdp")`,
		`int CountPackets(struct xdp_md *ctx)`,
		`bpf_map_lookup_elem(&PktCount, &key)`,
		`__sync_fetch_and_add(count, 1)`,
		`return XDP_PASS;`,
	} {
		if !strings.Contains(c, want) {
			t.Errorf("emitted C missing %q\n--- got ---\n%s", want, c)
		}
	}
}

func TestRun_NoInputs(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "unrelated.go"), []byte("package main\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Run(RunOptions{InputDir: dir})
	if err == nil {
		t.Fatal("expected error for directory with no //bpf:license files")
	}
	if !strings.Contains(err.Error(), "//bpf:license") {
		t.Errorf("error %q should mention //bpf:license", err)
	}
}
