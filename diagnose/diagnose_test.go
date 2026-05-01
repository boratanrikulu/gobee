package diagnose

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestParseSourceMap(t *testing.T) {
	in := `# header line
9	counter.go:10:5
20	counter.go:16:2

`
	sm, err := ParseSourceMap(strings.NewReader(in))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := sm[9]; got != "counter.go:10:5" {
		t.Errorf("sm[9] = %q, want counter.go:10:5", got)
	}
	if got := sm[20]; got != "counter.go:16:2" {
		t.Errorf("sm[20] = %q, want counter.go:16:2", got)
	}
	if _, ok := sm[42]; ok {
		t.Errorf("sm[42] should be absent")
	}
}

func TestRewrite_HelloworldHash(t *testing.T) {
	mapBytes, err := os.ReadFile("testdata/helloworld_hash.bpf.c.map")
	if err != nil {
		t.Fatal(err)
	}
	sm, err := ParseSourceMap(bytes.NewReader(mapBytes))
	if err != nil {
		t.Fatal(err)
	}

	logBytes, err := os.ReadFile("testdata/helloworld_hash_verifier.log")
	if err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	if err := Rewrite(bytes.NewReader(logBytes), &out, sm); err != nil {
		t.Fatalf("Rewrite: %v", err)
	}
	got := out.String()

	wantLines := []string{
		"; int CountPackets(struct xdp_md *ctx) { @ counter.bpf.c:17",
		"; __u32 key = 0; @ counter.bpf.c:18    → bpf/counter.go:14:2",
		"; __u64 *count = bpf_map_lookup_elem(&PktCount, &key); @ counter.bpf.c:19    → bpf/counter.go:15:2",
		"; __sync_fetch_and_add(count, 1); @ counter.bpf.c:20    → bpf/counter.go:16:2",
	}
	for _, want := range wantLines {
		if !strings.Contains(got, want) {
			t.Errorf("output missing expected line:\n  want: %s\n--- output ---\n%s", want, got)
		}
	}

	// Lines without a known C-line ref must pass through verbatim.
	for _, passthrough := range []string{
		"R0 invalid mem access 'map_value_or_null'",
		"processed 8 insns (limit 1000000)",
	} {
		if !strings.Contains(got, passthrough) {
			t.Errorf("expected verbatim passthrough of %q\n--- output ---\n%s", passthrough, got)
		}
	}

	// counter.bpf.c:17 has no entry in the test sourcemap, so it must NOT be
	// annotated (no false matches).
	for _, line := range strings.Split(got, "\n") {
		if strings.Contains(line, "counter.bpf.c:17") && strings.Contains(line, "→ bpf/counter.go") {
			t.Errorf("c-line 17 has no sourcemap entry but was annotated: %q", line)
		}
	}
}

func TestAnnotateLines(t *testing.T) {
	sm := SourceMap{
		20: "counter.go:16:2",
		42: "counter.go:25:5",
	}
	in := []string{
		"R0 invalid mem access 'map_value_or_null'",
		"; xdp.bpf.c:20    something",
		"; xdp.bpf.c:42    other thing",
		"unrelated line",
	}
	got := AnnotateLines(in, sm)

	if len(got) != len(in) {
		t.Fatalf("got %d lines, want %d", len(got), len(in))
	}
	if got[0] != in[0] {
		t.Errorf("line 0 should pass through verbatim: got %q", got[0])
	}
	if !strings.Contains(got[1], "→ counter.go:16:2") {
		t.Errorf("line 1 missing annotation: got %q", got[1])
	}
	if !strings.Contains(got[2], "→ counter.go:25:5") {
		t.Errorf("line 2 missing annotation: got %q", got[2])
	}
	if got[3] != in[3] {
		t.Errorf("line 3 should pass through verbatim: got %q", got[3])
	}
}

func TestParseSourceMapBytes(t *testing.T) {
	in := []byte("9\tcounter.go:10:5\n20\tcounter.go:16:2\n")
	sm, err := ParseSourceMapBytes(in)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if sm[9] != "counter.go:10:5" {
		t.Errorf("sm[9] = %q", sm[9])
	}
	if sm[20] != "counter.go:16:2" {
		t.Errorf("sm[20] = %q", sm[20])
	}
}

func TestRewrite_NoMatches(t *testing.T) {
	in := "this line has no bpf reference\n2026/04/30 attached XDP to lima0\n"
	sm := SourceMap{20: "counter.go:16:2"}
	var out bytes.Buffer
	if err := Rewrite(strings.NewReader(in), &out, sm); err != nil {
		t.Fatalf("Rewrite: %v", err)
	}
	if out.String() != in {
		t.Errorf("expected verbatim passthrough\n--- got ---\n%s\n--- want ---\n%s", out.String(), in)
	}
}
