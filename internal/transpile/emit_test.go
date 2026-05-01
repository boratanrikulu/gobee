package transpile

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var updateGoldens = flag.Bool("update", false, "rewrite golden files with current emitter output")

func TestEmit_Helloworld(t *testing.T) {
	inputAbs, err := filepath.Abs("../../testdata/golden/helloworld.go")
	if err != nil {
		t.Fatal(err)
	}
	goldenAbs, err := filepath.Abs("../../testdata/golden/helloworld.c")
	if err != nil {
		t.Fatal(err)
	}

	prog, err := ParseFile(inputAbs)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if d := Validate(prog); len(d) != 0 {
		t.Fatalf("validate produced unexpected diagnostics:\n%s", d.Error())
	}

	got, _, err := Emit(prog, "testdata/golden/helloworld.go")
	if err != nil {
		t.Fatalf("emit: %v", err)
	}

	if *updateGoldens {
		if err := os.WriteFile(goldenAbs, got, 0o644); err != nil {
			t.Fatalf("update golden: %v", err)
		}
		return
	}

	want, err := os.ReadFile(goldenAbs)
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("emitter output diverged from golden\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

func TestEmit_AutoTranslatesHelpers(t *testing.T) {
	src := `//go:build ignore

package main

import "github.com/boratanrikulu/gobee/bpf"

//bpf:license GPL

//bpf:section xdp
func Run(ctx *bpf.XdpMd) bpf.XdpAction {
	var t uint64 = bpf.KtimeGetNs()
	_ = t
	var pid uint64 = bpf.GetCurrentPidTgid()
	_ = pid
	return bpf.XdpPass
}

func main() {}
`
	dir := t.TempDir()
	path := filepath.Join(dir, "input.go")
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	prog, err := ParseFile(path)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if d := Validate(prog); len(d) != 0 {
		t.Fatalf("validate: %s", d.Error())
	}
	out, _, err := Emit(prog, "input.go")
	if err != nil {
		t.Fatalf("emit: %v", err)
	}
	c := string(out)
	for _, want := range []string{"bpf_ktime_get_ns()", "bpf_get_current_pid_tgid()"} {
		if !strings.Contains(c, want) {
			t.Errorf("emitted C missing %q\n--- got ---\n%s", want, c)
		}
	}
}

func TestGoNameToBpfHelper(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"MapLookupElem", "bpf_map_lookup_elem"},
		{"KtimeGetNs", "bpf_ktime_get_ns"},
		{"GetCurrentPidTgid", "bpf_get_current_pid_tgid"},
		{"RingbufReserve", "bpf_ringbuf_reserve"},
	}
	for _, tc := range cases {
		got := goNameToBpfHelper(tc.in)
		if got != tc.want {
			t.Errorf("goNameToBpfHelper(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
