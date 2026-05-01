package transpile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const validatorFixtureHeader = `//go:build ignore

package main

import "github.com/boratanrikulu/gobee/bpf"

//bpf:license GPL

//bpf:section xdp
func Run(ctx *bpf.XdpMd) bpf.XdpAction {
`

const validatorFixtureFooter = `
	return bpf.XdpPass
}

func main() {}
`

func TestValidate_Helloworld(t *testing.T) {
	path, err := filepath.Abs("../../testdata/golden/helloworld.go")
	if err != nil {
		t.Fatal(err)
	}
	prog, err := ParseFile(path)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if d := Validate(prog); len(d) != 0 {
		t.Errorf("expected zero diagnostics, got:\n%s", d.Error())
	}
}

func TestValidate_RejectsBadConstructs(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string // substring expected in at least one diagnostic
	}{
		{"range", `for _, x := range [3]int{1, 2, 3} { _ = x }`, "range loops"},
		{"switch", `var x uint32 = 0; switch x { case 0: }`, "switch"},
		{"goroutine", `go func() {}()`, "goroutines"},
		{"defer", `defer func() {}()`, "defer"},
		{"funclit", `f := func() {}; _ = f`, "function literals"},
		{"slice", `var s []int; _ = s`, "slices"},
		{"map_builtin", `var m map[uint32]uint32; _ = m`, "builtin map"},
		{"chan", `var c chan int; _ = c`, "channels"},
		{"interface", `var i interface{}; _ = i`, "interfaces"},
		{"make", `_ = make([]int, 1)`, "make is not supported"},
		{"new", `_ = new(uint32)`, "new is not supported"},
		{"panic_call", `panic("x")`, "panic"},
		{"string_var", `var s string = "hi"; _ = s`, "strings"},
		{"infinite_for", `for { break }`, "infinite for"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := validatorFixtureHeader + "\t" + tc.body + validatorFixtureFooter
			diags := validateSource(t, src)
			if len(diags) == 0 {
				t.Fatalf("expected diagnostic containing %q, got none", tc.want)
			}
			joined := diags.Error()
			if !strings.Contains(joined, tc.want) {
				t.Errorf("expected diagnostic containing %q, got:\n%s", tc.want, joined)
			}
		})
	}
}

func TestValidate_RejectsForeignImport(t *testing.T) {
	src := `//go:build ignore

package main

import (
	"net"

	"github.com/boratanrikulu/gobee/bpf"
)

//bpf:license GPL

//bpf:section xdp
func Run(ctx *bpf.XdpMd) bpf.XdpAction {
	var raw uint32 = 0x7F000001
	ip := net.IP{byte(raw >> 24), byte(raw >> 16), byte(raw >> 8), byte(raw)}
	_ = ip
	return bpf.XdpPass
}

func main() {}
`
	diags := validateSource(t, src)
	joined := diags.Error()
	if !strings.Contains(joined, `import "net" is not allowed`) {
		t.Errorf("expected diagnostic about disallowed import, got:\n%s", joined)
	}
}

func TestValidate_RejectsMethodAndMultiReturn(t *testing.T) {
	src := `//go:build ignore

package main

import "github.com/boratanrikulu/gobee/bpf"

//bpf:license GPL

type T struct{}

//bpf:section xdp
func (T) Method(ctx *bpf.XdpMd) (bpf.XdpAction, bool) {
	return bpf.XdpPass, true
}

func main() {}
`
	diags := validateSource(t, src)
	joined := diags.Error()
	if !strings.Contains(joined, "methods on user types") {
		t.Errorf("expected method diagnostic, got:\n%s", joined)
	}
	if !strings.Contains(joined, "multiple return values") {
		t.Errorf("expected multi-return diagnostic, got:\n%s", joined)
	}
}

func validateSource(t *testing.T, src string) Diagnostics {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "input.go")
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatalf("write tmp: %v", err)
	}
	prog, err := ParseFile(path)
	if err != nil {
		t.Fatalf("parse: %v\nsrc:\n%s", err, src)
	}
	return Validate(prog)
}
