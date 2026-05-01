package transpile

import (
	"go/types"
	"path/filepath"
	"testing"
)

func TestParseFile_Helloworld(t *testing.T) {
	path, err := filepath.Abs("../../testdata/golden/helloworld.go")
	if err != nil {
		t.Fatal(err)
	}
	prog, err := ParseFile(path)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	if prog.License != "GPL" {
		t.Errorf("license = %q, want GPL", prog.License)
	}
	if len(prog.Maps) != 1 {
		t.Fatalf("len(Maps) = %d, want 1", len(prog.Maps))
	}
	m := prog.Maps[0]
	if m.Name != "PktCount" {
		t.Errorf("map name = %q, want PktCount", m.Name)
	}
	if m.Type != "array" {
		t.Errorf("map type = %q, want array", m.Type)
	}
	if m.MaxEntries != 1 {
		t.Errorf("map max_entries = %d, want 1", m.MaxEntries)
	}
	if got := basicKind(m.KeyType); got != types.Uint32 {
		t.Errorf("key kind = %v, want uint32", got)
	}
	if got := basicKind(m.ValType); got != types.Uint64 {
		t.Errorf("value kind = %v, want uint64", got)
	}

	if len(prog.Programs) != 1 {
		t.Fatalf("len(Programs) = %d, want 1", len(prog.Programs))
	}
	p := prog.Programs[0]
	if p.Name != "CountPackets" {
		t.Errorf("func name = %q, want CountPackets", p.Name)
	}
	if p.Section != "xdp" {
		t.Errorf("section = %q, want xdp", p.Section)
	}
}

func basicKind(t types.Type) types.BasicKind {
	if b, ok := t.(*types.Basic); ok {
		return b.Kind()
	}
	return types.Invalid
}
