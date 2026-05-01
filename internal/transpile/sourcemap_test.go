package transpile

import (
	"path/filepath"
	"testing"
)

func TestEmit_SourceMap_Helloworld(t *testing.T) {
	inputAbs, err := filepath.Abs("../../testdata/golden/helloworld.go")
	if err != nil {
		t.Fatal(err)
	}
	prog, err := ParseFile(inputAbs)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	_, mappings, err := Emit(prog, "helloworld.go")
	if err != nil {
		t.Fatalf("emit: %v", err)
	}
	if len(mappings) == 0 {
		t.Fatal("no source mappings produced")
	}

	byCLine := make(map[int]int)
	for _, m := range mappings {
		byCLine[m.CLine] = m.Position.Line
	}

	// Manually verified against testdata/golden/helloworld.go
	// and the emitted helloworld.bpf.c.
	want := []struct {
		c, g int
		desc string
	}{
		{9, 9, "map decl `var PktCount = ...`"},
		{16, 12, "function header `func CountPackets`"},
		{18, 13, "`var key uint32 = 0`"},
		{19, 14, "`count, ok := PktCount.Lookup(...)`"},
		{20, 15, "`if !ok {`"},
		{21, 16, "`return bpf.XdpPass` inside if"},
		{23, 18, "`bpf.AtomicAdd64(count, 1)`"},
		{24, 19, "trailing `return bpf.XdpPass`"},
	}
	for _, tc := range want {
		if got := byCLine[tc.c]; got != tc.g {
			t.Errorf("c-line %d (%s): mapped to go-line %d, want %d", tc.c, tc.desc, got, tc.g)
		}
	}
}

func TestFormatSourceMap_SortsAndHeaders(t *testing.T) {
	pos := func(line int) SourceMapping {
		return SourceMapping{
			CLine: line,
			Position: posFor("counter.go", line, 1),
		}
	}
	out := string(FormatSourceMap([]SourceMapping{pos(20), pos(5), pos(13)}))
	want := "# gobee sourcemap. Format: <c-line>\\t<go-file>:<go-line>:<go-col>\n" +
		"5\tcounter.go:5:1\n" +
		"13\tcounter.go:13:1\n" +
		"20\tcounter.go:20:1\n"
	if out != want {
		t.Errorf("FormatSourceMap output mismatch\n--- got ---\n%s\n--- want ---\n%s", out, want)
	}
}
