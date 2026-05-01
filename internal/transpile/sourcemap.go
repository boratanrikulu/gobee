package transpile

import (
	"fmt"
	"go/token"
	"io"
	"sort"
	"strings"
)

// SourceMapping ties one line in the emitted C back to its originating Go
// source position. Used by `gobee diagnose` to rewrite verifier errors.
type SourceMapping struct {
	CLine    int
	Position token.Position
}

// posFor builds a token.Position from raw fields. Used by tests; kept here so
// it can also support a future "load sourcemap from disk" path.
func posFor(filename string, line, col int) token.Position {
	return token.Position{Filename: filename, Line: line, Column: col}
}

// FormatSourceMap renders mappings as a tab-separated text file:
//
//	<c-line>\t<go-file>:<go-line>:<go-col>
//
// Lines are sorted by C line number. The format is intentionally trivial so
// users can read or grep it directly.
func FormatSourceMap(mappings []SourceMapping) []byte {
	sorted := append([]SourceMapping(nil), mappings...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].CLine < sorted[j].CLine })

	var b strings.Builder
	b.WriteString("# gobee sourcemap. Format: <c-line>\\t<go-file>:<go-line>:<go-col>\n")
	for _, m := range sorted {
		fmt.Fprintf(&b, "%d\t%s:%d:%d\n", m.CLine, m.Position.Filename, m.Position.Line, m.Position.Column)
	}
	return []byte(b.String())
}

// WriteSourceMap writes the sourcemap text representation to w.
func WriteSourceMap(w io.Writer, mappings []SourceMapping) error {
	_, err := w.Write(FormatSourceMap(mappings))
	return err
}
