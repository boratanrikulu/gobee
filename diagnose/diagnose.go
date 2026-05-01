// Package diagnose rewrites BPF verifier output by replacing C source
// references (`counter.bpf.c:20`) with the originating Go positions
// (`counter.go:16:2`), using a sourcemap produced by transpile.Emit.
//
// Two callers consume this package:
//
//   - `gobee diagnose` (cmd/gobee/app) reads a verifier log from stdin
//     and prints an annotated copy to stdout.
//   - The generated `<stem>_bindings.go` file embeds its own sourcemap
//     and calls AnnotateLines to wrap any *ebpf.VerifierError returned
//     by LoadAndAssign with Go source positions, so the user sees a
//     helpful error like
//
//       counter.bpf.c:25: invalid memory access  → counter.go:18:5
//
//     instead of the bare verifier complaint.
package diagnose

import (
	"bufio"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
)

// SourceMap is the in-memory shape of a `.bpf.c.map` file. Keys are emitted-C
// line numbers; values are Go positions formatted as `file:line:col`.
type SourceMap map[int]string

// ParseSourceMapBytes is the byte-slice convenience wrapper for callers
// that already have the sourcemap in memory (e.g. generated bindings
// that embed it as a string literal).
func ParseSourceMapBytes(b []byte) (SourceMap, error) {
	return ParseSourceMap(strings.NewReader(string(b)))
}

// AnnotateLines walks each input line, extends any line that mentions a
// `<stem>.bpf.c:<N>` reference with the matching Go position from sm,
// and returns the annotated copy. Lines without recognized refs pass
// through verbatim.
//
// The intended use is wrapping `*ebpf.VerifierError.Log`:
//
//	if verr := new(ebpf.VerifierError); errors.As(err, &verr) {
//	    annotated := diagnose.AnnotateLines(verr.Log, sm)
//	    return fmt.Errorf("verifier rejected the program:\n%s", strings.Join(annotated, "\n"))
//	}
func AnnotateLines(lines []string, sm SourceMap) []string {
	out := make([]string, len(lines))
	for i, line := range lines {
		out[i] = annotateLine(line, sm)
	}
	return out
}

// ParseSourceMap reads a sourcemap as written by transpile.FormatSourceMap.
// Comment lines (`#...`) and blank lines are skipped.
func ParseSourceMap(r io.Reader) (SourceMap, error) {
	out := make(SourceMap)
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.SplitN(line, "\t", 2)
		if len(fields) != 2 {
			return nil, fmt.Errorf("malformed sourcemap line %q", line)
		}
		cline, err := strconv.Atoi(fields[0])
		if err != nil {
			return nil, fmt.Errorf("malformed c-line in %q: %w", line, err)
		}
		out[cline] = fields[1]
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// cFileRefPattern matches `<stem>.bpf.c:<line>` references in verifier output.
// We don't anchor to a specific stem so any gobee-emitted .bpf.c reference is
// recognized.
var cFileRefPattern = regexp.MustCompile(`([\w./-]+\.bpf\.c):(\d+)`)

// Rewrite reads verifier output from r line by line and writes an annotated
// copy to w. Each line that contains a `<file>.bpf.c:<N>` reference is
// extended with the corresponding `→ <go-file>:<go-line>:<go-col>` mapping
// when one exists. Lines without recognized refs pass through verbatim.
func Rewrite(r io.Reader, w io.Writer, sm SourceMap) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		annotated := annotateLine(line, sm)
		if _, err := fmt.Fprintln(w, annotated); err != nil {
			return err
		}
	}
	return scanner.Err()
}

// annotateLine returns line with one trailing `(→ go-file:line:col)` per
// distinct C-line ref it contains. Unknown refs are left alone (no false
// rewrites).
func annotateLine(line string, sm SourceMap) string {
	matches := cFileRefPattern.FindAllStringSubmatch(line, -1)
	if len(matches) == 0 {
		return line
	}
	var added []string
	seen := make(map[int]bool)
	for _, m := range matches {
		cline, err := strconv.Atoi(m[2])
		if err != nil {
			continue
		}
		if seen[cline] {
			continue
		}
		seen[cline] = true
		if pos, ok := sm[cline]; ok {
			added = append(added, "→ "+pos)
		}
	}
	if len(added) == 0 {
		return line
	}
	return line + "    " + strings.Join(added, "  ")
}
