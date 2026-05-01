package transpile

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// RunOptions configures a single `gobee translate` invocation.
type RunOptions struct {
	// InputDir contains kernel-side .go files. Each file with a //bpf:license
	// directive is treated as a separate transpilation unit.
	InputDir string

	// OutputDir is where generated .bpf.c files land. Defaults to InputDir.
	OutputDir string

	// Stderr receives progress output. Defaults to os.Stderr.
	Stderr io.Writer

	// BindingsDir is where the typed Go bindings file (`<stem>_bindings.go`)
	// is written. Empty disables bindings generation entirely; the user owns
	// program/map lookup via stringly-typed `coll.Programs["X"]` in that case.
	// The package name for the bindings is derived from the directory's
	// base name (sanitized to a valid Go identifier). The bindings file
	// can't live next to the .bpf.c because Go rejects packages that mix
	// .go and .c without cgo, so users typically point this at a sibling
	// directory like `./bpf` while emitting the .bpf.c into `./bpf/src`.
	BindingsDir string
}

// Result describes one emitted artifact.
type Result struct {
	InputFile    string
	CFile        string
	MapFile      string
	BindingsFile string
	Stem         string
}

// Run translates every kernel-side .go file in opts.InputDir into a sibling
// .bpf.c file. gobee stops here — the user owns clang invocation, .o
// embedding, and userspace loading (typically via a Makefile + go:embed,
// the same pattern as the gecit project).
func Run(opts RunOptions) ([]Result, error) {
	if opts.Stderr == nil {
		opts.Stderr = os.Stderr
	}
	if opts.OutputDir == "" {
		opts.OutputDir = opts.InputDir
	}

	inputs, err := findInputs(opts.InputDir)
	if err != nil {
		return nil, err
	}
	if len(inputs) == 0 {
		return nil, fmt.Errorf("no .go files with //bpf:license found in %s", opts.InputDir)
	}
	if err := os.MkdirAll(opts.OutputDir, 0o755); err != nil {
		return nil, fmt.Errorf("create output dir: %w", err)
	}

	results := make([]Result, 0, len(inputs))
	for _, in := range inputs {
		r, err := translateOne(in, opts)
		if err != nil {
			return results, err
		}
		results = append(results, r)
	}
	return results, nil
}

func translateOne(inputFile string, opts RunOptions) (Result, error) {
	outputDir := opts.OutputDir
	stem := strings.TrimSuffix(filepath.Base(inputFile), ".go")
	cFile := filepath.Join(outputDir, stem+".bpf.c")
	mapFile := cFile + ".map"

	prog, err := ParseFile(inputFile)
	if err != nil {
		return Result{}, fmt.Errorf("%s: %w", inputFile, err)
	}
	if diags := Validate(prog); len(diags) > 0 {
		return Result{}, fmt.Errorf("validation failed:\n%s", diags.Error())
	}

	relSource, _ := filepath.Rel(outputDir, inputFile)
	if relSource == "" {
		relSource = inputFile
	}
	source, mappings, err := Emit(prog, relSource)
	if err != nil {
		return Result{}, fmt.Errorf("emit %s: %w", inputFile, err)
	}
	if err := os.WriteFile(cFile, source, 0o644); err != nil {
		return Result{}, fmt.Errorf("write %s: %w", cFile, err)
	}
	sourcemap := FormatSourceMap(mappings)
	if err := os.WriteFile(mapFile, sourcemap, 0o644); err != nil {
		return Result{}, fmt.Errorf("write %s: %w", mapFile, err)
	}

	res := Result{InputFile: inputFile, CFile: cFile, MapFile: mapFile, Stem: stem}

	if opts.BindingsDir == "" {
		fmt.Fprintf(opts.Stderr, "gobee: %s: bindings skipped (pass --bindings-dir to generate typed Go accessors)\n", inputFile)
		return res, nil
	}
	if err := os.MkdirAll(opts.BindingsDir, 0o755); err != nil {
		return res, fmt.Errorf("create bindings dir: %w", err)
	}
	bindingsFile := filepath.Join(opts.BindingsDir, stem+"_bindings.go")
	pkgName := sanitizePackageName(filepath.Base(opts.BindingsDir))
	f, err := os.Create(bindingsFile)
	if err != nil {
		return res, fmt.Errorf("create %s: %w", bindingsFile, err)
	}
	if err := WriteBindings(f, prog, pkgName, stem, sourcemap); err != nil {
		f.Close()
		return res, fmt.Errorf("write bindings %s: %w", bindingsFile, err)
	}
	if err := f.Close(); err != nil {
		return res, fmt.Errorf("close %s: %w", bindingsFile, err)
	}
	res.BindingsFile = bindingsFile
	return res, nil
}

// sanitizePackageName turns an arbitrary directory name into a valid Go
// package identifier: lowercase alphanumerics, underscores collapse
// non-id runes, and a leading underscore appears if the result starts
// with a digit.
func sanitizePackageName(s string) string {
	if s == "" {
		return "bpf"
	}
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
			out = append(out, c)
		case c >= 'A' && c <= 'Z':
			out = append(out, c+('a'-'A'))
		default:
			out = append(out, '_')
		}
	}
	if len(out) == 0 {
		return "bpf"
	}
	if out[0] >= '0' && out[0] <= '9' {
		out = append([]byte{'_'}, out...)
	}
	return string(out)
}

// findInputs returns .go files in dir whose contents reference //bpf:license.
// Cheap text scan — avoids paying go/types cost on unrelated files.
func findInputs(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", dir, err)
	}
	var inputs []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		body, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
		if strings.Contains(string(body), "//bpf:license") {
			inputs = append(inputs, path)
		}
	}
	return inputs, nil
}

// PrintSummary writes a one-line-per-artifact summary to w.
func PrintSummary(w io.Writer, results []Result) {
	for _, r := range results {
		fmt.Fprintf(w, "gobee: %s\n", r.InputFile)
		fmt.Fprintf(w, "  → %s\n", r.CFile)
		if r.MapFile != "" {
			fmt.Fprintf(w, "  → %s\n", r.MapFile)
		}
		if r.BindingsFile != "" {
			fmt.Fprintf(w, "  → %s\n", r.BindingsFile)
		}
	}
}
