package transpile

import (
	"fmt"
	"go/ast"
	"strings"
)

const directivePrefix = "//bpf:"

// directive is a parsed `//bpf:<name> [args...] [k=v ...]` comment.
type directive struct {
	name string
	args []string
	kv   map[string]string
}

// parseDirective returns the parsed directive if the comment text starts with
// "//bpf:". Returns (nil, nil) for unrelated comments. Whitespace around
// fields is trimmed; values containing '=' are treated as k=v pairs.
func parseDirective(text string) (*directive, error) {
	if !strings.HasPrefix(text, directivePrefix) {
		return nil, nil
	}
	rest := strings.TrimSpace(strings.TrimPrefix(text, directivePrefix))
	if rest == "" {
		return nil, fmt.Errorf("empty directive")
	}
	fields := strings.Fields(rest)
	d := &directive{name: fields[0], kv: make(map[string]string)}
	for _, f := range fields[1:] {
		if i := strings.IndexByte(f, '='); i >= 0 {
			d.kv[f[:i]] = f[i+1:]
		} else {
			d.args = append(d.args, f)
		}
	}
	return d, nil
}

// docDirective scans a doc comment group for the named directive and returns
// the first match, or nil if absent. Errors during parsing are ignored here;
// callers that need to surface malformed directives should iterate the group
// directly via parseDirective.
func docDirective(cg *ast.CommentGroup, name string) *directive {
	if cg == nil {
		return nil
	}
	for _, c := range cg.List {
		d, _ := parseDirective(c.Text)
		if d != nil && d.name == name {
			return d
		}
	}
	return nil
}
