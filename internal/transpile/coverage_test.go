package transpile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestExampleMapCoverage fails if any registered map type has no example
// under testdata/examples/. Keeps the example matrix and the supported
// surface in sync — when someone adds a new map type to
// bpfMapGoTypeToDirective they also have to demonstrate it.
func TestExampleMapCoverage(t *testing.T) {
	examples := readExampleSources(t)
	uncovered := map[string]bool{}
	for goType := range bpfMapGoTypeToDirective {
		if !anyExampleMentions(examples, "bpf."+goType) {
			uncovered[goType] = true
		}
	}
	if len(uncovered) > 0 {
		var names []string
		for n := range uncovered {
			names = append(names, n)
		}
		t.Errorf("map types with no example in testdata/examples/: %v", names)
	}
}

// TestExampleSectionCoverage fails if any //bpf:section kind we claim to
// support has no example. The list mirrors docs/status.md.
func TestExampleSectionCoverage(t *testing.T) {
	// Section names mirror docs/status.md. TC programs use the
	// "classifier/" prefix in libbpf; our examples follow that
	// convention (10_tc_classifier.go, etc.).
	required := []string{
		"xdp",
		"tracepoint/",
		"kprobe/",
		"kretprobe/",
		"uprobe/",
		"sockops",
		"classifier/",
		"cgroup_skb/",
		"lsm/",
	}
	examples := readExampleSources(t)
	var missing []string
	for _, sec := range required {
		needle := "//bpf:section " + sec
		if !anyExampleMentions(examples, needle) {
			missing = append(missing, sec)
		}
	}
	if len(missing) > 0 {
		t.Errorf("section kinds with no example in testdata/examples/: %v", missing)
	}
}

func readExampleSources(t *testing.T) []string {
	t.Helper()
	dir := filepath.Join("..", "..", "testdata", "examples")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read examples: %v", err)
	}
	var bodies []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		body, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		bodies = append(bodies, string(body))
	}
	if len(bodies) == 0 {
		t.Fatal("no example .go files found")
	}
	return bodies
}

func anyExampleMentions(examples []string, needle string) bool {
	for _, body := range examples {
		if strings.Contains(body, needle) {
			return true
		}
	}
	return false
}
