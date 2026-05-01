package transpile

import "testing"

func TestParseDirective(t *testing.T) {
	cases := []struct {
		in   string
		want *directive
	}{
		{"// not a directive", nil},
		{"//other:tag foo", nil},
		{"//bpf:license GPL", &directive{name: "license", args: []string{"GPL"}, kv: map[string]string{}}},
		{"//bpf:section xdp", &directive{name: "section", args: []string{"xdp"}, kv: map[string]string{}}},
	}
	for _, tc := range cases {
		got, err := parseDirective(tc.in)
		if err != nil {
			t.Errorf("parseDirective(%q) error: %v", tc.in, err)
			continue
		}
		if !directivesEqual(got, tc.want) {
			t.Errorf("parseDirective(%q) = %+v, want %+v", tc.in, got, tc.want)
		}
	}
}

func TestParseDirectiveErrors(t *testing.T) {
	if _, err := parseDirective("//bpf:"); err == nil {
		t.Error("empty directive should error")
	}
}

func directivesEqual(a, b *directive) bool {
	if a == nil || b == nil {
		return a == b
	}
	if a.name != b.name {
		return false
	}
	if len(a.args) != len(b.args) {
		return false
	}
	for i := range a.args {
		if a.args[i] != b.args[i] {
			return false
		}
	}
	if len(a.kv) != len(b.kv) {
		return false
	}
	for k, v := range a.kv {
		if b.kv[k] != v {
			return false
		}
	}
	return true
}
