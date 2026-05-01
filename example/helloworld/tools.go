//go:build tools

// This file anchors the gobee module in this example's module graph.
// Without it, `go mod tidy` would strip the require: the kernel-side
// source under bpf/src/ imports gobee/bpf, but that file has
// //go:build ignore so tidy doesn't see it. The transpiler's
// typechecker resolves the import in the example's module context,
// so the require has to be there.
package main

import (
	_ "github.com/boratanrikulu/gobee/bpf"
)
