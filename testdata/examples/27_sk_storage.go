//go:build ignore

// Per-socket storage. SkStorage gives every kernel `struct sock *` its
// own value slot — useful in sock_ops and tracing programs that get a
// socket pointer. The kernel sizes the map dynamically, so no
// MaxEntries.

package main

import "github.com/boratanrikulu/gobee/bpf"

//bpf:license GPL

type SockStats struct {
	Bytes uint64
}

var perSk = bpf.SkStorage[SockStats]{}

//bpf:section sockops
func TrackBytes(ctx *bpf.SockOpsMd) bpf.SockOpsReturn {
	// In a real program the user would obtain `sk` via a CO-RE field
	// read on the bpf_sock_ops context. Here we use unsafe.Pointer
	// passthrough as a transpile-only fixture.
	return bpf.SockOpsOk
}

func main() {}
