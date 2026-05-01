//go:build ignore

// Counts established TCP connections (both active and passive). Demonstrates
// the sock_ops program type and the SockOpsReturn enum. Pre-CO-RE we can't
// switch on ctx.Op directly; this example just increments unconditionally
// to keep the kernel-side code compileable. The userspace driver attaches
// to a cgroup v2.

package main

import "github.com/boratanrikulu/gobee/bpf"

//bpf:license GPL

var Established = bpf.ArrayMap[uint32, uint64]{MaxEntries: 1}

//bpf:section sockops
func CountEstablished(ctx *bpf.SockOpsMd) bpf.SockOpsReturn {
	var key uint32 = 0
	count, ok := Established.Lookup(&key)
	if !ok {
		return bpf.SockOpsOk
	}
	bpf.AtomicAdd64(count, 1)
	return bpf.SockOpsOk
}

func main() {}
