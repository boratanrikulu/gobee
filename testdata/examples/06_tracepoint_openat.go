//go:build ignore

// Counts every openat(2) syscall in a single ArrayMap slot. Demonstrates
// the tracepoint program type with no ctx-field access (pre-CO-RE
// friendly). Attach in userspace via cilium/ebpf's link.Tracepoint.

package main

import "github.com/boratanrikulu/gobee/bpf"

//bpf:license GPL

var Opens = bpf.ArrayMap[uint32, uint64]{MaxEntries: 1}

//bpf:section tracepoint/syscalls/sys_enter_openat
func HandleOpenat(ctx *bpf.TracepointCtx) bpf.TpReturn {
	var key uint32 = 0
	count, ok := Opens.Lookup(&key)
	if !ok {
		return bpf.TpOk
	}
	bpf.AtomicAdd64(count, 1)
	return bpf.TpOk
}

func main() {}
