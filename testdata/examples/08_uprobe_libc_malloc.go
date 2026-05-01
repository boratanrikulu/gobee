//go:build ignore

// Counts userspace calls to libc's malloc() across all processes. The
// uprobe section format is `uprobe/<binary>:<sym>`; the kernel locates
// the binary by path and patches the entry point. Reuses the kprobe
// PtRegs context type — same shape on the BPF side.

package main

import "github.com/boratanrikulu/gobee/bpf"

//bpf:license GPL

var Mallocs = bpf.ArrayMap[uint32, uint64]{MaxEntries: 1}

//bpf:section uprobe/libc.so.6:malloc
func MallocEntry(ctx *bpf.PtRegs) bpf.KpReturn {
	var key uint32 = 0
	count, ok := Mallocs.Lookup(&key)
	if !ok {
		return bpf.KpOk
	}
	bpf.AtomicAdd64(count, 1)
	return bpf.KpOk
}

func main() {}
