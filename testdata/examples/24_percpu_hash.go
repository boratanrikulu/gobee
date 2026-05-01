//go:build ignore

// Per-CPU hash counter. PerCPUHash gives every CPU its own copy of every
// slot — kernel-side reads/writes don't need atomics because each CPU
// only touches its own slot. Userspace sums across CPUs at read time.

package main

import "github.com/boratanrikulu/gobee/bpf"

//bpf:license GPL

var hits = bpf.PerCPUHash[uint32, uint64]{MaxEntries: 1024}

//bpf:section tracepoint/syscalls/sys_enter_openat
func CountByPid(ctx *bpf.SyscallEnterCtx) bpf.TpReturn {
	var pid uint32 = bpf.GetCurrentPid()
	count, ok := hits.Lookup(&pid)
	if !ok {
		var one uint64 = 1
		hits.Update(&pid, &one)
		return bpf.TpOk
	}
	*count = *count + 1
	return bpf.TpOk
}

func main() {}
