//go:build ignore

// LRU per-CPU hash. Combines per-CPU isolation (no atomics needed) with
// LRU eviction (oldest entries get pushed out when the map fills). Useful
// for bounded-memory caches in hot tracing paths.

package main

import "github.com/boratanrikulu/gobee/bpf"

//bpf:license GPL

var cache = bpf.LruPerCPUHash[uint32, uint64]{MaxEntries: 256}

//bpf:section kprobe/__x64_sys_openat
func RecordPid(ctx *bpf.PtRegs) bpf.KpReturn {
	var pid uint32 = bpf.GetCurrentPid()
	var ts uint64 = bpf.KtimeGetNs()
	cache.Update(&pid, &ts)
	return bpf.KpOk
}

func main() {}
