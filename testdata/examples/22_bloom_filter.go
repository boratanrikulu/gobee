//go:build ignore

// A bloom filter that records every uid that called execve. Bloom
// filters answer "have I seen X?" with no false negatives but possible
// false positives — useful for cheap deduplication when you don't need
// per-key state.

package main

import "github.com/boratanrikulu/gobee/bpf"

//bpf:license GPL

var seenUids = bpf.BloomFilter[uint32]{MaxEntries: 4096}

//bpf:section tracepoint/syscalls/sys_enter_execve
func RememberUid(ctx *bpf.SyscallEnterCtx) bpf.TpReturn {
	var uid uint32 = bpf.GetCurrentUid()
	seenUids.Add(&uid)
	return bpf.TpOk
}

func main() {}
