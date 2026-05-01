//go:build ignore

// Per-CPU packet counter: each CPU gets its own slot, no contention,
// userspace aggregates. Demonstrates `bpf.PerCPUArray`
// (`type=percpu_array`).

package main

import "github.com/boratanrikulu/gobee/bpf"

//bpf:license GPL

var PerCPU = bpf.PerCPUArray[uint32, uint64]{MaxEntries: 1}

//bpf:section xdp
func CountPerCpu(ctx *bpf.XdpMd) bpf.XdpAction {
	var key uint32 = 0
	count, ok := PerCPU.Lookup(&key)
	if !ok {
		return bpf.XdpPass
	}
	bpf.AtomicAdd64(count, 1)
	return bpf.XdpPass
}

func main() {}
