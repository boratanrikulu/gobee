//go:build ignore

// Records a per-CPU bucket of packet counts. The CPU id keys the map.
// Demonstrates: bpf_get_smp_processor_id helper, HashMap as a CPU-bucketed
// counter, the standard "lookup, branch, increment-or-init" pattern.

package main

import "github.com/boratanrikulu/gobee/bpf"

//bpf:license GPL

var PerCPU = bpf.HashMap[uint32, uint64]{MaxEntries: 128}

//bpf:section xdp
func CountByCpu(ctx *bpf.XdpMd) bpf.XdpAction {
	var cpu uint32 = bpf.GetSmpProcessorId()
	count, ok := PerCPU.Lookup(&cpu)
	if !ok {
		var one uint64 = 1
		PerCPU.Update(&cpu, &one)
		return bpf.XdpPass
	}
	bpf.AtomicAdd64(count, 1)
	return bpf.XdpPass
}

func main() {}
