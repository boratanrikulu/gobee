//go:build ignore

// A cgroup_skb egress program that allows all traffic and counts
// packets. Demonstrates the cgroup_skb program type, the same SkBuff
// context as TC, and the boolean-shaped CgroupSkbReturn enum.

package main

import "github.com/boratanrikulu/gobee/bpf"

//bpf:license GPL

var EgressPkts = bpf.ArrayMap[uint32, uint64]{MaxEntries: 1}

//bpf:section cgroup_skb/egress
func CountEgress(ctx *bpf.SkBuff) bpf.CgroupSkbReturn {
	var key uint32 = 0
	count, ok := EgressPkts.Lookup(&key)
	if !ok {
		return bpf.CgroupSkbAllow
	}
	bpf.AtomicAdd64(count, 1)
	return bpf.CgroupSkbAllow
}

func main() {}
