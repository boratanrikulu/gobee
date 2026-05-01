//go:build ignore

// Counts packets per ingress interface index. Demonstrates CO-RE field
// access: `ctx.IngressIfIndex` becomes `BPF_CORE_READ(ctx, ingress_ifindex)`
// in the emitted C, which is BTF-relocated at load time and works across
// kernel versions.

package main

import "github.com/boratanrikulu/gobee/bpf"

//bpf:license GPL

var PerIface = bpf.HashMap[uint32, uint64]{MaxEntries: 64}

//bpf:section xdp
func CountPerIface(ctx *bpf.XdpMd) bpf.XdpAction {
	var ifindex uint32 = ctx.IngressIfIndex
	count, ok := PerIface.Lookup(&ifindex)
	if !ok {
		var one uint64 = 1
		PerIface.Update(&ifindex, &one)
		return bpf.XdpPass
	}
	bpf.AtomicAdd64(count, 1)

	return bpf.XdpPass
}

func main() {}
