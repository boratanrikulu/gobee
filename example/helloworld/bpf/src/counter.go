//go:build ignore

package main

import "github.com/boratanrikulu/gobee/bpf"

//bpf:license GPL

var PerIface = bpf.HashMap[uint32, uint64]{MaxEntries: 64}

//bpf:section xdp
func CountPackets(ctx *bpf.XdpMd) bpf.XdpAction {
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
