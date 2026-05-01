//go:build ignore

package main

import "github.com/boratanrikulu/gobee/bpf"

//bpf:license GPL

var PktCount = bpf.ArrayMap[uint32, uint64]{MaxEntries: 1}

//bpf:section xdp
func CountPackets(ctx *bpf.XdpMd) bpf.XdpAction {
	var key uint32 = 0
	count, ok := PktCount.Lookup(&key)
	if !ok {
		return bpf.XdpPass
	}
	bpf.AtomicAdd64(count, 1)
	return bpf.XdpPass
}

func main() {}
