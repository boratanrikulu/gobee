//go:build ignore

// Records the kernel-time of the most recently observed packet in a single
// ArrayMap slot. Demonstrates: zero-argument helper returning a primitive
// (KtimeGetNs), explicit map Update via the map var's method, no comma-ok.

package main

import "github.com/boratanrikulu/gobee/bpf"

//bpf:license GPL

var LastSeen = bpf.ArrayMap[uint32, uint64]{MaxEntries: 1}

//bpf:section xdp
func StampPackets(ctx *bpf.XdpMd) bpf.XdpAction {
	var key uint32 = 0
	var now uint64 = bpf.KtimeGetNs()
	LastSeen.Update(&key, &now)
	return bpf.XdpPass
}

func main() {}
