//go:build ignore

// Counts packets per source port using an LRU hash, so the table never
// fills up: when full the kernel evicts the least-recently-used entry.
// Demonstrates `bpf.LruHashMap` (`type=lru_hash`).

package main

import "github.com/boratanrikulu/gobee/bpf"

//bpf:license GPL

var PerPort = bpf.LruHashMap[uint16, uint64]{MaxEntries: 4096}

//bpf:section xdp
func CountPerPort(ctx *bpf.XdpMd) bpf.XdpAction {
	var port uint16 = 80
	count, ok := PerPort.Lookup(&port)
	if !ok {
		var one uint64 = 1
		PerPort.Update(&port, &one)
		return bpf.XdpPass
	}
	bpf.AtomicAdd64(count, 1)
	return bpf.XdpPass
}

func main() {}
