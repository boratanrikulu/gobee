//go:build ignore

// Presence-only map lookups using `_, ok := Map.Lookup(...)`. Two
// lookups in the same scope must not collide on a `_` C identifier;
// gobee mints unique synthetic names per call.

package main

import "github.com/boratanrikulu/gobee/bpf"

//bpf:license GPL

var Allow = bpf.HashMap[uint32, uint8]{MaxEntries: 1024}
var Deny = bpf.HashMap[uint32, uint8]{MaxEntries: 1024}

//bpf:section xdp
func Filter(ctx *bpf.XdpMd) bpf.XdpAction {
	var key uint32 = 1
	_, denied := Deny.Lookup(&key)
	if denied {
		return bpf.XdpDrop
	}
	_, allowed := Allow.Lookup(&key)
	if !allowed {
		return bpf.XdpDrop
	}
	return bpf.XdpPass
}

func main() {}
