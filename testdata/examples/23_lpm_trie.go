//go:build ignore

// IPv4 longest-prefix-match trie. Routing tables and ACLs use this map
// type because lookups walk the trie once and return the most specific
// match. The key must lead with `__u32 prefixlen` (the libbpf ABI).

package main

import "github.com/boratanrikulu/gobee/bpf"

//bpf:license GPL

type V4Key struct {
	PrefixLen uint32
	Addr      uint32
}

var blocklist = bpf.LpmTrie[V4Key, uint32]{MaxEntries: 1024}

//bpf:section xdp
func DropBlocked(ctx *bpf.XdpMd) bpf.XdpAction {
	var key V4Key
	key.PrefixLen = 32
	key.Addr = ctx.IngressIfIndex
	hit, ok := blocklist.Lookup(&key)
	if !ok {
		return bpf.XdpPass
	}
	if *hit == 1 {
		return bpf.XdpDrop
	}
	return bpf.XdpPass
}

func main() {}
