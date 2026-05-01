//go:build ignore

// Deliberately broken kernel-side program. Looks up a map slot, then
// dereferences the result without checking the nil-ok return. The BPF
// verifier rejects this because the helper "may return NULL" and we'd
// be reading from a null pointer.
//
// Used by e2e/loader_test.go to prove Load<Stem> annotates the
// verifier error with Go source positions.

package main

import "github.com/boratanrikulu/gobee/bpf"

//bpf:license GPL

var Counter = bpf.HashMap[uint32, uint64]{MaxEntries: 1}

//bpf:section xdp
func Bad(ctx *bpf.XdpMd) bpf.XdpAction {
	var key uint32 = 0
	count, _ := Counter.Lookup(&key)
	bpf.AtomicAdd64(count, 1)
	return bpf.XdpPass
}

func main() {}
