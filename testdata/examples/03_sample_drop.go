//go:build ignore

// Probabilistically drops 1-in-N packets using bpf_get_prandom_u32. Useful
// as a chaos-testing tool. Demonstrates: a different XDP return value
// (XdpDrop), a helper with a uint32 return used in a comparison, no maps.

package main

import "github.com/boratanrikulu/gobee/bpf"

//bpf:license GPL

//bpf:section xdp
func SampleDrop(ctx *bpf.XdpMd) bpf.XdpAction {
	var r uint32 = bpf.GetPrandomU32()
	if r%16 == 0 {
		return bpf.XdpDrop
	}
	return bpf.XdpPass
}

func main() {}
