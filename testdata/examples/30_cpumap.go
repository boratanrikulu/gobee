//go:build ignore

// Steers XDP packets onto another CPU via a cpumap. Userspace pins
// each slot to a target CPU plus an optional follow-up program.
// Useful for separating the XDP fast path from the kernel network
// stack when both run on the same NIC.

package main

import "github.com/boratanrikulu/gobee/bpf"

//bpf:license GPL

var workers = bpf.CpuMap{MaxEntries: 12}

//bpf:section xdp
func ToCpu(ctx *bpf.XdpMd) bpf.XdpAction {
	var key uint32 = ctx.RxQueueIndex
	return workers.Redirect(ctx, key, 0)
}

func main() {}
