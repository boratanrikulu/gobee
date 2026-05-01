//go:build ignore

// Trivial XDP load balancer using a devmap. Userspace populates
// `txPort` with target interface indexes; the XDP program forwards
// every incoming packet out the slot keyed by the ingress queue.
//
// Demonstrates DevMap.Redirect, the kernel-side method that compiles
// to bpf_redirect_map. The same pattern works for CpuMap (slot is a
// CPU descriptor) and XskMap (slot is an AF_XDP socket fd).

package main

import "github.com/boratanrikulu/gobee/bpf"

//bpf:license GPL

var txPort = bpf.DevMap{MaxEntries: 64}

//bpf:section xdp
func Forward(ctx *bpf.XdpMd) bpf.XdpAction {
	var key uint32 = ctx.RxQueueIndex
	return txPort.Redirect(ctx, key, 0)
}

func main() {}
