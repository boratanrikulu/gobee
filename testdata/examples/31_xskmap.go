//go:build ignore

// Hands every packet to an AF_XDP socket via an xskmap. Userspace
// binds each slot to an AF_XDP socket fd; this XDP program forwards
// the packet to the socket bound to the ingress queue, bypassing
// the kernel network stack entirely (zero-copy receive).

package main

import "github.com/boratanrikulu/gobee/bpf"

//bpf:license GPL

var xsks = bpf.XskMap{MaxEntries: 64}

//bpf:section xdp
func ToUserspace(ctx *bpf.XdpMd) bpf.XdpAction {
	var key uint32 = ctx.RxQueueIndex
	return xsks.Redirect(ctx, key, 0)
}

func main() {}
