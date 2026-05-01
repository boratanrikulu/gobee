//go:build ignore

// Push every packet's ingress ifindex into a FIFO queue. Userspace pops
// to drain. Demonstrates `bpf.Queue[T]` with `type=queue`.

package main

import "github.com/boratanrikulu/gobee/bpf"

//bpf:license GPL

var Iface = bpf.Queue[uint32]{MaxEntries: 1024}

//bpf:section xdp
func PushIface(ctx *bpf.XdpMd) bpf.XdpAction {
	var idx uint32 = ctx.IngressIfIndex
	Iface.Push(&idx)
	return bpf.XdpPass
}

func main() {}
