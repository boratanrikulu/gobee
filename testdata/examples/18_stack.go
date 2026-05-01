//go:build ignore

// Push every packet's ingress ifindex onto a LIFO stack. Userspace pops
// to drain. Demonstrates `bpf.Stack[T]` with `type=stack`.

package main

import "github.com/boratanrikulu/gobee/bpf"

//bpf:license GPL

var Recent = bpf.Stack[uint32]{MaxEntries: 1024}

//bpf:section xdp
func PushIface(ctx *bpf.XdpMd) bpf.XdpAction {
	var idx uint32 = ctx.IngressIfIndex
	Recent.Push(&idx)
	return bpf.XdpPass
}

func main() {}
