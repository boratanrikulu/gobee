//go:build ignore

// A trivial TC classifier that lets every packet through (TC_ACT_OK).
// Demonstrates the TC program type, *bpf.SkBuff context, and the
// TcAction enum. Real classifiers walk the packet via ctx.Data /
// ctx.DataEnd, which becomes a CO-RE-relocated read in the emitted C.

package main

import "github.com/boratanrikulu/gobee/bpf"

//bpf:license GPL

//bpf:section classifier/ingress
func PassThrough(ctx *bpf.SkBuff) bpf.TcAction {
	return bpf.TcOk
}

func main() {}
