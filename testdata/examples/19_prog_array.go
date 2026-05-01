//go:build ignore

// Tail-calls into the program registered at index 0 of a prog_array.
// Userspace populates the array with program FDs at runtime.
// Demonstrates `bpf.ProgArray` and tail calls.

package main

import (
	"unsafe"

	"github.com/boratanrikulu/gobee/bpf"
)

//bpf:license GPL

var Stages = bpf.ProgArray{MaxEntries: 8}

//bpf:section xdp
func Dispatch(ctx *bpf.XdpMd) bpf.XdpAction {
	var stage uint32 = 0
	Stages.TailCall(unsafe.Pointer(ctx), stage)
	return bpf.XdpPass
}

func main() {}
