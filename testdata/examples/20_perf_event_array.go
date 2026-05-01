//go:build ignore

// Emits the kernel timestamp on every packet via a perf_event_array.
// Demonstrates `bpf.PerfEventArray[T].Output(ctx, &val)`. For new code
// prefer ringbuf — perf_event_array exists for kernels older than 5.8.

package main

import (
	"unsafe"

	"github.com/boratanrikulu/gobee/bpf"
)

//bpf:license GPL

type SampleEvent struct {
	TimeNs uint64
}

var Events = bpf.PerfEventArray[SampleEvent]{MaxEntries: 128}

//bpf:section xdp
func Sample(ctx *bpf.XdpMd) bpf.XdpAction {
	var e SampleEvent
	e.TimeNs = bpf.KtimeGetNs()
	Events.Output(unsafe.Pointer(ctx), &e)
	return bpf.XdpPass
}

func main() {}
