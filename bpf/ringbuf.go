package bpf

// RingBuf is a BPF_MAP_TYPE_RINGBUF for delivering events from kernel to
// userspace. MaxEntries is the byte size of the ring (must be a power of
// 2, at least 4096).
//
// Typical usage:
//
//	type Event struct {
//	    Pid  uint32
//	    Comm [16]byte
//	}
//
//	var Events = bpf.RingBuf[Event]{MaxEntries: 4096}
//
//	e, ok := Events.Reserve()
//	if !ok {
//	    return bpf.TpOk
//	}
//	e.Pid = bpf.GetCurrentPid()
//	Events.Submit(e)
//
// Reserve / Submit / Discard is the zero-copy path. Output is a one-shot
// helper that allocates, copies, and submits in one call; prefer
// Reserve/Submit unless the event is a constant-sized small value.
type RingBuf[T any] struct {
	MaxEntries uint32
}

// Reserve allocates space for one event in the ring. Returns (event, true)
// on success or (nil, false) if the ring is full. The bool is the
// recognized comma-ok marker; the emitter aliases it to a non-nil pointer
// check.
func (*RingBuf[T]) Reserve() (*T, bool) { panic(stubMsg) }

// Submit publishes a previously reserved event so the userspace reader
// can see it.
func (*RingBuf[T]) Submit(event *T) { panic(stubMsg) }

// Discard drops a previously reserved event without publishing it. Use
// this on the error path to avoid leaking ring budget.
func (*RingBuf[T]) Discard(event *T) { panic(stubMsg) }

// Output is the one-shot variant of Reserve+Submit: it allocates, copies
// the value, and submits in a single call. Returns 0 on success or a
// negative errno on failure.
func (*RingBuf[T]) Output(event *T) int64 { panic(stubMsg) }
