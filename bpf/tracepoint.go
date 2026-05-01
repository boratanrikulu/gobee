package bpf

// TracepointCtx is the context pointer passed to a tracepoint BPF program.
// Renders as `void *` in emitted C because each tracepoint hook has its
// own auto-generated `struct trace_event_raw_<name>` and modeling them all
// in Go is impractical. To read tracepoint arguments, use the
// `bpf.ProbeReadKernel` family of helpers against the raw context pointer.
type TracepointCtx struct{}

// TpReturn is the return type of a tracepoint program. Legacy tracepoints
// always return 0; non-zero values are reserved for future kernel use and
// are currently ignored.
type TpReturn uint32

// TpOk is the canonical "I'm done, no error" return value for a tracepoint
// program.
const TpOk TpReturn = 0
