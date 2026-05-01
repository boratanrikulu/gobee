package bpf

// LsmCtx is the context pointer passed to an LSM (Linux Security Module)
// BPF program. Renders as `void *` in the emitted C.
//
// LSM has ~200 hooks (file_open, bprm_check_security, socket_connect, …),
// each with its own argument shape. gobee does not model every hook
// individually; all LSM programs receive `*bpf.LsmCtx`, and to inspect
// hook arguments you use the `bpf.ProbeReadKernel` family of helpers or
// drop the hook-specific signature in via an inline-C block.
type LsmCtx struct{}

// LsmReturn is the return type of an LSM program. The kernel treats 0 as
// "allow" and any negative value as a denial (typically `-EPERM`,
// `-EACCES`, etc.). Positive values are reserved.
type LsmReturn int32

const (
	// LsmAllow lets the operation proceed.
	LsmAllow LsmReturn = 0

	// LsmDeny refuses the operation. Equivalent to `-1`. For a specific
	// errno, return a literal negative integer (e.g. `return -13` for
	// `-EACCES`).
	LsmDeny LsmReturn = -1
)
