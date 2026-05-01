package bpf

// SyscallEnterCtx is the typed context for syscall-entry tracepoints
// (`tracepoint/syscalls/sys_enter_*`). Renders as
// `struct trace_event_raw_sys_enter *` in the emitted C.
//
// Args[0..5] are the raw syscall arguments. For execve, Args[0] is a
// userspace pointer to the program filename and Args[1] is a userspace
// pointer to the argv array. Use `bpf.ReadUserStrInto` to copy a string
// out of userspace into a local buffer.
type SyscallEnterCtx struct {
	Id   int64     `bpf:"id"`
	Args [6]uint64 `bpf:"args"`
}

// SyscallExitCtx is the typed context for syscall-exit tracepoints
// (`tracepoint/syscalls/sys_exit_*`). Ret is the syscall return value.
type SyscallExitCtx struct {
	Id  int64 `bpf:"id"`
	Ret int64 `bpf:"ret"`
}

// ExecveEnterCtx is the syscall-specific context for
// `tracepoint/syscalls/sys_enter_execve`. Each field is a userspace
// pointer (uint64) named after the execve(2) argument it carries.
//
// Renders in C as `struct trace_event_raw_sys_enter *`; the named Go
// fields map back to `args[0]`, `args[1]`, `args[2]` via struct tags,
// so `ctx.Filename` emits as `ctx->args[0]`.
type ExecveEnterCtx struct {
	Filename uint64 `bpf:"args[0]"`
	Argv     uint64 `bpf:"args[1]"`
	Envp     uint64 `bpf:"args[2]"`
}

// OpenatEnterCtx is the syscall-specific context for
// `tracepoint/syscalls/sys_enter_openat`.
type OpenatEnterCtx struct {
	Dfd      uint64 `bpf:"args[0]"`
	Filename uint64 `bpf:"args[1]"`
	Flags    uint64 `bpf:"args[2]"`
	Mode     uint64 `bpf:"args[3]"`
}
