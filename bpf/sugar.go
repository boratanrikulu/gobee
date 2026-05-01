package bpf

// This file holds typed convenience wrappers over the auto-generated
// libbpf helpers. They exist purely so kernel-side Go code reads
// naturally; the gobee emitter inlines each one into the matching libbpf
// helper expression at transpile time.

// GetCurrentPid returns the calling task's process ID (the upper 32 bits
// of bpf_get_current_pid_tgid). Equivalent to what userspace tools call
// "PID".
func GetCurrentPid() uint32 { panic(stubMsg) }

// GetCurrentTid returns the calling thread's ID (the lower 32 bits of
// bpf_get_current_pid_tgid). Equivalent to gettid(2).
func GetCurrentTid() uint32 { panic(stubMsg) }

// GetCurrentUid returns the calling task's effective UID (the lower 32
// bits of bpf_get_current_uid_gid).
func GetCurrentUid() uint32 { panic(stubMsg) }

// GetCurrentGid returns the calling task's effective GID (the upper 32
// bits of bpf_get_current_uid_gid).
func GetCurrentGid() uint32 { panic(stubMsg) }

// GetTaskComm fills buf with the calling task's command name (the
// kernel's TASK_COMM_LEN is 16, NUL-padded). Returns 0 on success, a
// negative errno on failure.
func GetTaskComm(buf *[16]byte) int64 { panic(stubMsg) }

// GetUserString copies a NUL-terminated string from the userspace
// pointer addr into buf, up to its length. Returns the number of bytes
// copied including the terminating NUL on success, or a negative errno.
func GetUserString(buf *[128]byte, addr uint64) int64 { panic(stubMsg) }

// GetUserArgv reads up to 8 entries of the userspace argv array (a
// `char *const *`) into buf as 32-byte slots. Returns the number of
// bytes written.
func GetUserArgv(buf *[256]byte, argv uint64) int64 { panic(stubMsg) }
