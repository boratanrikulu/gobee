// Package bpf is the kernel-side API used by gobee programs.
//
// All function and method bodies in this package are panic stubs. Files that
// import this package must be tagged with `//go:build ignore` and processed
// by `gobee translate` rather than compiled with `go build`. If a stub ever
// runs, it panics with a message indicating that the program was not
// transpiled.
//
// # What's in this package
//
//   - Program-type context structs and return enums: XdpMd / XdpAction,
//     TracepointCtx / TpReturn, PtRegs / KpReturn (kprobe + uprobe),
//     SockOpsMd / SockOpsReturn, SkBuff / TcAction / CgroupSkbReturn,
//     LsmCtx / LsmReturn.
//   - BPF map types: ArrayMap[K, V] and HashMap[K, V] with Lookup
//     (comma-ok), Update, Delete.
//   - The AtomicAdd64 clang intrinsic.
//   - The full libbpf helper surface (~200 functions) auto-generated
//     into helpers_generated.go from bpf_helper_defs.h.
//
// docs/status.md in the gobee repository is the single source of truth
// for what is supported, in progress, planned, or rejected.
package bpf
