package transpile

import (
	"fmt"
	"go/types"
)

const bpfPkgPath = "github.com/boratanrikulu/gobee/bpf"

// goTypeToC maps a resolved Go type to its emitted C representation.
// Pointer types render as `<C base type> *`; named bpf-package types map to
// their kernel-side C equivalents.
func goTypeToC(t types.Type) (string, error) {
	switch tt := t.(type) {
	case *types.Basic:
		return basicToC(tt)
	case *types.Pointer:
		base, err := goTypeToC(tt.Elem())
		if err != nil {
			return "", err
		}
		return base + " *", nil
	case *types.Named:
		return namedToC(tt)
	}
	return "", fmt.Errorf("unsupported type: %s", t.String())
}

func basicToC(b *types.Basic) (string, error) {
	switch b.Kind() {
	case types.Bool:
		return "bool", nil
	case types.Int8:
		return "__s8", nil
	case types.Int16:
		return "__s16", nil
	case types.Int32, types.UntypedInt:
		return "__s32", nil
	case types.Int64:
		return "__s64", nil
	case types.Uint8:
		return "__u8", nil
	case types.Uint16:
		return "__u16", nil
	case types.Uint32:
		return "__u32", nil
	case types.Uint64:
		return "__u64", nil
	case types.UnsafePointer:
		return "void *", nil
	}
	return "", fmt.Errorf("unsupported basic type: %s", b.Name())
}

// bpfTypeInfo describes how a Go type from the bpf package maps to C.
// One entry per type. Adding a new bpf-package type = one row, no other
// places to update.
type bpfTypeInfo struct {
	cType        string // emitted C type ("struct xdp_md", "int", "void", ...)
	needsVmlinux bool   // forces `#include "vmlinux.h"` because the C type lives there
	fieldsCORE   bool   // field reads emit BPF_CORE_READ (kernel-context structs)
}

var bpfPackageTypes = map[string]bpfTypeInfo{
	// XDP. xdp_md is the BPF program context (UAPI struct, stable layout)
	// — direct ctx->field access only. CO-RE/probe_read on a context
	// pointer fails silently at runtime, leaving counters stuck at zero.
	"XdpMd":     {"struct xdp_md", false, false},
	"XdpAction": {"int", false, false},
	// Tracepoint
	"TracepointCtx":   {"void", false, false},
	"TpReturn":        {"int", false, false},
	"SyscallEnterCtx": {"struct trace_event_raw_sys_enter", true, false},
	"SyscallExitCtx":  {"struct trace_event_raw_sys_exit", true, false},
	// Per-syscall typed contexts. All render as the same kernel struct;
	// named Go fields map to `args[N]` via struct tags so users get
	// `ctx.Filename` instead of `ctx.Args[0]`.
	"ExecveEnterCtx": {"struct trace_event_raw_sys_enter", true, false},
	"OpenatEnterCtx": {"struct trace_event_raw_sys_enter", true, false},
	// Kprobe / uprobe
	"PtRegs":   {"struct pt_regs", false, false},
	"KpReturn": {"int", false, false},
	// Sock ops. bpf_sock_ops is a BPF context — direct field access.
	"SockOpsMd":     {"struct bpf_sock_ops", false, false},
	"SockOpsReturn": {"int", false, false},
	// TC and cgroup_skb. __sk_buff is a BPF context — direct field access.
	"SkBuff":          {"struct __sk_buff", false, false},
	"TcAction":        {"int", false, false},
	"CgroupSkbReturn": {"int", false, false},
	// LSM
	"LsmCtx":    {"void", false, false},
	"LsmReturn": {"int", false, false},
}

// bpfPackageTypeInfo returns the bpfTypeInfo for a Named type if it's
// declared in the gobee bpf package; ok=false otherwise.
func bpfPackageTypeInfo(n *types.Named) (bpfTypeInfo, bool) {
	obj := n.Obj()
	if obj.Pkg() == nil || obj.Pkg().Path() != bpfPkgPath {
		return bpfTypeInfo{}, false
	}
	info, ok := bpfPackageTypes[obj.Name()]
	return info, ok
}

func namedToC(n *types.Named) (string, error) {
	if info, ok := bpfPackageTypeInfo(n); ok {
		return info.cType, nil
	}
	// User-defined named type. Always a struct (the validator rejects
	// methods and the parser only collects struct decls). C requires the
	// `struct` qualifier when referencing a struct by tag name.
	return "struct " + n.Obj().Name(), nil
}
