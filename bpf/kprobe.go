package bpf

// PtRegs is the context pointer for kprobe, kretprobe, uprobe, and
// uretprobe BPF programs. Renders as `struct pt_regs *` in the emitted C.
//
// pt_regs has an arch-specific layout (the register file at the moment
// the probe fired). To read register values, use the
// `bpf.ProbeReadKernel` family of helpers, or the libbpf `PT_REGS_PARMn`
// macros from inline-C escape hatches.
type PtRegs struct{}

// KpReturn is the return type of kprobe / kretprobe / uprobe / uretprobe
// programs. The kernel ignores the value; convention is to return 0.
type KpReturn uint32

// KpOk is the canonical no-op return for probe-style programs.
const KpOk KpReturn = 0
