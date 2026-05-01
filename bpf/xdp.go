package bpf

// XdpMd mirrors `struct xdp_md` from the Linux kernel. In transpiled C
// it becomes `struct xdp_md *`; field access (e.g. `ctx.IngressIfIndex`)
// is emitted as direct `ctx->ingress_ifindex` access. xdp_md is the BPF
// program context (a UAPI struct with stable layout), not kernel data,
// so CO-RE relocations don't apply.
//
// Each field's `bpf` struct tag carries the C-side field name. When the
// tag is present, the emitter uses it verbatim; otherwise it falls back
// to snake-casing the Go name.
type XdpMd struct {
	Data           uint32 `bpf:"data"`
	DataEnd        uint32 `bpf:"data_end"`
	DataMeta       uint32 `bpf:"data_meta"`
	IngressIfIndex uint32 `bpf:"ingress_ifindex"`
	RxQueueIndex   uint32 `bpf:"rx_queue_index"`
	EgressIfIndex  uint32 `bpf:"egress_ifindex"`
}

// XdpAction is the return type of an XDP program; values map 1:1 to the kernel
// XDP_* constants.
type XdpAction uint32

const (
	XdpAborted  XdpAction = 0
	XdpDrop     XdpAction = 1
	XdpPass     XdpAction = 2
	XdpTx       XdpAction = 3
	XdpRedirect XdpAction = 4
)
