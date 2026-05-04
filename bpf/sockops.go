package bpf

// SockOpsMd is the context pointer for sock_ops BPF programs. Renders as
// `struct bpf_sock_ops *` in emitted C. `bpf_sock_ops` is a UAPI BPF
// program context with a stable layout, so field access (e.g. `ctx.Op`,
// `ctx.RemoteIp4`) is emitted as `ctx->op` directly — no BPF_CORE_READ.
type SockOpsMd struct {
	Op                uint32 `bpf:"op"`
	Family            uint32 `bpf:"family"`
	RemoteIp4         uint32 `bpf:"remote_ip4"`
	LocalIp4          uint32 `bpf:"local_ip4"`
	RemotePort        uint32 `bpf:"remote_port"`
	LocalPort         uint32 `bpf:"local_port"`
	IsFullsock        uint32 `bpf:"is_fullsock"`
	State             uint32 `bpf:"state"`
	SndCwnd           uint32 `bpf:"snd_cwnd"`
	SrttUs            uint32 `bpf:"srtt_us"`
	SndNxt            uint32 `bpf:"snd_nxt"`
	RcvNxt            uint32 `bpf:"rcv_nxt"`
	MssCache          uint32 `bpf:"mss_cache"`
	BytesReceived     uint64 `bpf:"bytes_received"`
	BytesAcked        uint64 `bpf:"bytes_acked"`
	SkbLen            uint32 `bpf:"skb_len"`
	SkbTcpFlags       uint32 `bpf:"skb_tcp_flags"`
	BpfSockOpsCbFlags uint32 `bpf:"bpf_sock_ops_cb_flags"`
}

// SockOpsReturn is the return type of a sock_ops program. The kernel
// uses non-zero to mean "drop / abort" for some op variants and ignores
// it for others. Convention is to return SockOpsOk (1) for "continue"
// and 0 for an error path.
type SockOpsReturn uint32

const (
	SockOpsErr SockOpsReturn = 0
	SockOpsOk  SockOpsReturn = 1
)

// Sock-ops operation codes. Matches the kernel's BPF_SOCK_OPS_* enum
// (uapi/linux/bpf.h). Use these to switch on `ctx.Op` or to compare
// against the `op` argument of helpers that take one.
//
// The names mirror the kernel's exactly so Go-side code reads like the C.
const (
	BpfSockOpsVoid                 uint32 = 0
	BpfSockOpsTimeoutInit          uint32 = 1
	BpfSockOpsRwndInit             uint32 = 2
	BpfSockOpsTcpConnectCb         uint32 = 3
	BpfSockOpsActiveEstablishedCb  uint32 = 4
	BpfSockOpsPassiveEstablishedCb uint32 = 5
	BpfSockOpsNeedsEcn             uint32 = 6
	BpfSockOpsBaseRtt              uint32 = 7
	BpfSockOpsRtoCb                uint32 = 8
	BpfSockOpsRetransCb            uint32 = 9
	BpfSockOpsStateCb              uint32 = 10
	BpfSockOpsTcpListenCb          uint32 = 11
	BpfSockOpsRttCb                uint32 = 12
	BpfSockOpsParseHdrOptCb        uint32 = 13
	BpfSockOpsHdrOptLenCb          uint32 = 14
	BpfSockOpsWriteHdrOptCb        uint32 = 15
)

// Sock-ops callback flag bits. Read from / written to
// `ctx.BpfSockOpsCbFlags` to control which TCP events the kernel calls
// the program back on. Names mirror the kernel's BPF_SOCK_OPS_*_CB_FLAG
// enum (uapi/linux/bpf.h). Combine with bitwise OR; pass the result to
// bpf.SockOpsCbFlagsSet to install.
const (
	BpfSockOpsRtoCbFlag                uint32 = 1 << 0
	BpfSockOpsRetransCbFlag            uint32 = 1 << 1
	BpfSockOpsStateCbFlag              uint32 = 1 << 2
	BpfSockOpsRttCbFlag                uint32 = 1 << 3
	BpfSockOpsParseAllHdrOptCbFlag     uint32 = 1 << 4
	BpfSockOpsParseUnknownHdrOptCbFlag uint32 = 1 << 5
	BpfSockOpsWriteHdrOptCbFlag        uint32 = 1 << 6
)
