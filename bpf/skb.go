package bpf

// SkBuff is the context pointer for TC (classifier/action) and cgroup_skb
// programs. Renders as `struct __sk_buff *` in the emitted C. Field access
// (e.g. `ctx.Len`, `ctx.IngressIfindex`) is emitted as
// `BPF_CORE_READ(ctx, len)` etc. so it gets BTF-relocated at load time.
type SkBuff struct {
	Len            uint32 `bpf:"len"`
	PktType        uint32 `bpf:"pkt_type"`
	Mark           uint32 `bpf:"mark"`
	QueueMapping   uint32 `bpf:"queue_mapping"`
	Protocol       uint32 `bpf:"protocol"`
	VlanPresent    uint32 `bpf:"vlan_present"`
	VlanTci        uint32 `bpf:"vlan_tci"`
	VlanProto      uint32 `bpf:"vlan_proto"`
	Priority       uint32 `bpf:"priority"`
	IngressIfindex uint32 `bpf:"ingress_ifindex"`
	Ifindex        uint32 `bpf:"ifindex"`
	TcIndex        uint32 `bpf:"tc_index"`
	Hash           uint32 `bpf:"hash"`
	TcClassid      uint32 `bpf:"tc_classid"`
	Data           uint32 `bpf:"data"`
	DataEnd        uint32 `bpf:"data_end"`
	NapiId         uint32 `bpf:"napi_id"`
	Family         uint32 `bpf:"family"`
	RemoteIp4      uint32 `bpf:"remote_ip4"`
	LocalIp4       uint32 `bpf:"local_ip4"`
	RemotePort     uint32 `bpf:"remote_port"`
	LocalPort      uint32 `bpf:"local_port"`
	DataMeta       uint32 `bpf:"data_meta"`
	Tstamp         uint64 `bpf:"tstamp"`
}

// TcAction is the return type of a TC classifier/action program.
type TcAction int32

// TC_ACT_* values mirror the kernel's `pkt_sched.h` enum.
const (
	TcUnspec     TcAction = -1
	TcOk         TcAction = 0
	TcReclassify TcAction = 1
	TcShot       TcAction = 2
	TcPipe       TcAction = 3
	TcStolen     TcAction = 4
	TcQueued     TcAction = 5
	TcRepeat     TcAction = 6
	TcRedirect   TcAction = 7
	TcTrap       TcAction = 8
)

// CgroupSkbReturn is the return type of a cgroup_skb program. The kernel
// treats 0 as "drop" and 1 as "allow"; everything else is reserved.
type CgroupSkbReturn uint32

const (
	CgroupSkbDrop  CgroupSkbReturn = 0
	CgroupSkbAllow CgroupSkbReturn = 1
)
