package bpf

// Byte-order helpers for reading network-endian fields like
// `bpf_sock_ops::remote_port` (a __be32 ABI). These are clang macros
// from <bpf/bpf_endian.h>, not BPF kernel helpers, so they aren't part
// of helpers_generated.go. The transpiler emits them as bpf_ntohl /
// bpf_htonl / bpf_ntohs / bpf_htons and adds the include when used.

// Ntohl converts a 32-bit value from network to host byte order.
func Ntohl(v uint32) uint32 { panic(stubMsg) }

// Htonl converts a 32-bit value from host to network byte order.
func Htonl(v uint32) uint32 { panic(stubMsg) }

// Ntohs converts a 16-bit value from network to host byte order.
func Ntohs(v uint16) uint16 { panic(stubMsg) }

// Htons converts a 16-bit value from host to network byte order.
func Htons(v uint16) uint16 { panic(stubMsg) }
