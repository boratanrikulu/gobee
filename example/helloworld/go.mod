module example.com/gobee-helloworld

go 1.24.1

replace github.com/boratanrikulu/gobee => ../..

require (
	github.com/boratanrikulu/bpfvet v0.2.1
	github.com/boratanrikulu/gobee v0.0.0-00010101000000-000000000000
	github.com/cilium/ebpf v0.21.0
	golang.org/x/sys v0.37.0
)
