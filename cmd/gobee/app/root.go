package app

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const Version = "0.0.1-dev"

var rootCmd = &cobra.Command{
	Use:     "gobee",
	Short:   "gobee. Go-native eBPF kernel programming",
	Version: Version,
	Long: `gobee transpiles a Go subset to BPF C and generates typed Go bindings
for the userspace side. You compile the emitted .bpf.c with clang and load
the .o via cilium/ebpf, exactly like a hand-written BPF program. gobee does
not invoke clang or any build tooling.

Support matrix: see docs/status.md.`,
}

func init() {
	// Bind GOBEE_* env vars to the same names as the flags so CI and Docker
	// callers can drive gobee without long argv chains.
	viper.SetEnvPrefix("GOBEE")
	viper.AutomaticEnv()
}

// Execute runs the root command. Returns any error encountered so main.go
// can decide on the exit code.
func Execute() error {
	return rootCmd.Execute()
}
