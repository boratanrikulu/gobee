package app

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/boratanrikulu/gobee/diagnose"
)

var diagnoseCmd = &cobra.Command{
	Use:   "diagnose",
	Short: "Annotate a BPF verifier log with Go source positions",
	Long: `Reads a BPF verifier log on stdin and writes an annotated copy on
stdout. Each C-line reference the sourcemap covers gets a Go source
position (<file>:<line>:<col>) inserted next to it.

Run gobee translate first to produce the .bpf.c.map sourcemap, then pipe
the verifier log into this command:

  cat verifier.log | gobee diagnose -m bpf/src/counter.bpf.c.map`,
	RunE: runDiagnose,
}

func init() {
	diagnoseCmd.Flags().StringP("map", "m", "", "path to the .bpf.c.map sourcemap (required)")
	_ = diagnoseCmd.MarkFlagRequired("map")

	viper.BindPFlag("diagnose_map", diagnoseCmd.Flags().Lookup("map"))

	rootCmd.AddCommand(diagnoseCmd)
}

func runDiagnose(cmd *cobra.Command, args []string) error {
	mapPath := viper.GetString("diagnose_map")
	f, err := os.Open(mapPath)
	if err != nil {
		return fmt.Errorf("open sourcemap: %w", err)
	}
	defer f.Close()
	sm, err := diagnose.ParseSourceMap(f)
	if err != nil {
		return fmt.Errorf("parse sourcemap: %w", err)
	}
	if err := diagnose.Rewrite(os.Stdin, os.Stdout, sm); err != nil {
		return fmt.Errorf("rewrite: %w", err)
	}
	return nil
}
