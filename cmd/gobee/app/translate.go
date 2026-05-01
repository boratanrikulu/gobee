package app

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/boratanrikulu/gobee/internal/transpile"
)

var translateCmd = &cobra.Command{
	Use:   "translate <input-dir>",
	Short: "Transpile kernel-side Go to BPF C",
	Long: `Walks <input-dir> for .go files with a //bpf:license directive and
writes a sibling .bpf.c plus .bpf.c.map next to each one. With
--bindings-dir, also emits a typed Go bindings file (<stem>_bindings.go)
into that directory; without it, bindings are skipped and the user is
expected to load programs via stringly-typed coll.Programs lookups.`,
	Args: cobra.ExactArgs(1),
	RunE: runTranslate,
}

func init() {
	translateCmd.Flags().StringP("output", "o", "", "output directory for generated .bpf.c (default: input dir)")
	translateCmd.Flags().String("bindings-dir", "", "directory for the typed Go bindings file; package name is the dir's base name. Empty = skip bindings")

	viper.BindPFlag("output", translateCmd.Flags().Lookup("output"))
	viper.BindPFlag("bindings_dir", translateCmd.Flags().Lookup("bindings-dir"))

	rootCmd.AddCommand(translateCmd)
}

func runTranslate(cmd *cobra.Command, args []string) error {
	results, err := transpile.Run(transpile.RunOptions{
		InputDir:    args[0],
		OutputDir:   viper.GetString("output"),
		BindingsDir: viper.GetString("bindings_dir"),
		Stderr:      os.Stderr,
	})
	if err != nil {
		return fmt.Errorf("translate: %w", err)
	}
	transpile.PrintSummary(os.Stdout, results)
	return nil
}
