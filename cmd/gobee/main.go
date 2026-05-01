package main

import (
	"os"

	"github.com/boratanrikulu/gobee/cmd/gobee/app"
)

func main() {
	if err := app.Execute(); err != nil {
		os.Exit(1)
	}
}
