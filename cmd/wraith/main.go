package main

import (
	"context"
	"fmt"
	"os"

	"github.com/Adam-Ghanem/Wraith/internal/cli"
)

func main() {
	args := os.Args[1:]
	if cli.PrintOfflineHelp(args, os.Stdout) {
		return
	}
	if err := cli.Run(context.Background(), args, os.Stdout, os.Stderr); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(cli.ExitCode(err))
	}
}
