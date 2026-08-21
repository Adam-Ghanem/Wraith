package main

import (
	"context"
	"fmt"
	"os"

	"github.com/Adam-Ghanem/Wraith/internal/cli"
)

func main() {
	args := os.Args[1:]
	var err error
	if len(args) > 0 && args[0] == "scan" {
		err = cli.RunStandaloneScan(context.Background(), args, os.Stdout, os.Stderr)
	} else {
		err = cli.Run(context.Background(), args, os.Stdout, os.Stderr)
	}
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(cli.ExitCode(err))
	}
}
