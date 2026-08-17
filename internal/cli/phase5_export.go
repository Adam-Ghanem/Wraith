package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/Adam-Ghanem/Wraith/internal/enum"
)

// Phase 5 policy: export-fixtures is an authorized, read-only fixture writer.
// It delegates to the existing scan/history commands and their canonical JSON encoders.
const fixtureScanFileName = "scan.json"
const fixtureHistoryFileName = "history.json"

type ExportFixturesOptions struct {
	Domain       string
	DatabasePath string
	OutputDir    string
	Authorized   bool
	Verbose      bool
}

var fixtureScanRunner = runScan
var fixtureHistoryRunner = runHistory

func parseExportFixturesOptions(args []string) (ExportFixturesOptions, error) {
	if len(args) == 0 || args[0] != "export-fixtures" {
		return ExportFixturesOptions{}, errors.New("usage: wraith export-fixtures -d DOMAIN --db wraith.db --out ./fixtures --authorized")
	}
	fs := flag.NewFlagSet("export-fixtures", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	domainText := ""
	fs.StringVar(&domainText, "d", "", "authorized domain")
	fs.StringVar(&domainText, "domain", "", "authorized domain")
	databasePath := fs.String("db", DefaultDatabasePath, "SQLite database path")
	outputDir := fs.String("out", "", "fixture output directory")
	authorized := fs.Bool("authorized", false, "confirm ownership or explicit authorization")
	verbose := false
	fs.BoolVar(&verbose, "verbose", false, "enable structured diagnostic logging")
	fs.BoolVar(&verbose, "v", false, "enable structured diagnostic logging")
	if err := fs.Parse(args[1:]); err != nil {
		return ExportFixturesOptions{}, fmt.Errorf("export-fixtures usage: %w", err)
	}
	if fs.NArg() != 0 {
		return ExportFixturesOptions{}, fmt.Errorf("export-fixtures usage: unexpected argument %q", fs.Arg(0))
	}
	if !*authorized {
		return ExportFixturesOptions{}, errors.New("export-fixtures requires explicit authorization; use --authorized only for a domain you own or are authorized to test")
	}
	if strings.TrimSpace(*databasePath) == "" {
		return ExportFixturesOptions{}, errors.New("database path is required")
	}
	if strings.TrimSpace(*outputDir) == "" {
		return ExportFixturesOptions{}, errors.New("fixture output directory is required")
	}
	domain, err := enum.NormalizeDomain(domainText)
	if err != nil {
		return ExportFixturesOptions{}, err
	}
	return ExportFixturesOptions{Domain: domain, DatabasePath: *databasePath, OutputDir: *outputDir, Authorized: *authorized, Verbose: verbose}, nil
}

func runExportFixtures(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	options, err := parseExportFixturesOptions(args)
	if err != nil {
		return err
	}
	if stderr == nil {
		stderr = io.Discard
	}
	if err := os.MkdirAll(options.OutputDir, 0o750); err != nil {
		return fmt.Errorf("create fixture output directory: %w", err)
	}

	scanPath := filepath.Join(options.OutputDir, fixtureScanFileName)
	if err := writeFixture(scanPath, func(w io.Writer) error {
		return fixtureScanRunner(ctx, []string{"scan", "-d", options.Domain, "--authorized", "--json", "--db", options.DatabasePath}, w, stderr)
	}); err != nil {
		return fmt.Errorf("export scan fixture: %w", err)
	}

	historyPath := filepath.Join(options.OutputDir, fixtureHistoryFileName)
	if err := writeFixture(historyPath, func(w io.Writer) error {
		return fixtureHistoryRunner(ctx, []string{"history", "-d", options.Domain, "--authorized", "--json", "--db", options.DatabasePath}, w, stderr)
	}); err != nil {
		_ = os.Remove(historyPath)
		_, _ = fmt.Fprintf(stderr, "scan.json was written to %s; history.json was not written: %v\n", scanPath, err)
		return err
	}
	_, err = fmt.Fprintf(stdout, "wrote %s and %s\n", scanPath, historyPath)
	return err
}

func writeFixture(path string, render func(io.Writer) error) (err error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer func() {
		closeErr := file.Close()
		if err == nil && closeErr != nil {
			err = closeErr
		}
	}()
	return render(file)
}
