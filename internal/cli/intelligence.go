package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/Adam-Ghanem/Wraith/internal/intelligence"
	"github.com/Adam-Ghanem/Wraith/internal/storage"
)

type intelligenceOptions struct {
	ProjectID, DatabasePath string
	JSON                    bool
}

func parseIntelligenceOptions(args []string) (intelligenceOptions, error) {
	const usage = "usage: wraith intelligence --project PROJECT [--db PATH] [--json]"
	if len(args) == 0 || args[0] != "intelligence" {
		return intelligenceOptions{}, errors.New(usage)
	}
	fs := flag.NewFlagSet("intelligence", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	project := fs.String("project", "", "")
	db := fs.String("db", DefaultDatabasePath, "")
	jsonOutput := fs.Bool("json", false, "")
	if fs.Parse(args[1:]) != nil || fs.NArg() != 0 || strings.TrimSpace(*project) == "" || strings.TrimSpace(*db) == "" {
		return intelligenceOptions{}, errors.New(usage)
	}
	return intelligenceOptions{ProjectID: strings.TrimSpace(*project), DatabasePath: strings.TrimSpace(*db), JSON: *jsonOutput}, nil
}
func runIntelligence(ctx context.Context, args []string, stdout, _ io.Writer) error {
	options, err := parseIntelligenceOptions(args)
	if err != nil {
		return err
	}
	db, err := storage.Open(options.DatabasePath)
	if err != nil {
		return err
	}
	defer db.Close()
	if err = db.Migrate(ctx); err != nil {
		return err
	}
	assets, err := db.ListWebAssets(ctx, options.ProjectID)
	if err != nil {
		return err
	}
	endpoints, err := db.ListEndpoints(ctx, options.ProjectID)
	if err != nil {
		return err
	}
	graph, err := intelligence.BuildGraph(options.ProjectID, assets, endpoints, nil)
	if err != nil {
		return err
	}
	if options.JSON {
		return json.NewEncoder(stdout).Encode(graph)
	}
	_, err = fmt.Fprintf(stdout, "project=%s nodes=%d edges=%d\n", options.ProjectID, len(graph.Nodes), len(graph.Edges))
	return err
}
