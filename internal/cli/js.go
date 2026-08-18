package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/evidence"
	"github.com/Adam-Ghanem/Wraith/internal/jsanalysis"
	"github.com/Adam-Ghanem/Wraith/internal/storage"
)

type jsOptions struct {
	ProjectID, DatabasePath, FilePath, AssetID, SourceMapPath string
	Authorized, JSON                                          bool
	MaxFiles, MaxSize                                         int
}

func parseJSOptions(args []string) (jsOptions, error) {
	const usage = "usage: wraith js --project PROJECT --authorized --file FILE [--asset ID] [--sourcemap FILE] [--db PATH] [--max-files N] [--max-size BYTES] [--json]"
	if len(args) == 0 || args[0] != "js" {
		return jsOptions{}, errors.New(usage)
	}
	fs := flag.NewFlagSet("js", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	project := fs.String("project", "", "R1 project identifier")
	database := fs.String("db", DefaultDatabasePath, "SQLite database path")
	authorized := fs.Bool("authorized", false, "confirm ownership or explicit authorization")
	file := fs.String("file", "", "explicit local JavaScript file")
	asset := fs.String("asset", "", "project-local JavaScript asset identity")
	sourceMap := fs.String("sourcemap", "", "explicit local source-map file")
	maxFiles := fs.Int("max-files", 1, "maximum local files in this invocation")
	maxSize := fs.Int("max-size", jsanalysis.DefaultStaticLimits().MaxFileBytes, "maximum bytes per local JavaScript file")
	jsonOutput := fs.Bool("json", false, "emit JSON output")
	if err := fs.Parse(args[1:]); err != nil {
		return jsOptions{}, fmt.Errorf("js usage: %w", err)
	}
	if fs.NArg() != 0 || strings.TrimSpace(*project) == "" || strings.TrimSpace(*database) == "" || strings.TrimSpace(*file) == "" || !*authorized || *maxFiles < 1 || *maxFiles > 1000 || *maxSize < 1 || *maxSize > 8<<20 {
		return jsOptions{}, errors.New(usage)
	}
	return jsOptions{ProjectID: strings.TrimSpace(*project), DatabasePath: strings.TrimSpace(*database), FilePath: strings.TrimSpace(*file), AssetID: strings.TrimSpace(*asset), SourceMapPath: strings.TrimSpace(*sourceMap), Authorized: *authorized, JSON: *jsonOutput, MaxFiles: *maxFiles, MaxSize: *maxSize}, nil
}

func runJS(ctx context.Context, args []string, stdout, _ io.Writer) error {
	options, err := parseJSOptions(args)
	if err != nil {
		return err
	}
	data, err := readBoundedFile(options.FilePath, int64(options.MaxSize))
	if err != nil {
		return errors.New("invalid local JavaScript file")
	}
	limits := jsanalysis.DefaultStaticLimits()
	limits.MaxFileBytes = options.MaxSize
	database, err := storage.Open(options.DatabasePath)
	if err != nil {
		return err
	}
	defer database.Close()
	if err := database.Migrate(ctx); err != nil {
		return err
	}
	var asset evidence.WebAsset
	sourceID := "local:" + options.FilePath
	if options.AssetID != "" {
		assets, err := database.ListWebAssets(ctx, options.ProjectID)
		if err != nil {
			return err
		}
		for _, candidate := range assets {
			if candidate.Identity == options.AssetID && candidate.Kind == evidence.AssetKindJavaScript {
				asset = candidate
				break
			}
		}
		if asset.Identity == "" {
			return errors.New("JavaScript asset is not available in this project")
		}
		sourceID = asset.Identity
	}
	report, err := jsanalysis.StaticAnalyze(jsanalysis.StaticInput{SourceID: sourceID, Body: data}, limits)
	if err != nil {
		return err
	}
	output := struct {
		jsanalysis.StaticReport
		LocalSourceMap *jsanalysis.SourceMapSummary `json:"local_source_map,omitempty"`
	}{StaticReport: report}
	if options.SourceMapPath != "" {
		mapData, err := readBoundedFile(options.SourceMapPath, int64(jsanalysis.DefaultSourceMapLimits().MaxBytes))
		if err != nil {
			return errors.New("invalid local source map")
		}
		summary, err := jsanalysis.ParseLocalSourceMap(mapData, jsanalysis.DefaultSourceMapLimits())
		if err != nil {
			return err
		}
		output.LocalSourceMap = &summary
	}
	if asset.Identity != "" && report.Parsed {
		if err := jsanalysis.PersistStaticEvidence(ctx, database, options.ProjectID, asset, report, time.Now().UTC()); err != nil {
			return err
		}
		if output.LocalSourceMap != nil {
			if err := jsanalysis.PersistLocalSourceMapEvidence(ctx, database, options.ProjectID, asset, *output.LocalSourceMap, time.Now().UTC()); err != nil {
				return err
			}
		}
	}
	if options.JSON {
		return json.NewEncoder(stdout).Encode(output)
	}
	_, err = fmt.Fprintf(stdout, "project=%s parsed=%t urls=%d requests=%d parameters=%d websockets=%d graphql=%d routes=%d source_maps=%d technologies=%d client_flows=%d persisted=%t\n", options.ProjectID, report.Parsed, len(report.URLs), len(report.Requests), len(report.Parameters), len(report.WebSockets), len(report.GraphQL), len(report.Routes), len(report.SourceMaps), len(report.Technologies), len(report.ClientFlows), asset.Identity != "")
	return err
}
