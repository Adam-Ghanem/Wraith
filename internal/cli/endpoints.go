package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Adam-Ghanem/Wraith/internal/endpointintelligence"
	"github.com/Adam-Ghanem/Wraith/internal/storage"
)

type endpointsOptions struct {
	ProjectID, DatabasePath, OpenAPIPath string
	Authorized, JSON                     bool
}

func parseEndpointsOptions(args []string) (endpointsOptions, error) {
	if len(args) == 0 || args[0] != "endpoints" {
		return endpointsOptions{}, errors.New("usage: wraith endpoints --project PROJECT --authorized [--db PATH] [--json] [--openapi FILE]")
	}
	fs := flag.NewFlagSet("endpoints", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	project := fs.String("project", "", "R1 project identifier")
	database := fs.String("db", DefaultDatabasePath, "SQLite database path")
	authorized := fs.Bool("authorized", false, "confirm ownership or explicit authorization")
	jsonOutput := fs.Bool("json", false, "emit JSON output")
	openAPI := fs.String("openapi", "", "local JSON OpenAPI or Swagger document")
	if err := fs.Parse(args[1:]); err != nil {
		return endpointsOptions{}, fmt.Errorf("endpoints usage: %w", err)
	}
	if fs.NArg() != 0 || strings.TrimSpace(*project) == "" || strings.TrimSpace(*database) == "" || !*authorized {
		return endpointsOptions{}, errors.New("usage: wraith endpoints --project PROJECT --authorized [--db PATH] [--json] [--openapi FILE]")
	}
	return endpointsOptions{ProjectID: strings.TrimSpace(*project), DatabasePath: *database, OpenAPIPath: strings.TrimSpace(*openAPI), Authorized: *authorized, JSON: *jsonOutput}, nil
}

func runEndpoints(ctx context.Context, args []string, stdout, _ io.Writer) error {
	options, err := parseEndpointsOptions(args)
	if err != nil {
		return err
	}
	database, err := storage.Open(options.DatabasePath)
	if err != nil {
		return err
	}
	defer database.Close()
	if err := database.Migrate(ctx); err != nil {
		return err
	}
	inventory, err := endpointintelligence.Build(ctx, database, options.ProjectID, endpointintelligence.DefaultLimits())
	if err != nil {
		return err
	}
	output := struct {
		endpointintelligence.Inventory
		LocalOpenAPI []endpointintelligence.Endpoint `json:"local_openapi,omitempty"`
	}{Inventory: inventory}
	if options.OpenAPIPath != "" {
		data, err := readBoundedFile(options.OpenAPIPath, 1<<20)
		if err != nil {
			return errors.New("invalid local openapi file")
		}
		parsed, err := endpointintelligence.ParseOpenAPI(options.ProjectID, data, endpointintelligence.DefaultOpenAPILimits())
		if err != nil {
			return err
		}
		output.LocalOpenAPI = parsed
	}
	if options.JSON {
		return json.NewEncoder(stdout).Encode(output)
	}
	_, err = fmt.Fprintf(stdout, "project=%s endpoints=%d parameters=%d assets=%d local_openapi_operations=%d\n", inventory.ProjectID, inventory.EndpointCount, inventory.ParameterCount, len(inventory.Assets), len(output.LocalOpenAPI))
	return err
}
func readBoundedFile(path string, max int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, max+1))
	if err != nil || int64(len(data)) > max {
		return nil, errors.New("file exceeds limit")
	}
	return data, nil
}
