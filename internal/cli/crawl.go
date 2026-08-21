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

	"github.com/Adam-Ghanem/Wraith/internal/crawler"
	"github.com/Adam-Ghanem/Wraith/internal/httpengine"
	"github.com/Adam-Ghanem/Wraith/internal/policy"
	"github.com/Adam-Ghanem/Wraith/internal/storage"
)

type crawlOptions struct {
	ProjectID, DatabasePath string
	Authorized, JSON        bool
	Rate                    int
	Config                  crawler.Config
}

func parseCrawlOptions(args []string) (crawlOptions, error) {
	if len(args) == 0 || args[0] != "crawl" {
		return crawlOptions{}, errors.New("usage: wraith crawl TARGET --project PROJECT --authorized [--depth N] [--max-pages N] [--concurrency N] [--rate N] [--json]")
	}
	fs := flag.NewFlagSet("crawl", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	project := fs.String("project", "", "R1 project identifier")
	database := fs.String("db", DefaultDatabasePath, "SQLite database path")
	authorized := fs.Bool("authorized", false, "confirm ownership or explicit authorization")
	jsonOutput := fs.Bool("json", false, "emit JSON output")
	depth := fs.Int("depth", 2, "maximum crawl depth")
	pages := fs.Int("max-pages", 100, "maximum fetched pages")
	concurrency := fs.Int("concurrency", 4, "maximum crawler workers")
	rate := fs.Int("rate", 20, "maximum R3 requests per second")
	timeout := fs.Duration("timeout", 10*time.Second, "per-request timeout")
	sameOrigin := fs.Bool("same-origin", true, "keep discovered URLs on the start origin")
	respectRobots := fs.Bool("respect-robots", true, "honor robots.txt crawler guidance")
	flagArgs := args[1:]
	if len(flagArgs) > 0 && !strings.HasPrefix(flagArgs[0], "-") {
		flagArgs = append(append([]string{}, flagArgs[1:]...), flagArgs[0])
	}
	if err := fs.Parse(flagArgs); err != nil {
		return crawlOptions{}, fmt.Errorf("crawl usage: %w", err)
	}
	if fs.NArg() != 1 || strings.TrimSpace(*project) == "" || strings.TrimSpace(*database) == "" || !*authorized {
		return crawlOptions{}, errors.New("usage: wraith crawl TARGET --project PROJECT --authorized [--depth N] [--max-pages N] [--concurrency N] [--rate N] [--json]")
	}
	config := crawler.DefaultConfig(strings.TrimSpace(*project), fs.Arg(0))
	config.MaxDepth = *depth
	config.MaxPages = *pages
	config.MaxConcurrency = *concurrency
	config.Timeout = *timeout
	config.SameOrigin = *sameOrigin
	config.RespectRobots = *respectRobots
	if *rate < 1 || *rate > 20 || config.MaxDepth < 0 || config.MaxDepth > 10 || config.MaxPages < 1 || config.MaxPages > 10000 || config.MaxConcurrency < 1 || config.MaxConcurrency > 50 || config.Timeout <= 0 || config.Timeout > 30*time.Second {
		return crawlOptions{}, errors.New("crawl options are outside safe bounds")
	}
	return crawlOptions{ProjectID: config.ProjectID, DatabasePath: *database, Authorized: *authorized, JSON: *jsonOutput, Rate: *rate, Config: config}, nil
}

func runCrawl(ctx context.Context, args []string, stdout, _ io.Writer) error {
	options, err := parseCrawlOptions(args)
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
	engine := httpengine.NewEngine(httpengine.Config{Gateway: policy.NewGateway(policy.NewEvaluator(database)), ObservationSink: sqliteObservationSink{repository: database}, RateLimiter: httpengine.NewRateLimiter(time.Second / time.Duration(options.Rate)), MaxConcurrentRequests: options.Config.MaxConcurrency, MaxResponseBytes: options.Config.MaxResponseBytes, MaxRedirects: options.Config.MaxRedirects, RequestTimeout: options.Config.Timeout, UserAgent: options.Config.UserAgent})
	defer func() { _ = engine.CloseIdleConnections() }()
	result, err := crawler.Crawler{Client: engine, Repository: database}.Crawl(ctx, options.Config)
	if err != nil {
		return err
	}
	if options.JSON {
		return json.NewEncoder(stdout).Encode(result)
	}
	_, err = fmt.Fprintf(stdout, "pages_discovered=%d pages_fetched=%d endpoints=%d parameters=%d forms=%d javascript_assets=%d api_references=%d redirects=%d errors=%d duration_ms=%d\n", result.PagesDiscovered, result.PagesFetched, result.Endpoints, result.Parameters, result.Forms, result.JavaScriptAssets, result.APIReferences, result.Redirects, len(result.Errors), result.Duration.Milliseconds())
	return err
}
