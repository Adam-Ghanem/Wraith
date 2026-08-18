package cli

import "testing"

func TestParseCrawlOptionsRequiresProjectAuthorizationAndBounds(t *testing.T) {
	options, err := parseCrawlOptions([]string{"crawl", "https://example.com", "--project", "project-a", "--authorized", "--depth", "3", "--max-pages", "25", "--concurrency", "4", "--rate", "5"})
	if err != nil {
		t.Fatalf("parse crawl: %v", err)
	}
	if options.ProjectID != "project-a" || options.Config.MaxDepth != 3 || options.Config.MaxPages != 25 || options.Config.MaxConcurrency != 4 || options.Rate != 5 {
		t.Fatalf("options=%+v", options)
	}
	if _, err := parseCrawlOptions([]string{"crawl", "https://example.com", "--authorized"}); err == nil {
		t.Fatal("expected project requirement")
	}
}
