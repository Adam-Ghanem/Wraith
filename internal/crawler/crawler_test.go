package crawler

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/httpengine"
)

func TestExtractDocumentCanonicalizesResourcesFormsAndParameters(t *testing.T) {
	document, err := ExtractDocument("https://example.com/root", []byte(`<!doctype html><base href="/base/"><a href="page#one">first</a><a href="page#two">second</a><script src="app.js"></script><form action="/search?q=secret" method="post"><input name="q"><textarea name="notes"></textarea><select name="kind"><option value="private">public</option></select></form><a href="/api/items?cursor=opaque">API</a>`))
	if err != nil {
		t.Fatalf("ExtractDocument: %v", err)
	}
	if len(document.URLs) != 3 || document.URLs[0] != "https://example.com/api/items?cursor=opaque" || document.URLs[1] != "https://example.com/app.js" || document.URLs[2] != "https://example.com/page" {
		t.Fatalf("URLs=%#v, want canonical deduplicated resources", document.URLs)
	}
	if len(document.Forms) != 1 || document.Forms[0].Method != "POST" || len(document.Forms[0].Parameters) != 3 {
		t.Fatalf("forms=%#v, want one POST form with parameter names only", document.Forms)
	}
	if len(document.APIReferences) != 1 || document.APIReferences[0] != "https://example.com/api/items?cursor=opaque" {
		t.Fatalf("APIReferences=%#v", document.APIReferences)
	}
}

func TestCrawlStaysSameOriginDeduplicatesFragmentsAndHonorsPageLimit(t *testing.T) {
	client := &fakeClient{responses: map[string]httpengine.Response{
		"https://example.com/":  {StatusCode: http.StatusOK, ContentType: "text/html", Body: []byte(`<a href="/a#first">a</a><a href="/a#second">dup</a><a href="https://other.example/">third party</a>`)},
		"https://example.com/a": {StatusCode: http.StatusOK, ContentType: "text/html", Body: []byte(`ok`)},
	}}
	config := DefaultConfig("project-a", "https://example.com/")
	config.RespectRobots, config.MaxPages = false, 2
	result, err := (Crawler{Client: client}).Crawl(context.Background(), config)
	if err != nil {
		t.Fatalf("Crawl: %v", err)
	}
	pageRequests := 0
	for _, request := range client.requests {
		if request.Source == "crawler" {
			pageRequests++
		}
	}
	if result.PagesFetched != 2 || pageRequests != 2 {
		t.Fatalf("fetched=%d pageRequests=%d all=%#v", result.PagesFetched, pageRequests, client.requests)
	}
	for _, request := range client.requests {
		if request.URL == "https://other.example/" {
			t.Fatal("third-party URL was fetched")
		}
	}
}

func TestCrawlPropagatesCancellationBeforeR3Request(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	client := &fakeClient{}
	config := DefaultConfig("project-a", "https://example.com/")
	config.RespectRobots = false
	_, err := (Crawler{Client: client}).Crawl(ctx, config)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error=%v", err)
	}
	if len(client.requests) != 0 {
		t.Fatalf("requests=%d, want none", len(client.requests))
	}
}

func TestCrawlBoundsQueryVariantsPerPath(t *testing.T) {
	client := &fakeClient{responses: map[string]httpengine.Response{
		"https://example.com/":             {StatusCode: http.StatusOK, ContentType: "text/html", Body: []byte(`<a href="/search?q=one">1</a><a href="/search?q=two">2</a><a href="/search?q=three">3</a>`)},
		"https://example.com/search?q=one": {StatusCode: http.StatusOK, ContentType: "text/html"},
	}}
	config := DefaultConfig("project-a", "https://example.com/")
	config.RespectRobots, config.MaxQueryVariants, config.MaxPages = false, 1, 10
	_, err := (Crawler{Client: client}).Crawl(context.Background(), config)
	if err != nil {
		t.Fatalf("Crawl: %v", err)
	}
	pageRequests := 0
	for _, request := range client.requests {
		if request.Source == "crawler" {
			pageRequests++
		}
	}
	if pageRequests != 2 {
		t.Fatalf("page requests=%d, want start plus one query variant", pageRequests)
	}
}

func TestCrawlRobotsAndSitemapCannotQueueThirdPartyURLs(t *testing.T) {
	client := &fakeClient{responses: map[string]httpengine.Response{
		"https://example.com/robots.txt": {StatusCode: http.StatusOK, Body: []byte("Sitemap: https://other.example/sitemap.xml\n")},
		"https://example.com/":           {StatusCode: http.StatusOK, ContentType: "text/html"},
	}}
	config := DefaultConfig("project-a", "https://example.com/")
	_, err := (Crawler{Client: client}).Crawl(context.Background(), config)
	if err != nil {
		t.Fatalf("Crawl: %v", err)
	}
	for _, request := range client.requests {
		if strings.Contains(request.URL, "other.example") {
			t.Fatalf("third-party robots/sitemap URL fetched: %s", request.URL)
		}
	}
}

type fakeClient struct {
	mu        sync.Mutex
	requests  []httpengine.Request
	responses map[string]httpengine.Response
}

func (client *fakeClient) Do(ctx context.Context, request httpengine.Request) (httpengine.Response, error) {
	if err := ctx.Err(); err != nil {
		return httpengine.Response{}, err
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	client.requests = append(client.requests, request)
	if response, ok := client.responses[request.URL]; ok {
		return response, nil
	}
	return httpengine.Response{StatusCode: http.StatusNotFound}, nil
}

var _ = time.Second
