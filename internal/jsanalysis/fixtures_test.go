package jsanalysis

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStaticAnalyzeLocalFixtures(t *testing.T) {
	cases := []struct {
		name             string
		parsed           bool
		requests, params int
		websockets, gql  int
		routes, flows    int
	}{
		{name: "fetch_xhr_axios.js", parsed: true, requests: 3, params: 2},
		{name: "dynamic_templates.js", parsed: true, requests: 1},
		{name: "parameters.js", parsed: true, requests: 1, params: 3, flows: 1},
		{name: "websocket_graphql.js", parsed: true, websockets: 1, gql: 1},
		{name: "routes.js", parsed: true, routes: 1},
		{name: "minified.js", parsed: true, requests: 1, websockets: 1},
		{name: "malformed.js", parsed: false},
		{name: "sources_sinks.js", parsed: true, flows: 2},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			body, err := os.ReadFile(filepath.Join("testdata", test.name))
			if err != nil {
				t.Fatal(err)
			}
			report, err := StaticAnalyze(StaticInput{SourceID: "fixture:" + test.name, Body: body}, DefaultStaticLimits())
			if err != nil || report.Parsed != test.parsed || len(report.Requests) != test.requests || len(report.Parameters) != test.params || len(report.WebSockets) != test.websockets || len(report.GraphQL) != test.gql || len(report.Routes) != test.routes || len(report.ClientFlows) != test.flows {
				t.Fatalf("report=%#v err=%v", report, err)
			}
		})
	}
}

func TestParseLocalSourceMapFixture(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "app.js.map"))
	if err != nil {
		t.Fatal(err)
	}
	summary, err := ParseLocalSourceMap(data, DefaultSourceMapLimits())
	if err != nil || summary.Version != 3 || len(summary.Sources) != 2 {
		t.Fatalf("summary=%#v err=%v", summary, err)
	}
}
