package jsanalysis

import "testing"

func TestStaticAnalyzeExtractsDeterministicClientSideEvidence(t *testing.T) {
	source := []byte(`
const base = "/api";
fetch("/api/users?id=1", { method: "POST", body: JSON.stringify({ email: value, token: secret }) });
axios.get("/api/me");
const socket = new WebSocket("wss://example.test/socket");
const operation = "query GetUser($id: ID!) { user(id: $id) { id } }";
const routes = [{ path: "/settings" }];
//# sourceMappingURL=app.js.map
const input = location.search;
element.innerHTML = input;
`)
	report, err := StaticAnalyze(StaticInput{SourceID: "javascript:https://example.test/app.js", Body: source}, DefaultStaticLimits())
	if err != nil {
		t.Fatal(err)
	}
	if !report.Parsed || len(report.URLs) != 2 || len(report.Requests) != 2 || len(report.Parameters) != 3 {
		t.Fatalf("unexpected static report: %#v", report)
	}
	if report.Requests[0].Method != "GET" || report.Requests[1].Method != "POST" || report.WebSockets[0].Value != "wss://example.test/socket" {
		t.Fatalf("request or websocket extraction mismatch: %#v", report)
	}
	if report.GraphQL[0].Operation != "GetUser" || report.Routes[0].Value != "/settings" || report.SourceMaps[0].Value != "app.js.map" {
		t.Fatalf("GraphQL, route, or source-map extraction mismatch: %#v", report)
	}
	if report.ClientFlows[0].Kind != "client_side_sink" || report.ClientFlows[1].Kind != "client_side_source" {
		t.Fatalf("client source/sink extraction mismatch: %#v", report.ClientFlows)
	}
	if !report.Parameters[2].SensitiveReference || report.Parameters[2].Name != "token" {
		t.Fatalf("sensitive parameter should retain only name metadata: %#v", report.Parameters)
	}
}

func TestStaticAnalyzeFailsClosedForInvalidAndOversizedInput(t *testing.T) {
	limits := DefaultStaticLimits()
	limits.MaxFileBytes = 8
	if _, err := StaticAnalyze(StaticInput{SourceID: "local:oversized.js", Body: []byte("const x = 1")}, limits); err == nil {
		t.Fatal("expected oversized input rejection")
	}
	limits = DefaultStaticLimits()
	report, err := StaticAnalyze(StaticInput{SourceID: "local:broken.js", Body: []byte("const =")}, limits)
	if err != nil || report.Parsed || len(report.URLs) != 0 {
		t.Fatalf("malformed source should produce bounded non-panicking report: %#v err=%v", report, err)
	}
}
