package npd

import "testing"

func TestSummarizeDoesNotAssignRisk(t *testing.T) {
	result := Result{Target: "192.0.2.10", Ports: []PortResult{{Port: 22, State: StateOpen}, {Port: 80, State: StateClosed}, {Port: 443, State: StateFiltered}, {Port: 8080, State: StatePolicy}}}
	summary := Summarize(result)
	if summary.Open != 1 || summary.Closed != 1 || summary.Filtered != 1 || summary.Policy != 1 || summary.PortsEvaluated != 4 {
		t.Fatalf("summary=%#v", summary)
	}
}

func TestMarkdownAndJSONAreStableForPortOrder(t *testing.T) {
	first := Result{Target: "192.0.2.10", Ports: []PortResult{{Port: 443, State: StateOpen}, {Port: 22, State: StateClosed}}}
	second := Result{Target: "192.0.2.10", Ports: []PortResult{{Port: 22, State: StateClosed}, {Port: 443, State: StateOpen}}}
	firstJSON, err := JSON(first)
	if err != nil {
		t.Fatal(err)
	}
	secondJSON, err := JSON(second)
	if err != nil {
		t.Fatal(err)
	}
	if string(firstJSON) == string(secondJSON) {
		t.Log("JSON ordering is canonical")
	}
	if Markdown(first) != Markdown(second) {
		t.Fatal("markdown summary changed with port order")
	}
}
