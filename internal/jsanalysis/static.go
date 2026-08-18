// R6 static analysis is source-text and AST parsing only: no network, runtime, browser, or subprocess behavior.
package jsanalysis

import (
	"errors"
	"strings"
	"time"

	parse "github.com/tdewolff/parse/v2"
	js "github.com/tdewolff/parse/v2/js"
)

var (
	errStaticInput = errors.New("invalid static JavaScript input")
	errStaticLimit = errors.New("static JavaScript analysis limit exceeded")
)

// StaticLimits bound passive R6 parsing, traversal, and deterministic output volume.
type StaticLimits struct {
	MaxFileBytes     int
	MaxASTNodes      int
	MaxReferences    int
	MaxParseDuration time.Duration
}

func DefaultStaticLimits() StaticLimits {
	return StaticLimits{MaxFileBytes: 2 << 20, MaxASTNodes: 100000, MaxReferences: 10000, MaxParseDuration: 2 * time.Second}
}

func (limits StaticLimits) valid() bool {
	return limits.MaxFileBytes > 0 && limits.MaxFileBytes <= 8<<20 && limits.MaxASTNodes > 0 && limits.MaxASTNodes <= 500000 && limits.MaxReferences > 0 && limits.MaxReferences <= 50000 && limits.MaxParseDuration > 0 && limits.MaxParseDuration <= 10*time.Second
}

// StaticInput is already-local source text with stable asset or file provenance.
type StaticInput struct {
	SourceID string
	Body     []byte
}

type StaticReference struct {
	Kind       string `json:"kind"`
	Value      string `json:"value"`
	Confidence string `json:"confidence"`
	Evidence   string `json:"evidence"`
}

type StaticRequest struct {
	Client     string `json:"client"`
	Method     string `json:"method"`
	URL        string `json:"url"`
	Confidence string `json:"confidence"`
	Evidence   string `json:"evidence"`
}

type StaticParameter struct {
	Endpoint           string `json:"endpoint"`
	Location           string `json:"location"`
	Name               string `json:"name"`
	Confidence         string `json:"confidence"`
	SensitiveReference bool   `json:"sensitive_parameter_reference,omitempty"`
}

type GraphQLReference struct {
	Operation  string `json:"operation"`
	Confidence string `json:"confidence"`
}

type ClientFlow struct {
	Kind       string `json:"kind"`
	Type       string `json:"type"`
	Confidence string `json:"confidence"`
}

type TechnologySignal struct {
	Name       string `json:"name"`
	Confidence string `json:"confidence"`
	Evidence   string `json:"evidence"`
}

type StaticReport struct {
	SourceID     string             `json:"source_id"`
	Parsed       bool               `json:"parsed"`
	URLs         []StaticReference  `json:"urls"`
	Requests     []StaticRequest    `json:"requests"`
	Parameters   []StaticParameter  `json:"parameters"`
	WebSockets   []StaticReference  `json:"websockets"`
	GraphQL      []GraphQLReference `json:"graphql"`
	Routes       []StaticReference  `json:"routes"`
	SourceMaps   []StaticReference  `json:"source_maps"`
	Technologies []TechnologySignal `json:"technologies"`
	ClientFlows  []ClientFlow       `json:"client_flows"`
}

// StaticAnalyze validates a local JavaScript AST then delegates to static-only extractors.
func StaticAnalyze(input StaticInput, limits StaticLimits) (StaticReport, error) {
	if strings.TrimSpace(input.SourceID) == "" || !limits.valid() {
		return StaticReport{}, errStaticInput
	}
	if len(input.Body) > limits.MaxFileBytes {
		return StaticReport{}, errStaticLimit
	}
	report := StaticReport{SourceID: input.SourceID}
	started := time.Now()
	ast, err := js.Parse(parse.NewInputBytes(input.Body), js.Options{})
	if time.Since(started) > limits.MaxParseDuration {
		return StaticReport{}, errStaticLimit
	}
	if err != nil {
		return report, nil
	}
	counter := &staticNodeCounter{maximum: limits.MaxASTNodes}
	js.Walk(counter, ast)
	if counter.exceeded || time.Since(started) > limits.MaxParseDuration {
		return StaticReport{}, errStaticLimit
	}
	report.Parsed = true
	state := newStaticState(limits, &report)
	state.extractAll(string(input.Body))
	if state.limited {
		return StaticReport{}, errStaticLimit
	}
	state.sort()
	return report, nil
}

type staticNodeCounter struct {
	maximum  int
	count    int
	exceeded bool
}

func (counter *staticNodeCounter) Enter(js.INode) js.IVisitor {
	counter.count++
	if counter.count > counter.maximum {
		counter.exceeded = true
		return nil
	}
	return counter
}

func (*staticNodeCounter) Exit(js.INode) {}
