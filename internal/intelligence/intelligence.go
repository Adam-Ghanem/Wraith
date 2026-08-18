package intelligence

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/evidence"
)

type NodeKind string

const (
	NodeAsset    NodeKind = "asset"
	NodeEndpoint NodeKind = "endpoint"
)

type EdgeKind string

const EdgeAssetContainsEndpoint EdgeKind = "asset_contains_endpoint"

type Node struct {
	ID, ProjectID string
	Kind          NodeKind
}
type Edge struct {
	From, To string
	Kind     EdgeKind
}
type Graph struct {
	ProjectID string
	Nodes     []Node
	Edges     []Edge
}

type Lifecycle string

const (
	LifecycleObserved   Lifecycle = "observed"
	LifecycleCorrelated Lifecycle = "correlated"
	LifecycleResolved   Lifecycle = "resolved"
	LifecycleStale      Lifecycle = "stale"
)

type Candidate struct {
	ProjectID, RuleID, SubjectIdentity string
	EvidenceIDs                        []string
	ObservedAt                         time.Time
}
type Confidence struct {
	Score   int
	Reasons []string
}
type Correlation struct {
	ID, ProjectID, RuleID, SubjectIdentity string
	EvidenceIDs                            []string
	Lifecycle                              Lifecycle
	Confidence                             Confidence
	ClaimsExploitability                   bool
}

type ChangeState string

const (
	ChangeNew       ChangeState = "new"
	ChangeChanged   ChangeState = "changed"
	ChangeUnchanged ChangeState = "unchanged"
	ChangeRemoved   ChangeState = "removed"
)

type Change struct {
	State             ChangeState
	Previous, Current *Correlation
}

func DetectChanges(projectID string, previous, current []Correlation) ([]Change, error) {
	if strings.TrimSpace(projectID) == "" {
		return nil, errors.New("invalid project")
	}
	key := func(c Correlation) string { return c.RuleID + "\x00" + c.SubjectIdentity }
	old, now := map[string]Correlation{}, map[string]Correlation{}
	for _, c := range previous {
		if c.ProjectID != projectID || strings.TrimSpace(c.RuleID) == "" || strings.TrimSpace(c.SubjectIdentity) == "" {
			return nil, errors.New("invalid previous correlation")
		}
		old[key(c)] = c
	}
	for _, c := range current {
		if c.ProjectID != projectID || strings.TrimSpace(c.RuleID) == "" || strings.TrimSpace(c.SubjectIdentity) == "" {
			return nil, errors.New("invalid current correlation")
		}
		now[key(c)] = c
	}
	keys := map[string]bool{}
	for k := range old {
		keys[k] = true
	}
	for k := range now {
		keys[k] = true
	}
	ordered := make([]string, 0, len(keys))
	for k := range keys {
		ordered = append(ordered, k)
	}
	sort.Strings(ordered)
	changes := make([]Change, 0, len(ordered))
	for _, k := range ordered {
		previousValue, hadPrevious := old[k]
		currentValue, hadCurrent := now[k]
		switch {
		case hadPrevious && hadCurrent:
			if strings.Join(previousValue.EvidenceIDs, "\x00") == strings.Join(currentValue.EvidenceIDs, "\x00") {
				changes = append(changes, Change{State: ChangeUnchanged, Previous: &previousValue, Current: &currentValue})
			} else {
				changes = append(changes, Change{State: ChangeChanged, Previous: &previousValue, Current: &currentValue})
			}
		case hadCurrent:
			changes = append(changes, Change{State: ChangeNew, Current: &currentValue})
		default:
			changes = append(changes, Change{State: ChangeRemoved, Previous: &previousValue})
		}
	}
	return changes, nil
}

func BuildGraph(projectID string, assets []evidence.WebAsset, endpoints []evidence.Endpoint, _ []evidence.Observation) (Graph, error) {
	if strings.TrimSpace(projectID) == "" {
		return Graph{}, errors.New("invalid project")
	}
	graph := Graph{ProjectID: projectID}
	nodes := map[string]Node{}
	hosts := map[string]string{}
	for _, asset := range assets {
		if asset.ProjectID != projectID || asset.Identity == "" {
			return Graph{}, errors.New("cross-project or invalid asset")
		}
		nodes[asset.Identity] = Node{ID: asset.Identity, ProjectID: projectID, Kind: NodeAsset}
		parsed, err := url.Parse(asset.CanonicalURL)
		if err != nil {
			return Graph{}, err
		}
		hosts[parsed.Scheme+"://"+parsed.Host] = asset.Identity
	}
	edges := map[string]Edge{}
	for _, endpoint := range endpoints {
		if endpoint.ProjectID != projectID || endpoint.Identity == "" {
			return Graph{}, errors.New("cross-project or invalid endpoint")
		}
		nodes[endpoint.Identity] = Node{ID: endpoint.Identity, ProjectID: projectID, Kind: NodeEndpoint}
		parsed, err := url.Parse(endpoint.URL)
		if err != nil {
			return Graph{}, err
		}
		if assetID, ok := hosts[parsed.Scheme+"://"+parsed.Host]; ok {
			edge := Edge{From: assetID, To: endpoint.Identity, Kind: EdgeAssetContainsEndpoint}
			edges[edge.From+"\x00"+string(edge.Kind)+"\x00"+edge.To] = edge
		}
	}
	for _, node := range nodes {
		graph.Nodes = append(graph.Nodes, node)
	}
	for _, edge := range edges {
		graph.Edges = append(graph.Edges, edge)
	}
	sort.Slice(graph.Nodes, func(i, j int) bool { return graph.Nodes[i].ID < graph.Nodes[j].ID })
	sort.Slice(graph.Edges, func(i, j int) bool {
		return graph.Edges[i].From+string(graph.Edges[i].Kind)+graph.Edges[i].To < graph.Edges[j].From+string(graph.Edges[j].Kind)+graph.Edges[j].To
	})
	return graph, nil
}

func Correlate(projectID string, candidates []Candidate) ([]Correlation, error) {
	if strings.TrimSpace(projectID) == "" {
		return nil, errors.New("invalid project")
	}
	groups := map[string][]Candidate{}
	for _, candidate := range candidates {
		if candidate.ProjectID != projectID || strings.TrimSpace(candidate.RuleID) == "" || strings.TrimSpace(candidate.SubjectIdentity) == "" || candidate.ObservedAt.IsZero() {
			return nil, errors.New("invalid candidate")
		}
		key := candidate.RuleID + "\x00" + candidate.SubjectIdentity
		groups[key] = append(groups[key], candidate)
	}
	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]Correlation, 0, len(keys))
	for _, key := range keys {
		group := groups[key]
		ids := map[string]bool{}
		for _, candidate := range group {
			for _, id := range candidate.EvidenceIDs {
				if strings.TrimSpace(id) != "" {
					ids[id] = true
				}
			}
		}
		evidenceIDs := make([]string, 0, len(ids))
		for id := range ids {
			evidenceIDs = append(evidenceIDs, id)
		}
		sort.Strings(evidenceIDs)
		score := len(evidenceIDs)*25 + len(group)*10
		if score > 100 {
			score = 100
		}
		sum := sha256.Sum256([]byte(projectID + "\x00" + key + "\x00" + strings.Join(evidenceIDs, "\x00")))
		parts := strings.Split(key, "\x00")
		out = append(out, Correlation{ID: hex.EncodeToString(sum[:]), ProjectID: projectID, RuleID: parts[0], SubjectIdentity: parts[1], EvidenceIDs: evidenceIDs, Lifecycle: LifecycleCorrelated, Confidence: Confidence{Score: score, Reasons: []string{"multiple recorded evidence references", "repeated matching rule and subject"}}})
	}
	return out, nil
}
