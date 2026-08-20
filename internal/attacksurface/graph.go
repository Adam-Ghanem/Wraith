// Package attacksurface builds a local, deterministic projection of evidence
// already collected by earlier Wraith phases. It performs no network or active
// security operation.
package attacksurface

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sort"
	"strings"
	"time"
)

type NodeType string

const (
	NodeProject     NodeType = "project"
	NodeAsset       NodeType = "asset"
	NodeEndpoint    NodeType = "endpoint"
	NodeParameter   NodeType = "parameter"
	NodeFinding     NodeType = "finding"
	NodeRisk        NodeType = "risk_assessment"
	NodeObservation NodeType = "observation"
	NodeAPI         NodeType = "api"
	NodeTechnology  NodeType = "technology"
	NodeAuthContext NodeType = "authentication_context"
)

type Relationship string

const (
	RelOwns         Relationship = "owns"
	RelExposes      Relationship = "exposes"
	RelAccepts      Relationship = "accepts"
	RelAffects      Relationship = "affects"
	RelBelongsTo    Relationship = "belongs_to"
	RelScores       Relationship = "scores"
	RelSupportedBy  Relationship = "supported_by"
	RelClassifies   Relationship = "classifies"
	RelRequiresAuth Relationship = "requires_authentication"
)

type Asset struct{ ID, ProjectID string }
type Endpoint struct {
	ID, ProjectID, AssetID string
	Classes                []string
	Authentication         string
}
type Parameter struct{ ID, ProjectID, EndpointID string }
type Finding struct {
	ID, ProjectID, EndpointID, ParameterID, AssetID string
	RiskScore                                       int
	Status                                          string
	EvidenceIDs                                     []string
}

type GraphInput struct {
	ProjectID  string
	Assets     []Asset
	Endpoints  []Endpoint
	Parameters []Parameter
	Findings   []Finding
}
type Node struct {
	ID, ProjectID string
	Type          NodeType
	Reference     string
}
type Edge struct {
	ID, ProjectID, Source, Destination string
	Relationship                       Relationship
}
type Graph struct {
	ProjectID   string
	Nodes       []Node
	Edges       []Edge
	Fingerprint string
}

func BuildGraph(input GraphInput) (Graph, error) {
	if strings.TrimSpace(input.ProjectID) == "" {
		return Graph{}, errors.New("invalid graph project")
	}
	nodes := map[string]Node{}
	edges := map[string]Edge{}
	addNode := func(node Node) error {
		if node.ProjectID != input.ProjectID || node.ID == "" || node.Reference == "" || !validNodeType(node.Type) {
			return errors.New("invalid or cross-project graph node")
		}
		if existing, ok := nodes[node.ID]; ok && existing != node {
			return errors.New("duplicate graph identity")
		}
		nodes[node.ID] = node
		return nil
	}
	addEdge := func(source string, relationship Relationship, destination string) error {
		if _, ok := nodes[source]; !ok {
			return errors.New("orphan graph source")
		}
		if _, ok := nodes[destination]; !ok {
			return errors.New("orphan graph destination")
		}
		if !validRelationship(relationship) {
			return errors.New("invalid graph relationship")
		}
		edge := Edge{ProjectID: input.ProjectID, Source: source, Relationship: relationship, Destination: destination}
		edge.ID = edgeID(edge)
		edges[edge.ID] = edge
		return nil
	}
	projectID := nodeID(NodeProject, input.ProjectID)
	if err := addNode(Node{ID: projectID, ProjectID: input.ProjectID, Type: NodeProject, Reference: input.ProjectID}); err != nil {
		return Graph{}, err
	}
	assetNodes := map[string]string{}
	for _, asset := range input.Assets {
		if asset.ProjectID != input.ProjectID || asset.ID == "" {
			return Graph{}, errors.New("invalid asset")
		}
		id := nodeID(NodeAsset, asset.ID)
		if err := addNode(Node{ID: id, ProjectID: input.ProjectID, Type: NodeAsset, Reference: asset.ID}); err != nil {
			return Graph{}, err
		}
		assetNodes[asset.ID] = id
		if err := addEdge(projectID, RelOwns, id); err != nil {
			return Graph{}, err
		}
	}
	endpointNodes := map[string]string{}
	for _, endpoint := range input.Endpoints {
		if endpoint.ProjectID != input.ProjectID || endpoint.ID == "" || endpoint.AssetID == "" {
			return Graph{}, errors.New("invalid endpoint")
		}
		assetNode, ok := assetNodes[endpoint.AssetID]
		if !ok {
			return Graph{}, errors.New("orphan endpoint asset")
		}
		id := nodeID(NodeEndpoint, endpoint.ID)
		if err := addNode(Node{ID: id, ProjectID: input.ProjectID, Type: NodeEndpoint, Reference: endpoint.ID}); err != nil {
			return Graph{}, err
		}
		endpointNodes[endpoint.ID] = id
		if err := addEdge(assetNode, RelExposes, id); err != nil {
			return Graph{}, err
		}
		for _, class := range unique(endpoint.Classes) {
			apiID := nodeID(NodeAPI, class)
			if err := addNode(Node{ID: apiID, ProjectID: input.ProjectID, Type: NodeAPI, Reference: class}); err != nil {
				return Graph{}, err
			}
			if err := addEdge(id, RelClassifies, apiID); err != nil {
				return Graph{}, err
			}
		}
		if endpoint.Authentication != "" && endpoint.Authentication != "unknown" {
			authID := nodeID(NodeAuthContext, endpoint.Authentication)
			if err := addNode(Node{ID: authID, ProjectID: input.ProjectID, Type: NodeAuthContext, Reference: endpoint.Authentication}); err != nil {
				return Graph{}, err
			}
			if err := addEdge(id, RelRequiresAuth, authID); err != nil {
				return Graph{}, err
			}
		}
	}
	parameterNodes := map[string]string{}
	for _, parameter := range input.Parameters {
		if parameter.ProjectID != input.ProjectID || parameter.ID == "" || parameter.EndpointID == "" {
			return Graph{}, errors.New("invalid parameter")
		}
		endpointNode, ok := endpointNodes[parameter.EndpointID]
		if !ok {
			return Graph{}, errors.New("orphan parameter endpoint")
		}
		id := nodeID(NodeParameter, parameter.ID)
		if err := addNode(Node{ID: id, ProjectID: input.ProjectID, Type: NodeParameter, Reference: parameter.ID}); err != nil {
			return Graph{}, err
		}
		parameterNodes[parameter.ID] = id
		if err := addEdge(endpointNode, RelAccepts, id); err != nil {
			return Graph{}, err
		}
	}
	for _, finding := range input.Findings {
		if finding.ProjectID != input.ProjectID || finding.ID == "" || finding.EndpointID == "" || finding.AssetID == "" || finding.RiskScore < 0 || finding.RiskScore > 100 {
			return Graph{}, errors.New("invalid finding")
		}
		endpointNode, endpointOK := endpointNodes[finding.EndpointID]
		assetNode, assetOK := assetNodes[finding.AssetID]
		if !endpointOK || !assetOK {
			return Graph{}, errors.New("orphan finding relationship")
		}
		findingNode := nodeID(NodeFinding, finding.ID)
		if err := addNode(Node{ID: findingNode, ProjectID: input.ProjectID, Type: NodeFinding, Reference: finding.ID}); err != nil {
			return Graph{}, err
		}
		if err := addEdge(findingNode, RelAffects, endpointNode); err != nil {
			return Graph{}, err
		}
		if err := addEdge(findingNode, RelBelongsTo, assetNode); err != nil {
			return Graph{}, err
		}
		if finding.ParameterID != "" {
			parameterNode, ok := parameterNodes[finding.ParameterID]
			if !ok {
				return Graph{}, errors.New("orphan finding parameter")
			}
			if err := addEdge(findingNode, RelAffects, parameterNode); err != nil {
				return Graph{}, err
			}
		}
		riskRef := finding.ID + ":" + stringScore(finding.RiskScore)
		riskNode := nodeID(NodeRisk, riskRef)
		if err := addNode(Node{ID: riskNode, ProjectID: input.ProjectID, Type: NodeRisk, Reference: riskRef}); err != nil {
			return Graph{}, err
		}
		if err := addEdge(riskNode, RelScores, findingNode); err != nil {
			return Graph{}, err
		}
		for _, observation := range unique(finding.EvidenceIDs) {
			observationNode := nodeID(NodeObservation, observation)
			if err := addNode(Node{ID: observationNode, ProjectID: input.ProjectID, Type: NodeObservation, Reference: observation}); err != nil {
				return Graph{}, err
			}
			if err := addEdge(findingNode, RelSupportedBy, observationNode); err != nil {
				return Graph{}, err
			}
		}
	}
	graph := Graph{ProjectID: input.ProjectID, Nodes: sortedNodes(nodes), Edges: sortedEdges(edges)}
	graph.Fingerprint = graphFingerprint(graph)
	return graph, nil
}

type Snapshot struct {
	ID, ProjectID, GraphFingerprint, SourceVersion string
	CreatedAt                                      time.Time
	NodeCount, EdgeCount                           int
}

func NewSnapshot(graph Graph, sourceVersion string, createdAt time.Time) Snapshot {
	return Snapshot{ID: snapshotID(graph.ProjectID, graph.Fingerprint, sourceVersion), ProjectID: graph.ProjectID, GraphFingerprint: graph.Fingerprint, SourceVersion: sourceVersion, CreatedAt: createdAt.UTC(), NodeCount: len(graph.Nodes), EdgeCount: len(graph.Edges)}
}

type GraphDiff struct{ Added, Removed, Changed []string }

func DiffSnapshots(previous, current Snapshot) (GraphDiff, error) {
	if previous.ProjectID == "" || current.ProjectID == "" || previous.ProjectID != current.ProjectID {
		return GraphDiff{}, errors.New("cross-project snapshot diff")
	}
	if previous.GraphFingerprint == current.GraphFingerprint {
		return GraphDiff{}, nil
	}
	changed := []string{"graph_fingerprint"}
	if previous.NodeCount != current.NodeCount {
		changed = append(changed, "node_count")
	}
	if previous.EdgeCount != current.EdgeCount {
		changed = append(changed, "edge_count")
	}
	return GraphDiff{Added: changed, Changed: changed}, nil
}

type Coverage struct{ AssetDiscovery, EndpointDiscovery, ParameterDiscovery, AuthenticationCoverage, ValidationCoverage, FindingCoverage int }

func CalculateCoverage(graph Graph) Coverage {
	count := func(kind NodeType) int {
		total := 0
		for _, node := range graph.Nodes {
			if node.Type == kind {
				total++
			}
		}
		return total
	}
	assets, endpoints, parameters, findings := count(NodeAsset), count(NodeEndpoint), count(NodeParameter), count(NodeFinding)
	percent := func(n, d int) int {
		if d == 0 {
			return 0
		}
		return n * 100 / d
	}
	return Coverage{AssetDiscovery: percent(assets, assets), EndpointDiscovery: percent(endpoints, assets), ParameterDiscovery: percent(parameters, endpoints), FindingCoverage: percent(findings, endpoints)}
}

type VisibilityGap struct{ Kind, NodeID, Reason string }

func VisibilityGaps(graph Graph) []VisibilityGap {
	outgoing := map[string]map[Relationship]bool{}
	for _, edge := range graph.Edges {
		if outgoing[edge.Source] == nil {
			outgoing[edge.Source] = map[Relationship]bool{}
		}
		outgoing[edge.Source][edge.Relationship] = true
	}
	gaps := make([]VisibilityGap, 0)
	for _, node := range graph.Nodes {
		switch node.Type {
		case NodeAsset:
			if !outgoing[node.ID][RelExposes] {
				gaps = append(gaps, VisibilityGap{Kind: "asset_without_endpoint", NodeID: node.ID, Reason: "Known asset has no currently recorded endpoint."})
			}
		case NodeEndpoint:
			if !outgoing[node.ID][RelAccepts] {
				gaps = append(gaps, VisibilityGap{Kind: "endpoint_without_parameter", NodeID: node.ID, Reason: "Known endpoint has no currently recorded parameter."})
			}
		}
	}
	sort.Slice(gaps, func(i, j int) bool { return gaps[i].Kind+gaps[i].NodeID < gaps[j].Kind+gaps[j].NodeID })
	return gaps
}
func nodeID(kind NodeType, reference string) string { return string(kind) + ":" + reference }
func edgeID(edge Edge) string {
	sum := sha256.Sum256([]byte(edge.ProjectID + "\x00" + edge.Source + "\x00" + string(edge.Relationship) + "\x00" + edge.Destination))
	return hex.EncodeToString(sum[:])
}
func snapshotID(project, fingerprint, version string) string {
	sum := sha256.Sum256([]byte(project + "\x00" + fingerprint + "\x00" + version))
	return hex.EncodeToString(sum[:])
}
func graphFingerprint(graph Graph) string {
	values := make([]string, 0, len(graph.Nodes)+len(graph.Edges))
	for _, node := range graph.Nodes {
		values = append(values, "n\x00"+node.ID+"\x00"+string(node.Type)+"\x00"+node.Reference)
	}
	for _, edge := range graph.Edges {
		values = append(values, "e\x00"+edge.Source+"\x00"+string(edge.Relationship)+"\x00"+edge.Destination)
	}
	sum := sha256.Sum256([]byte(graph.ProjectID + "\x00" + strings.Join(values, "\n")))
	return hex.EncodeToString(sum[:])
}
func sortedNodes(values map[string]Node) []Node {
	out := make([]Node, 0, len(values))
	for _, v := range values {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
func sortedEdges(values map[string]Edge) []Edge {
	out := make([]Edge, 0, len(values))
	for _, v := range values {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Source+string(out[i].Relationship)+out[i].Destination < out[j].Source+string(out[j].Relationship)+out[j].Destination
	})
	return out
}
func unique(values []string) []string {
	set := map[string]bool{}
	for _, v := range values {
		if v = strings.TrimSpace(v); v != "" {
			set[v] = true
		}
	}
	out := make([]string, 0, len(set))
	for v := range set {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}
func stringScore(value int) string {
	if value == 0 {
		return "0"
	}
	out := ""
	for value > 0 {
		out = string(rune('0'+value%10)) + out
		value /= 10
	}
	return out
}
func validNodeType(value NodeType) bool {
	switch value {
	case NodeProject, NodeAsset, NodeEndpoint, NodeParameter, NodeFinding, NodeRisk, NodeObservation, NodeAPI, NodeTechnology, NodeAuthContext:
		return true
	}
	return false
}
func validRelationship(value Relationship) bool {
	switch value {
	case RelOwns, RelExposes, RelAccepts, RelAffects, RelBelongsTo, RelScores, RelSupportedBy, RelClassifies, RelRequiresAuth:
		return true
	}
	return false
}
