package attacksurface

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sort"
	"strings"
	"time"
)

type CampaignStatus string

const (
	CampaignPlanned   CampaignStatus = "planned"
	CampaignActive    CampaignStatus = "active"
	CampaignPaused    CampaignStatus = "paused"
	CampaignCompleted CampaignStatus = "completed"
	CampaignCancelled CampaignStatus = "cancelled"
)

type CampaignTaskType string

const (
	TaskReviewAsset          CampaignTaskType = "review_asset"
	TaskReviewEndpoint       CampaignTaskType = "review_endpoint"
	TaskValidateFinding      CampaignTaskType = "validate_finding"
	TaskInvestigateGap       CampaignTaskType = "investigate_visibility_gap"
	TaskReviewAuthentication CampaignTaskType = "review_authentication"
	TaskReviewAPISurface     CampaignTaskType = "review_api_surface"
)

type CampaignBudget struct {
	MaxTasks, MaxValidationRequests, MaxConcurrency int
	MaxDuration                                     time.Duration
}
type CampaignTask struct {
	TaskID, ProjectID   string
	Type                CampaignTaskType
	ReferenceID, Reason string
	Priority            int
	ValidationRequests  int
}
type CampaignPlan struct {
	CampaignID, ProjectID, Name, Description, ScopeVersion, GraphSnapshot, RiskModelVersion string
	CreatedAt                                                                               time.Time
	Status                                                                                  CampaignStatus
	Budget                                                                                  CampaignBudget
	Tasks                                                                                   []CampaignTask
	Limitations                                                                             string
}
type CampaignInput struct {
	ProjectID, Name, Description string
	Graph                        Graph
	Snapshot                     Snapshot
	Budget                       CampaignBudget
	CreatedAt                    time.Time
}

func BuildCampaignPlan(input CampaignInput) (CampaignPlan, error) {
	if strings.TrimSpace(input.ProjectID) == "" || strings.TrimSpace(input.Name) == "" || input.Graph.ProjectID != input.ProjectID || input.Snapshot.ProjectID != input.ProjectID || input.Snapshot.GraphFingerprint != input.Graph.Fingerprint || !validBudget(input.Budget) {
		return CampaignPlan{}, errors.New("invalid campaign input")
	}
	created := input.CreatedAt
	if created.IsZero() {
		created = time.Unix(0, 0)
	}
	plan := CampaignPlan{ProjectID: input.ProjectID, Name: strings.TrimSpace(input.Name), Description: strings.TrimSpace(input.Description), ScopeVersion: "r11.6-v1", GraphSnapshot: input.Snapshot.ID, RiskModelVersion: input.Snapshot.SourceVersion, CreatedAt: created.UTC(), Status: CampaignPlanned, Budget: input.Budget, Limitations: "Planning only. Tasks do not execute network activity; R10.5, R1, and R3 remain execution authorities."}
	plan.CampaignID = campaignID(plan)
	candidates := make([]CampaignTask, 0)
	riskByFinding := map[string]int{}
	for _, edge := range input.Graph.Edges {
		if edge.Relationship == RelScores {
			riskRef := nodeReference(input.Graph, edge.Source)
			findingRef := nodeReference(input.Graph, edge.Destination)
			riskByFinding[findingRef] = parseRiskReference(riskRef)
		}
	}
	for _, node := range input.Graph.Nodes {
		if node.Type == NodeFinding {
			priority := riskByFinding[node.Reference]
			candidates = append(candidates, CampaignTask{ProjectID: input.ProjectID, Type: TaskValidateFinding, ReferenceID: node.Reference, Reason: "Existing validated finding requires prioritized analyst review.", Priority: priority, ValidationRequests: 1})
		}
	}
	for _, gap := range VisibilityGaps(input.Graph) {
		candidates = append(candidates, CampaignTask{ProjectID: input.ProjectID, Type: TaskInvestigateGap, ReferenceID: gap.NodeID, Reason: gap.Reason, Priority: 20})
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].Priority != candidates[j].Priority {
			return candidates[i].Priority > candidates[j].Priority
		}
		if candidates[i].Type != candidates[j].Type {
			return candidates[i].Type < candidates[j].Type
		}
		return candidates[i].ReferenceID < candidates[j].ReferenceID
	})
	requests := 0
	for _, task := range candidates {
		if len(plan.Tasks) >= input.Budget.MaxTasks {
			break
		}
		if requests+task.ValidationRequests > input.Budget.MaxValidationRequests {
			continue
		}
		task.TaskID = taskID(plan.CampaignID, task)
		plan.Tasks = append(plan.Tasks, task)
		requests += task.ValidationRequests
	}
	return plan, nil
}
func validBudget(b CampaignBudget) bool {
	return b.MaxTasks > 0 && b.MaxTasks <= 500 && b.MaxValidationRequests >= 0 && b.MaxValidationRequests <= 500 && b.MaxDuration > 0 && b.MaxDuration <= 24*time.Hour && b.MaxConcurrency > 0 && b.MaxConcurrency <= 100
}
func campaignID(plan CampaignPlan) string {
	sum := sha256.Sum256([]byte(plan.ProjectID + "\x00" + plan.Name + "\x00" + plan.GraphSnapshot + "\x00" + plan.ScopeVersion))
	return hex.EncodeToString(sum[:])
}
func taskID(campaign string, task CampaignTask) string {
	sum := sha256.Sum256([]byte(campaign + "\x00" + string(task.Type) + "\x00" + task.ReferenceID))
	return hex.EncodeToString(sum[:])
}
func nodeReference(graph Graph, id string) string {
	for _, node := range graph.Nodes {
		if node.ID == id {
			return node.Reference
		}
	}
	return ""
}
func parseRiskReference(value string) int {
	parts := strings.Split(value, ":")
	if len(parts) < 2 {
		return 0
	}
	digits := parts[len(parts)-1]
	result := 0
	for _, r := range digits {
		if r < '0' || r > '9' {
			return 0
		}
		result = result*10 + int(r-'0')
	}
	if result > 100 {
		return 100
	}
	return result
}
