package fuzzing

import (
	"errors"
	"sort"

	"github.com/Adam-Ghanem/Wraith/internal/httpengine"
)

var ErrInvalidAnalysis = errors.New("invalid fuzz analysis")

type AnalyzedResult struct {
	Mutation Mutation         `json:"mutation"`
	Analysis ResponseAnalysis `json:"analysis"`
}

func AnalyzeJob(plan FuzzPlan, job FuzzJob, baseline *httpengine.Response) ([]AnalyzedResult, error) {
	if job.State != JobCompleted || plan.ID == "" || plan.ID != job.ID && job.ID != "" {
		return nil, ErrInvalidAnalysis
	}
	mutations := make(map[string]Mutation, len(plan.Requests))
	for _, request := range plan.Requests {
		if request.Mutation.ID == "" {
			return nil, ErrInvalidAnalysis
		}
		mutations[request.Mutation.ID] = request.Mutation
	}
	result := make([]AnalyzedResult, 0, len(job.Results))
	for _, response := range job.Results {
		mutation, exists := mutations[response.MutationID]
		if !exists {
			return nil, ErrInvalidAnalysis
		}
		result = append(result, AnalyzedResult{Mutation: mutation, Analysis: AnalyzeResponse(baseline, mutation, response.Response)})
	}
	sort.Slice(result, func(left, right int) bool { return result[left].Mutation.ID < result[right].Mutation.ID })
	return result, nil
}
