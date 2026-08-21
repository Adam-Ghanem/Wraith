package datagovernance

import (
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/dataclassification"
)

func BenchmarkEvaluateTechnicalProjection(b *testing.B) {
	now := time.Date(2026, time.August, 21, 12, 0, 0, 0, time.UTC)
	policy, err := NewPolicy(PolicyInput{ProjectID: "project-a", Version: "policy-v1", CreatedAt: now, Rules: []Rule{{Consumer: ConsumerTechnicalReport, Maximum: dataclassification.LevelSensitive, Retention: 24 * time.Hour}}})
	if err != nil {
		b.Fatal(err)
	}
	input := EvaluationInput{Policy: policy, ProjectID: "project-a", Subject: SubjectEvidence, Classification: dataclassification.LevelSensitive, Consumer: ConsumerTechnicalReport, OccurredAt: now}
	b.ReportAllocs()
	for index := 0; index < b.N; index++ {
		if _, err := Evaluate(input); err != nil {
			b.Fatal(err)
		}
	}
}
