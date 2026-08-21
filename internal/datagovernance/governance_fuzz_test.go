package datagovernance

import (
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/dataclassification"
)

func FuzzNewPolicyAndEvaluate(f *testing.F) {
	f.Add("project-a", "policy-v1", "technical_report", "sensitive", int64(time.Hour))
	f.Fuzz(func(t *testing.T, projectID, version, consumer, level string, retentionNanos int64) {
		if retentionNanos < 1 || retentionNanos > int64(366*24*time.Hour) {
			retentionNanos = int64(time.Hour)
		}
		now := time.Date(2026, time.August, 21, 12, 0, 0, 0, time.UTC)
		policy, err := NewPolicy(PolicyInput{ProjectID: projectID, Version: version, CreatedAt: now, Rules: []Rule{{Consumer: Consumer(consumer), Maximum: dataclassification.Level(level), Retention: time.Duration(retentionNanos)}}})
		if err != nil {
			return
		}
		if err := ValidatePolicy(policy); err != nil {
			t.Fatalf("valid policy rejected: %v", err)
		}
		decision, err := Evaluate(EvaluationInput{Policy: policy, ProjectID: projectID, Subject: SubjectEvidence, Classification: dataclassification.Level(level), Consumer: Consumer(consumer), OccurredAt: now})
		if err == nil && ValidateDecision(decision) != nil {
			t.Fatal("returned decision did not validate")
		}
	})
}

func FuzzRetentionEvaluation(f *testing.F) {
	f.Add("evidence-1", int64(time.Hour), false)
	f.Fuzz(func(t *testing.T, reference string, retentionNanos int64, hold bool) {
		if retentionNanos < 1 || retentionNanos > int64(366*24*time.Hour) {
			retentionNanos = int64(time.Hour)
		}
		now := time.Date(2026, time.August, 21, 12, 0, 0, 0, time.UTC)
		policy, err := NewPolicy(PolicyInput{ProjectID: "project-a", Version: "policy-v1", CreatedAt: now, Rules: []Rule{{Consumer: ConsumerLocalStorage, Maximum: dataclassification.LevelInternal, Retention: time.Hour}}})
		if err != nil {
			t.Fatal(err)
		}
		record, err := NewRetentionRecord(RetentionInput{ProjectID: "project-a", Policy: policy, SubjectReference: reference, CreatedAt: now, RetainUntil: now.Add(time.Duration(retentionNanos)), Hold: hold})
		if err != nil {
			return
		}
		if _, err := EvaluateRetention(record, now); err != nil {
			t.Fatalf("valid retention record rejected: %v", err)
		}
	})
}
