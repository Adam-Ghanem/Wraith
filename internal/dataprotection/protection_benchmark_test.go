package dataprotection

import (
	"github.com/Adam-Ghanem/Wraith/internal/dataclassification"
	"testing"
)

func BenchmarkAggregateClassification(b *testing.B) {
	for index := 0; index < b.N; index++ {
		_, _ = AggregateClassification(dataclassification.LevelPublic, dataclassification.LevelInternal, dataclassification.LevelSensitive, dataclassification.LevelRestricted)
	}
}

func BenchmarkRedactSecretLikeValue(b *testing.B) {
	for index := 0; index < b.N; index++ {
		_, _ = Redact("Authorization: Bearer example-token")
	}
}
