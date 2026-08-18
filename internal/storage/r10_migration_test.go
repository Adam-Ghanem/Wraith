package storage

import (
	"context"
	"strings"
	"testing"
)

func TestR10MigrationCreatesSecretFreeAuthenticationTables(t *testing.T) {
	db, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := db.sql.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN ('identities','sessions_metadata','authentication_targets','authentication_runs','authentication_observations','lockout_observations','identity_observations','authorization_matrix')`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 8 {
		t.Fatalf("authentication table count=%d", count)
	}
	rows, err := db.sql.Query(`PRAGMA table_info(authentication_observations)`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, kind string
		var notNull, primary int
		var defaultValue any
		if err := rows.Scan(&cid, &name, &kind, &notNull, &defaultValue, &primary); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(strings.ToLower(name), "password") || strings.Contains(strings.ToLower(name), "credential_value") || strings.Contains(strings.ToLower(name), "secret") {
			t.Fatalf("forbidden secret column %q", name)
		}
	}
}
