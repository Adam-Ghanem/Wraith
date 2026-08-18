package storage

import (
	"context"
	"testing"
	"time"
)

func TestIdentityRecordsRemainProjectScoped(t *testing.T) {
	db, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := db.CreateIdentity(ctx, IdentityRecord{ProjectID: "alpha", IdentityID: "id-a", Name: "reader", Role: "user", Status: "active", CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := db.CreateIdentity(ctx, IdentityRecord{ProjectID: "beta", IdentityID: "id-b", Name: "reader", Role: "user", Status: "active", CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	identities, err := db.ListIdentities(ctx, "alpha")
	if err != nil {
		t.Fatal(err)
	}
	if len(identities) != 1 || identities[0].ProjectID != "alpha" || identities[0].IdentityID != "id-a" {
		t.Fatalf("identities=%#v", identities)
	}
}
