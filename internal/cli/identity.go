package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/authsecurity"
	"github.com/Adam-Ghanem/Wraith/internal/storage"
)

func runIdentity(ctx context.Context, args []string, stdout, _ io.Writer) error {
	if len(args) < 2 || args[0] != "identity" || (args[1] != "list" && args[1] != "create") {
		return errors.New("usage: wraith identity list|create --project PROJECT [--name NAME --role ROLE --description TEXT] [--db PATH] [--json]")
	}
	fs := flag.NewFlagSet("identity", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	project := fs.String("project", "", "")
	databasePath := fs.String("db", DefaultDatabasePath, "")
	name := fs.String("name", "", "")
	role := fs.String("role", "", "")
	description := fs.String("description", "", "")
	jsonOutput := fs.Bool("json", false, "")
	if err := fs.Parse(args[2:]); err != nil || fs.NArg() != 0 || strings.TrimSpace(*project) == "" || strings.TrimSpace(*databasePath) == "" {
		return errors.New("usage: wraith identity list|create --project PROJECT [--name NAME --role ROLE --description TEXT] [--db PATH] [--json]")
	}
	database, err := storage.Open(strings.TrimSpace(*databasePath))
	if err != nil {
		return err
	}
	defer database.Close()
	if err := database.Migrate(ctx); err != nil {
		return err
	}
	if args[1] == "create" {
		identity, err := authsecurity.NewIdentityContext(strings.TrimSpace(*project), strings.TrimSpace(*name), strings.TrimSpace(*role), strings.TrimSpace(*description), time.Now().UTC())
		if err != nil {
			return err
		}
		if err := database.CreateIdentity(ctx, storage.IdentityRecord{ProjectID: identity.ProjectID, IdentityID: identity.ID, Name: identity.Name, Role: identity.Role, Description: identity.Description, Status: identity.Status, CreatedAt: identity.CreatedAt, UpdatedAt: identity.UpdatedAt}); err != nil {
			return err
		}
		if *jsonOutput {
			return json.NewEncoder(stdout).Encode(identity)
		}
		_, err = fmt.Fprintf(stdout, "created identity %s for project %s\n", identity.Name, identity.ProjectID)
		return err
	}
	identities, err := database.ListIdentities(ctx, strings.TrimSpace(*project))
	if err != nil {
		return err
	}
	if *jsonOutput {
		return json.NewEncoder(stdout).Encode(identities)
	}
	for _, identity := range identities {
		if _, err := fmt.Fprintf(stdout, "%s\t%s\t%s\n", identity.IdentityID, identity.Name, identity.Role); err != nil {
			return err
		}
	}
	return nil
}
