package cli

import (
	"errors"
	"strings"
	"testing"
)

func TestFormatARPOpenErrorExplainsLinuxPrivileges(t *testing.T) {
	message := formatARPOpenError(errors.New("operation not permitted"))
	for _, want := range []string{"ARP", "permission", "CAP_NET_RAW", "elevated"} {
		if !strings.Contains(message, want) {
			t.Fatalf("expected permission guidance to contain %q: %s", want, message)
		}
	}
}

func TestFormatARPOpenErrorPreservesNonPermissionErrors(t *testing.T) {
	message := formatARPOpenError(errors.New("interface unavailable"))
	if !strings.Contains(message, "interface unavailable") {
		t.Fatalf("expected underlying error to be preserved: %s", message)
	}
}
