package cli

import (
	"bytes"
	"testing"
)

func TestPrintOfflineHelp(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
	}{
		{name: "legacy scan", args: []string{"scan", "--help"}, want: "usage: wraith scan -d DOMAIN --authorized [--json]\n"},
		{name: "npd", args: []string{"pentest", "ports", "scan", "--help"}, want: "usage: wraith pentest ports scan TARGET --project PROJECT --campaign CAMPAIGN --authorized --scope-version VERSION --profile safe|standard|deep|custom [--ports SPEC] [--db PATH] [--dry-run] [--timeout D] [--max-ports N] [--max-requests N] [--max-concurrency N] [--rate N] [--json]\n"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			var output bytes.Buffer
			if !PrintOfflineHelp(testCase.args, &output) {
				t.Fatal("expected offline help handler to claim command")
			}
			if output.String() != testCase.want {
				t.Fatalf("unexpected help output: %q", output.String())
			}
		})
	}
}
