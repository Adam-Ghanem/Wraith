package cli

import (
	"reflect"
	"testing"

	"github.com/Adam-Ghanem/Wraith/internal/npd"
	"github.com/Adam-Ghanem/Wraith/internal/udpscan"
)

func TestSplitStandaloneScanArgsAllowsFlagsBeforeTarget(t *testing.T) {
	flags, target, err := splitStandaloneScanArgs([]string{"-sU", "-p", "53,123", "example.com"})
	if err != nil {
		t.Fatalf("splitStandaloneScanArgs() error = %v", err)
	}
	if target != "example.com" {
		t.Fatalf("target = %q, want example.com", target)
	}
	want := []string{"-sU", "-p", "53,123"}
	if !reflect.DeepEqual(flags, want) {
		t.Fatalf("flags = %v, want %v", flags, want)
	}
}

func TestStandaloneScanPortsUsesUDPDefaults(t *testing.T) {
	ports, err := standaloneScanPorts(npd.ProfileStandard, "", 0, true)
	if err != nil {
		t.Fatalf("standaloneScanPorts() error = %v", err)
	}
	if !reflect.DeepEqual(ports, udpscan.DefaultPorts()) {
		t.Fatalf("UDP default ports = %v", ports)
	}
}

func TestSplitStandaloneScanArgsExpandsFullRange(t *testing.T) {
	flags, target, err := splitStandaloneScanArgs([]string{"example.com", "-p-"})
	if err != nil {
		t.Fatalf("splitStandaloneScanArgs() error = %v", err)
	}
	if target != "example.com" || !reflect.DeepEqual(flags, []string{"-p", "1-65535"}) {
		t.Fatalf("target=%q flags=%v", target, flags)
	}
}
