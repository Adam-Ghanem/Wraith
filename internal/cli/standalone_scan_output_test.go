package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Adam-Ghanem/Wraith/internal/npd"
	"github.com/Adam-Ghanem/Wraith/internal/scan"
)

func TestStripStandaloneOutputOptions(t *testing.T) {
	clean, outputs, err := stripStandaloneOutputOptions([]string{"scan", "example.com", "-oN", "scan.txt", "-oX=scan.xml", "-p", "22"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"scan", "example.com", "-p", "22"}
	if !reflect.DeepEqual(clean, want) {
		t.Fatalf("clean=%v, want %v", clean, want)
	}
	if outputs.normal != "scan.txt" || outputs.xml != "scan.xml" {
		t.Fatalf("unexpected outputs: %#v", outputs)
	}
}

func TestStripStandaloneOutputOptionsRejectsAllConflict(t *testing.T) {
	_, _, err := stripStandaloneOutputOptions([]string{"scan", "example.com", "-oA", "scan", "-oN", "scan.txt"})
	if err == nil {
		t.Fatal("expected -oA conflict")
	}
}

func TestDecodeStandaloneOutputPayloadFlattensDiscovery(t *testing.T) {
	payload, err := decodeStandaloneOutputPayload([]byte(`[{"hosts":["tcp://[2001:db8::1]/"],"count":1},{"hosts":[],"count":0}]`))
	if err != nil {
		t.Fatal(err)
	}
	if !payload.Discovery || len(payload.Hosts) != 1 || payload.Hosts[0] != "tcp://[2001:db8::1]/" {
		t.Fatalf("unexpected payload: %#v", payload)
	}
}

func TestWriteStandaloneNormalPayloadPreservesEmptyScanMessage(t *testing.T) {
	var buffer bytes.Buffer
	if err := writeStandaloneNormalPayload(&buffer, standaloneOutputPayload{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buffer.String(), "No live hosts found") {
		t.Fatalf("output=%q", buffer.String())
	}

	buffer.Reset()
	if err := writeStandaloneNormalPayload(&buffer, standaloneOutputPayload{Discovery: true}); err != nil {
		t.Fatal(err)
	}
	if buffer.Len() != 0 {
		t.Fatalf("empty discovery output=%q, want empty", buffer.String())
	}
}

func TestMarshalStandaloneXMLIncludesPortAndOS(t *testing.T) {
	payload := standaloneOutputPayload{Results: []scan.Result{{
		Target: "tcp://192.0.2.10/",
		State:  scan.StateCompleted,
		Ports: []npd.PortResult{{
			Port:     22,
			Protocol: "tcp",
			State:    npd.StateOpen,
			Service:  "ssh",
			Version:  "9.6",
		}},
		OS: &scan.OSFingerprint{Guess: "Linux/Unix-like", Confidence: "medium"},
	}}}
	data, err := marshalStandaloneXML(payload)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, want := range []string{"<wraithrun", `target="tcp://192.0.2.10/"`, `portid="22"`, `service="ssh"`, `guess="Linux/Unix-like"`} {
		if !strings.Contains(text, want) {
			t.Fatalf("XML missing %q: %s", want, text)
		}
	}
}

func TestWriteStandaloneOutputFilesAll(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "scan")
	payload := standaloneOutputPayload{Results: []scan.Result{{
		Target: "tcp://192.0.2.10/",
		State:  scan.StateCompleted,
		Ports:  []npd.PortResult{{Port: 80, Protocol: "tcp", State: npd.StateOpen, Service: "http"}},
	}}}
	if err := writeStandaloneOutputFiles(standaloneOutputOptions{allBase: base}, payload); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{".nmap", ".xml", ".gnmap"} {
		path := base + suffix
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if len(data) == 0 {
			t.Fatalf("%s is empty", path)
		}
	}
}
