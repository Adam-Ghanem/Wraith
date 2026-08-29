package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/Adam-Ghanem/Wraith/internal/scan"
	"github.com/Adam-Ghanem/Wraith/internal/serviceprobe"
)

type standaloneOutputOptions struct {
	normal   string
	xml      string
	grepable string
	allBase  string
}

type standaloneOutputPayload struct {
	Results   []scan.Result
	Hosts     []string
	Discovery bool
}

func runStandaloneScanWithOutputs(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	cleanArgs, outputs, err := stripStandaloneOutputOptions(args)
	if err != nil {
		return err
	}
	if outputs == (standaloneOutputOptions{}) {
		return runStandaloneScanBase(ctx, cleanArgs, stdout, stderr)
	}

	jsonStdout := hasStandaloneExactFlag(cleanArgs[1:], "--json")
	execArgs := append([]string(nil), cleanArgs...)
	if !jsonStdout {
		execArgs = append(execArgs, "--json")
	}
	var encoded bytes.Buffer
	if err := runStandaloneScanBase(ctx, execArgs, &encoded, stderr); err != nil {
		return err
	}
	payload, err := decodeStandaloneOutputPayload(encoded.Bytes())
	if err != nil {
		return err
	}

	if jsonStdout {
		if _, err := stdout.Write(encoded.Bytes()); err != nil {
			return err
		}
	} else if err := writeStandaloneNormalPayload(stdout, payload); err != nil {
		return err
	}

	return writeStandaloneOutputFiles(outputs, payload)
}

func runStandaloneScanBase(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if hasStandaloneInputList(args) {
		return RunStandaloneScanList(ctx, args, stdout, stderr)
	}
	return RunStandaloneScan(ctx, args, stdout, stderr)
}

func stripStandaloneOutputOptions(args []string) ([]string, standaloneOutputOptions, error) {
	if len(args) == 0 {
		return nil, standaloneOutputOptions{}, errors.New("missing scan command")
	}
	clean := []string{args[0]}
	var out standaloneOutputOptions
	for i := 1; i < len(args); i++ {
		raw := strings.TrimSpace(args[i])
		name, inline, matched := standaloneOutputFlag(raw)
		if !matched {
			clean = append(clean, args[i])
			continue
		}
		value := inline
		if value == "" {
			if i+1 >= len(args) {
				return nil, out, fmt.Errorf("%s requires a file path", name)
			}
			i++
			value = strings.TrimSpace(args[i])
		}
		if value == "" || value == "-" {
			return nil, out, fmt.Errorf("%s requires a local file path", name)
		}
		switch name {
		case "-oN":
			if out.normal != "" {
				return nil, out, errors.New("-oN may be specified only once")
			}
			out.normal = value
		case "-oX":
			if out.xml != "" {
				return nil, out, errors.New("-oX may be specified only once")
			}
			out.xml = value
		case "-oG":
			if out.grepable != "" {
				return nil, out, errors.New("-oG may be specified only once")
			}
			out.grepable = value
		case "-oA":
			if out.allBase != "" {
				return nil, out, errors.New("-oA may be specified only once")
			}
			out.allBase = value
		}
	}
	if out.allBase != "" && (out.normal != "" || out.xml != "" || out.grepable != "") {
		return nil, out, errors.New("-oA cannot be combined with -oN, -oX, or -oG")
	}
	return clean, out, nil
}

func standaloneOutputFlag(raw string) (string, string, bool) {
	for _, name := range []string{"-oN", "-oX", "-oG", "-oA"} {
		if raw == name {
			return name, "", true
		}
		if strings.HasPrefix(raw, name+"=") {
			return name, strings.TrimSpace(strings.TrimPrefix(raw, name+"=")), true
		}
	}
	return "", "", false
}

func decodeStandaloneOutputPayload(data []byte) (standaloneOutputPayload, error) {
	var raw any
	if err := json.Unmarshal(data, &raw); err != nil {
		return standaloneOutputPayload{}, fmt.Errorf("decode scan output: %w", err)
	}
	payload := standaloneOutputPayload{}
	if err := collectStandaloneOutputValue(&payload, raw); err != nil {
		return standaloneOutputPayload{}, err
	}
	seenHosts := map[string]struct{}{}
	deduped := make([]string, 0, len(payload.Hosts))
	for _, host := range payload.Hosts {
		if _, ok := seenHosts[host]; ok {
			continue
		}
		seenHosts[host] = struct{}{}
		deduped = append(deduped, host)
	}
	payload.Hosts = deduped
	sort.Slice(payload.Results, func(i, j int) bool { return payload.Results[i].Target < payload.Results[j].Target })
	return payload, nil
}

func collectStandaloneOutputValue(payload *standaloneOutputPayload, value any) error {
	switch typed := value.(type) {
	case []any:
		for _, item := range typed {
			if err := collectStandaloneOutputValue(payload, item); err != nil {
				return err
			}
		}
		return nil
	case map[string]any:
		if hosts, ok := typed["hosts"].([]any); ok {
			payload.Discovery = true
			for _, rawHost := range hosts {
				if host, ok := rawHost.(string); ok && strings.TrimSpace(host) != "" {
					payload.Hosts = append(payload.Hosts, host)
				}
			}
			return nil
		}
		if _, ok := typed["target"]; ok {
			encoded, err := json.Marshal(typed)
			if err != nil {
				return err
			}
			var result scan.Result
			if err := json.Unmarshal(encoded, &result); err != nil {
				return fmt.Errorf("decode structured scan result: %w", err)
			}
			payload.Results = append(payload.Results, result)
			return nil
		}
	}
	return errors.New("unsupported structured scan output")
}

func writeStandaloneNormalPayload(writer io.Writer, payload standaloneOutputPayload) error {
	if len(payload.Results) == 0 {
		if payload.Discovery {
			return writeDiscoveredHosts(writer, payload.Hosts, false)
		}
		_, err := fmt.Fprintln(writer, "No live hosts found. Use -Pn to skip host discovery.")
		return err
	}
	for i, result := range payload.Results {
		if i > 0 {
			if _, err := fmt.Fprintln(writer); err != nil {
				return err
			}
		}
		if err := writeStandaloneScanResult(writer, result); err != nil {
			return err
		}
	}
	return nil
}

func writeStandaloneOutputFiles(outputs standaloneOutputOptions, payload standaloneOutputPayload) error {
	if outputs.allBase != "" {
		outputs.normal = outputs.allBase + ".nmap"
		outputs.xml = outputs.allBase + ".xml"
		outputs.grepable = outputs.allBase + ".gnmap"
	}
	if outputs.normal != "" {
		var buffer bytes.Buffer
		if err := writeStandaloneNormalPayload(&buffer, payload); err != nil {
			return err
		}
		if err := os.WriteFile(outputs.normal, buffer.Bytes(), 0o600); err != nil {
			return fmt.Errorf("write -oN output: %w", err)
		}
	}
	if outputs.xml != "" {
		data, err := marshalStandaloneXML(payload)
		if err != nil {
			return err
		}
		if err := os.WriteFile(outputs.xml, data, 0o600); err != nil {
			return fmt.Errorf("write -oX output: %w", err)
		}
	}
	if outputs.grepable != "" {
		var buffer bytes.Buffer
		if err := writeStandaloneGrepable(&buffer, payload); err != nil {
			return err
		}
		if err := os.WriteFile(outputs.grepable, buffer.Bytes(), 0o600); err != nil {
			return fmt.Errorf("write -oG output: %w", err)
		}
	}
	return nil
}

type standaloneXMLRun struct {
	XMLName xml.Name            `xml:"wraithrun"`
	Scanner string              `xml:"scanner,attr"`
	Hosts   []standaloneXMLHost `xml:"host"`
}

type standaloneXMLHost struct {
	Target string              `xml:"target,attr"`
	State  string              `xml:"state,attr"`
	Ports  []standaloneXMLPort `xml:"ports>port,omitempty"`
	OS     *standaloneXMLOS    `xml:"os,omitempty"`
}

type standaloneXMLPort struct {
	Port     uint16 `xml:"portid,attr"`
	Protocol string `xml:"protocol,attr"`
	State    string `xml:"state,attr"`
	Service  string `xml:"service,attr,omitempty"`
	Version  string `xml:"version,attr,omitempty"`
}

type standaloneXMLOS struct {
	Guess      string `xml:"guess,attr,omitempty"`
	Confidence string `xml:"confidence,attr,omitempty"`
	Error      string `xml:"error,attr,omitempty"`
}

func marshalStandaloneXML(payload standaloneOutputPayload) ([]byte, error) {
	run := standaloneXMLRun{Scanner: "wraith"}
	for _, target := range payload.Hosts {
		run.Hosts = append(run.Hosts, standaloneXMLHost{Target: target, State: "up"})
	}
	for _, result := range payload.Results {
		host := standaloneXMLHost{Target: result.Target, State: string(result.State)}
		for _, item := range result.Ports {
			host.Ports = append(host.Ports, standaloneXMLPort{Port: item.Port, Protocol: item.Protocol, State: string(item.State), Service: item.Service, Version: item.Version})
		}
		if result.OS != nil {
			host.OS = &standaloneXMLOS{Guess: result.OS.Guess, Confidence: result.OS.Confidence, Error: result.OS.Error}
		}
		run.Hosts = append(run.Hosts, host)
	}
	data, err := xml.MarshalIndent(run, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode XML scan output: %w", err)
	}
	return append([]byte(xml.Header), append(data, '\n')...), nil
}

func writeStandaloneGrepable(writer io.Writer, payload standaloneOutputPayload) error {
	for _, target := range payload.Hosts {
		if _, err := fmt.Fprintf(writer, "Host: %s\tStatus: Up\n", displayStandaloneHost(target)); err != nil {
			return err
		}
	}
	for _, result := range payload.Results {
		parts := make([]string, 0, len(result.Ports))
		for _, item := range result.Ports {
			service := item.Service
			if service == "" {
				service = serviceprobe.ServiceName(item.Port)
			}
			parts = append(parts, fmt.Sprintf("%d/%s/%s//%s/%s/", item.Port, item.State, item.Protocol, sanitizeGrepable(service), sanitizeGrepable(item.Version)))
		}
		if _, err := fmt.Fprintf(writer, "Host: %s\tPorts: %s\n", displayStandaloneHost(result.Target), strings.Join(parts, ", ")); err != nil {
			return err
		}
	}
	return nil
}

func displayStandaloneHost(target string) string {
	if host, err := serviceprobe.ParseHost(target); err == nil {
		return host
	}
	return target
}

func sanitizeGrepable(value string) string {
	value = strings.ReplaceAll(value, "/", "-")
	value = strings.ReplaceAll(value, "\t", " ")
	value = strings.ReplaceAll(value, "\r", " ")
	value = strings.ReplaceAll(value, "\n", " ")
	return strings.Join(strings.Fields(value), " ")
}
