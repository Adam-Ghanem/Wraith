package portscan

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/executil"
	"github.com/Adam-Ghanem/Wraith/internal/model"
)

const (
	DefaultTimeout    = 5 * time.Minute
	DefaultTopPorts   = 1000
	DefaultMaxOutput  = 8 << 20
	DefaultMaxTargets = 100
	ToolName          = "nmap"
)

var lookupBinary = exec.LookPath

type Target struct {
	IP        string
	Subdomain string
}

type Finding struct {
	model.PortResult
	SubdomainOrIP string `json:"subdomain_or_ip"`
	IP            string `json:"ip,omitempty"`
	Source        string `json:"source"`
}

type Config struct {
	Timeout        time.Duration
	TopPorts       int
	MaxOutputBytes int64
}

func (c Config) Validate() error {
	if c.Timeout <= 0 || c.Timeout > DefaultTimeout {
		return fmt.Errorf("nmap timeout must be between 1 and %s", DefaultTimeout)
	}
	if c.TopPorts < 1 || c.TopPorts > DefaultTopPorts {
		return fmt.Errorf("nmap top ports must be between 1 and %d", DefaultTopPorts)
	}
	if c.MaxOutputBytes < 0 || c.MaxOutputBytes > DefaultMaxOutput {
		return fmt.Errorf("nmap output limit must be between 1 and %d bytes", DefaultMaxOutput)
	}
	return nil
}

func (c Config) withDefaults() Config {
	if c.MaxOutputBytes == 0 {
		c.MaxOutputBytes = DefaultMaxOutput
	}
	return c
}

type ScanResult struct {
	Findings []Finding
	Errors   []string
	Skipped  bool
	Reason   string
}

func BuildArgs(target Target, topPorts int) []string {
	return []string{
		"-sT",
		"-n",
		"-Pn",
		"-T3",
		"--top-ports", strconv.Itoa(topPorts),
		"--max-retries", "2",
		"--open",
		"-oX", "-",
		target.IP,
	}
}

func Scan(ctx context.Context, targets []Target, config Config) (ScanResult, error) {
	if ctx == nil {
		return ScanResult{}, errors.New("nmap context is required")
	}
	config = config.withDefaults()
	if err := config.Validate(); err != nil {
		return ScanResult{}, err
	}
	path, err := lookupBinary(ToolName)
	if err != nil {
		return ScanResult{Skipped: true, Reason: "nmap binary not found"}, nil
	}
	if len(targets) == 0 {
		return ScanResult{Skipped: true, Reason: "no same-scan IP targets"}, nil
	}
	if len(targets) > DefaultMaxTargets {
		targets = targets[:DefaultMaxTargets]
	}
	result := ScanResult{Findings: make([]Finding, 0)}
	seenTargets := make(map[string]struct{}, len(targets))
	for _, target := range targets {
		if err := validateScanTarget(target); err != nil {
			result.Errors = append(result.Errors, err.Error())
			continue
		}
		if _, seen := seenTargets[target.IP]; seen {
			continue
		}
		seenTargets[target.IP] = struct{}{}
		targetCtx, cancel := context.WithTimeout(ctx, config.Timeout)
		commandResult, runErr := executil.Run(targetCtx, path, BuildArgs(target, config.TopPorts), nil, config.MaxOutputBytes)
		cancel()
		if runErr != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", target.IP, runErr))
			continue
		}
		findings, parseErr := ParseXML(commandResult.Stdout, target)
		if parseErr != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", target.IP, parseErr))
			continue
		}
		result.Findings = append(result.Findings, findings...)
	}
	sort.Slice(result.Findings, func(i, j int) bool {
		if result.Findings[i].SubdomainOrIP != result.Findings[j].SubdomainOrIP {
			return result.Findings[i].SubdomainOrIP < result.Findings[j].SubdomainOrIP
		}
		return result.Findings[i].Port < result.Findings[j].Port
	})
	return result, nil
}

func ParseXML(data []byte, target Target) ([]Finding, error) {
	if int64(len(data)) > DefaultMaxOutput {
		return nil, errors.New("nmap XML exceeds configured output limit")
	}
	if err := validateTargetIP(target.IP); err != nil {
		return nil, err
	}
	var document nmapDocument
	if err := xml.Unmarshal(data, &document); err != nil {
		return nil, fmt.Errorf("parse nmap XML: %w", err)
	}
	findings := make([]Finding, 0)
	for _, host := range document.Hosts {
		if !hostContainsIP(host, target.IP) {
			continue
		}
		for _, port := range host.Ports.Ports {
			if port.State.State != "open" && port.State.State != "open|filtered" {
				continue
			}
			portNumber, err := strconv.Atoi(port.PortID)
			if err != nil || portNumber < 1 || portNumber > 65535 {
				continue
			}
			findings = append(findings, Finding{
				PortResult: model.PortResult{
					Port:     uint16(portNumber),
					Status:   port.State.State,
					Service:  port.Service.Name,
					Protocol: port.Protocol,
					Banner:   serviceEvidence(port.Service),
				},
				SubdomainOrIP: firstNonEmpty(target.Subdomain, target.IP),
				IP:            target.IP,
				Source:        ToolName,
			})
		}
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Port < findings[j].Port })
	return findings, nil
}

func validateScanTarget(target Target) error {
	if err := validateTargetIP(target.IP); err != nil {
		return err
	}
	if strings.TrimSpace(target.Subdomain) == "" {
		return errors.New("nmap target subdomain is required for discovered target")
	}
	return nil
}

func validateTargetIP(rawIP string) error {
	if net.ParseIP(strings.TrimSpace(rawIP)) == nil {
		return fmt.Errorf("nmap target IP is invalid: %q", rawIP)
	}
	return nil
}

type nmapDocument struct {
	Hosts []nmapHost `xml:"host"`
}

type nmapHost struct {
	Addresses []nmapAddress `xml:"address"`
	Ports     nmapPorts     `xml:"ports"`
}

type nmapAddress struct {
	Address string `xml:"addr,attr"`
}

type nmapPorts struct {
	Ports []nmapPort `xml:"port"`
}

type nmapPort struct {
	Protocol string      `xml:"protocol,attr"`
	PortID   string      `xml:"portid,attr"`
	State    nmapState   `xml:"state"`
	Service  nmapService `xml:"service"`
}

type nmapState struct {
	State string `xml:"state,attr"`
}

type nmapService struct {
	Name      string `xml:"name,attr"`
	Product   string `xml:"product,attr"`
	Version   string `xml:"version,attr"`
	ExtraInfo string `xml:"extrainfo,attr"`
}

func hostContainsIP(host nmapHost, targetIP string) bool {
	for _, address := range host.Addresses {
		if address.Address == targetIP {
			return true
		}
	}
	return false
}

func serviceEvidence(service nmapService) string {
	parts := make([]string, 0, 3)
	for _, value := range []string{service.Product, service.Version, service.ExtraInfo} {
		if strings.TrimSpace(value) != "" {
			parts = append(parts, strings.TrimSpace(value))
		}
	}
	return strings.Join(parts, " ")
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
