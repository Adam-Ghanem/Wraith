package scan

import (
	"fmt"
	"strings"

	"github.com/Adam-Ghanem/Wraith/internal/httpengine"
)

// OSFingerprint is intentionally heuristic. It records the packet evidence
// used for the guess so callers can distinguish an inference from an exact OS
// identity.
type OSFingerprint struct {
	Method         string   `json:"method"`
	Family         string   `json:"family"`
	Guess          string   `json:"guess"`
	Confidence     string   `json:"confidence"`
	MatchScore     int      `json:"match_score,omitempty"`
	Evidence       []string `json:"evidence,omitempty"`
	ObservedTTL    int      `json:"observed_ttl,omitempty"`
	InitialTTL     int      `json:"initial_ttl,omitempty"`
	Distance       int      `json:"distance,omitempty"`
	Window         uint16   `json:"window,omitempty"`
	MSS            uint16   `json:"mss,omitempty"`
	WindowScale    uint8    `json:"window_scale,omitempty"`
	WindowScaleSet bool     `json:"window_scale_set,omitempty"`
	SACKPermitted  bool     `json:"sack_permitted,omitempty"`
	Timestamp      bool     `json:"timestamp,omitempty"`
	TCPOptions     string   `json:"tcp_options,omitempty"`
	Error          string   `json:"error,omitempty"`
}

type osSignatureMatch struct {
	family   string
	guess    string
	score    int
	evidence []string
}

func InferOS(response httpengine.SYNResponse) OSFingerprint {
	fingerprint := OSFingerprint{
		Method:         "syn-signature-v2",
		Family:         "unknown",
		Guess:          "Unknown",
		Confidence:     "low",
		ObservedTTL:    response.TTL,
		Window:         response.Window,
		MSS:            response.MSS,
		WindowScale:    response.WindowScale,
		WindowScaleSet: response.WindowScaleSet,
		SACKPermitted:  response.SACKPermitted,
		Timestamp:      response.Timestamp,
		TCPOptions:     response.Options,
	}
	if response.TTL <= 0 {
		return fingerprint
	}

	fingerprint.InitialTTL = inferInitialTTL(response.TTL)
	if fingerprint.InitialTTL >= response.TTL {
		fingerprint.Distance = fingerprint.InitialTTL - response.TTL
	}

	matches := []osSignatureMatch{
		scoreLinuxSignature(response, fingerprint.InitialTTL),
		scoreAppleBSDSignature(response, fingerprint.InitialTTL),
		scoreWindowsSignature(response, fingerprint.InitialTTL),
		scoreApplianceSignature(response, fingerprint.InitialTTL),
	}
	best, second := bestOSSignatures(matches)
	if best.score < 3 {
		fingerprint.Family, fingerprint.Guess = genericOSGuess(fingerprint.InitialTTL)
		fingerprint.Evidence = []string{fmt.Sprintf("observed TTL %d suggests initial TTL %d", response.TTL, fingerprint.InitialTTL)}
		return fingerprint
	}

	fingerprint.Family = best.family
	fingerprint.Guess = best.guess
	fingerprint.MatchScore = best.score
	fingerprint.Evidence = append([]string(nil), best.evidence...)
	margin := best.score - second.score
	switch {
	case best.score >= 8 && margin >= 2:
		fingerprint.Confidence = "medium"
	case best.score >= 5 && margin >= 1:
		fingerprint.Confidence = "low-medium"
	default:
		fingerprint.Confidence = "low"
	}
	return fingerprint
}

func inferInitialTTL(observed int) int {
	switch {
	case observed <= 0:
		return 0
	case observed <= 64:
		return 64
	case observed <= 128:
		return 128
	default:
		return 255
	}
}

func scoreLinuxSignature(response httpengine.SYNResponse, initialTTL int) osSignatureMatch {
	match := osSignatureMatch{family: "Linux", guess: "Linux-like (TCP signature)"}
	if initialTTL == 64 {
		match.add(3, "initial TTL≈64")
	}
	if oneOfUint16(response.Window, 29200, 64240, 65160) {
		match.add(2, fmt.Sprintf("Linux-common TCP window=%d", response.Window))
	}
	if response.WindowScaleSet && response.WindowScale == 7 {
		match.add(2, "window scale=7")
	}
	if response.SACKPermitted {
		match.add(1, "SACK permitted")
	}
	if response.Timestamp {
		match.add(1, "TCP timestamps enabled")
	}
	if oneOfUint16(response.MSS, 1440, 1460) {
		match.add(1, fmt.Sprintf("common Ethernet MSS=%d", response.MSS))
	}
	if optionOrderContains(response.Options, "mss", "sack", "ts", "ws") {
		match.add(1, "option set includes MSS/SACK/timestamp/window-scale")
	}
	return match
}

func scoreAppleBSDSignature(response httpengine.SYNResponse, initialTTL int) osSignatureMatch {
	match := osSignatureMatch{family: "BSD/Apple-like", guess: "macOS/BSD-like (TCP signature)"}
	if initialTTL == 64 {
		match.add(3, "initial TTL≈64")
	}
	if response.Window == 65535 {
		match.add(3, "TCP window=65535")
	}
	if response.WindowScaleSet && (response.WindowScale == 6 || response.WindowScale == 8) {
		match.add(2, fmt.Sprintf("BSD/Apple-common window scale=%d", response.WindowScale))
	}
	if response.SACKPermitted {
		match.add(1, "SACK permitted")
	}
	if response.Timestamp {
		match.add(1, "TCP timestamps enabled")
	}
	if response.MSS == 1460 {
		match.add(1, "MSS=1460")
	}
	return match
}

func scoreWindowsSignature(response httpengine.SYNResponse, initialTTL int) osSignatureMatch {
	match := osSignatureMatch{family: "Windows", guess: "Microsoft Windows-like (TCP signature)"}
	if initialTTL == 128 {
		match.add(4, "initial TTL≈128")
	}
	if oneOfUint16(response.Window, 8192, 16384, 64240, 65535) {
		match.add(2, fmt.Sprintf("Windows-common TCP window=%d", response.Window))
	}
	if response.WindowScaleSet && response.WindowScale == 8 {
		match.add(2, "window scale=8")
	}
	if response.SACKPermitted {
		match.add(1, "SACK permitted")
	}
	if response.MSS == 1460 {
		match.add(1, "MSS=1460")
	}
	if optionOrderContains(response.Options, "mss", "ws", "sack") {
		match.add(1, "option set includes MSS/window-scale/SACK")
	}
	return match
}

func scoreApplianceSignature(response httpengine.SYNResponse, initialTTL int) osSignatureMatch {
	match := osSignatureMatch{family: "network-appliance/Unix-like", guess: "Network appliance or Unix-like OS (TCP signature)"}
	if initialTTL == 255 {
		match.add(4, "initial TTL≈255")
	}
	if oneOfUint16(response.Window, 4128, 8760, 16384, 32768, 65535) {
		match.add(1, fmt.Sprintf("appliance-common TCP window=%d", response.Window))
	}
	if !response.Timestamp {
		match.add(1, "TCP timestamps absent")
	}
	return match
}

func (match *osSignatureMatch) add(points int, evidence string) {
	match.score += points
	if strings.TrimSpace(evidence) != "" {
		match.evidence = append(match.evidence, evidence)
	}
}

func bestOSSignatures(matches []osSignatureMatch) (osSignatureMatch, osSignatureMatch) {
	var best, second osSignatureMatch
	for _, candidate := range matches {
		if candidate.score > best.score {
			second = best
			best = candidate
			continue
		}
		if candidate.score > second.score {
			second = candidate
		}
	}
	return best, second
}

func genericOSGuess(initialTTL int) (string, string) {
	switch initialTTL {
	case 64:
		return "Unix-like", "Unix-like (TTL only)"
	case 128:
		return "Windows-like", "Windows-like (TTL only)"
	case 255:
		return "network-appliance/Unix-like", "Network appliance or Unix-like OS (TTL only)"
	default:
		return "unknown", "Unknown"
	}
}

func oneOfUint16(value uint16, candidates ...uint16) bool {
	for _, candidate := range candidates {
		if value == candidate {
			return true
		}
	}
	return false
}

func optionOrderContains(raw string, names ...string) bool {
	value := strings.ToLower(strings.TrimSpace(raw))
	if value == "" {
		return false
	}
	position := 0
	for _, name := range names {
		index := strings.Index(value[position:], strings.ToLower(name))
		if index < 0 {
			return false
		}
		position += index + len(name)
	}
	return true
}

func OSFingerprintUnavailable(reason string) OSFingerprint {
	return OSFingerprint{
		Method:     "syn-signature-v2",
		Family:     "unknown",
		Guess:      "Unavailable",
		Confidence: "none",
		Error:      reason,
	}
}
