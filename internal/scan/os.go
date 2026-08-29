package scan

import "github.com/Adam-Ghanem/Wraith/internal/httpengine"

// OSFingerprint is intentionally heuristic. It records the packet evidence
// used for the guess so callers can distinguish an inference from an exact OS
// identity.
type OSFingerprint struct {
	Method         string `json:"method"`
	Family         string `json:"family"`
	Guess          string `json:"guess"`
	Confidence     string `json:"confidence"`
	ObservedTTL    int    `json:"observed_ttl,omitempty"`
	InitialTTL     int    `json:"initial_ttl,omitempty"`
	Distance       int    `json:"distance,omitempty"`
	Window         uint16 `json:"window,omitempty"`
	MSS            uint16 `json:"mss,omitempty"`
	WindowScale    uint8  `json:"window_scale,omitempty"`
	WindowScaleSet bool   `json:"window_scale_set,omitempty"`
	SACKPermitted  bool   `json:"sack_permitted,omitempty"`
	Timestamp      bool   `json:"timestamp,omitempty"`
	TCPOptions     string `json:"tcp_options,omitempty"`
	Error          string `json:"error,omitempty"`
}

func InferOS(response httpengine.SYNResponse) OSFingerprint {
	fingerprint := OSFingerprint{
		Method:         "syn-heuristic",
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

	switch {
	case response.TTL <= 64:
		fingerprint.InitialTTL = 64
		fingerprint.Family = "Unix-like"
		fingerprint.Guess = "Linux/Unix-like"
		if response.WindowScaleSet && response.WindowScale == 7 && response.SACKPermitted && response.Timestamp && (response.Window == 64240 || response.Window == 29200) {
			fingerprint.Family = "Linux"
			fingerprint.Guess = "Linux (heuristic)"
			fingerprint.Confidence = "medium"
		} else if response.Window == 65535 && response.WindowScaleSet && (response.WindowScale == 6 || response.WindowScale == 8) {
			fingerprint.Family = "BSD/Apple-like"
			fingerprint.Guess = "macOS/BSD-like (heuristic)"
			fingerprint.Confidence = "low"
		}
	case response.TTL <= 128:
		fingerprint.InitialTTL = 128
		fingerprint.Family = "Windows"
		fingerprint.Guess = "Microsoft Windows (heuristic)"
		if response.Window == 64240 || response.Window == 65535 || response.Window == 8192 || response.Window == 16384 {
			fingerprint.Confidence = "medium"
		}
	default:
		fingerprint.InitialTTL = 255
		fingerprint.Family = "network-appliance/Unix-like"
		fingerprint.Guess = "Network appliance or Unix-like OS (heuristic)"
		fingerprint.Confidence = "low"
	}
	if fingerprint.InitialTTL >= response.TTL {
		fingerprint.Distance = fingerprint.InitialTTL - response.TTL
	}
	return fingerprint
}

func OSFingerprintUnavailable(reason string) OSFingerprint {
	return OSFingerprint{
		Method:     "syn-heuristic",
		Family:     "unknown",
		Guess:      "Unavailable",
		Confidence: "none",
		Error:      reason,
	}
}
