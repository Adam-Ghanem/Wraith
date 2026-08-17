package storage

import (
	"sort"
	"strconv"
)

func DiffDevices(previous, current []DeviceSnapshot) []DeviceChange {
	before := make(map[string]DeviceSnapshot, len(previous))
	after := make(map[string]DeviceSnapshot, len(current))
	for _, device := range previous {
		before[device.IP] = device
	}
	for _, device := range current {
		after[device.IP] = device
	}

	changes := make([]DeviceChange, 0)
	for ip, previousDevice := range before {
		currentDevice, ok := after[ip]
		if !ok {
			copyPrevious := previousDevice
			changes = append(changes, DeviceChange{Kind: ChangeRemoved, IP: ip, Previous: &copyPrevious})
			continue
		}
		if previousDevice.OpenPortsJSON != currentDevice.OpenPortsJSON {
			copyPrevious := previousDevice
			copyCurrent := currentDevice
			changes = append(changes, DeviceChange{Kind: ChangeChanged, IP: ip, Previous: &copyPrevious, Current: &copyCurrent})
		}
	}
	for ip, currentDevice := range after {
		if _, ok := before[ip]; ok {
			continue
		}
		copyCurrent := currentDevice
		changes = append(changes, DeviceChange{Kind: ChangeNew, IP: ip, Current: &copyCurrent})
	}
	sort.Slice(changes, func(i, j int) bool {
		if changes[i].IP == changes[j].IP {
			return changes[i].Kind < changes[j].Kind
		}
		return changes[i].IP < changes[j].IP
	})
	return changes
}

func DiffSubdomains(previous, current []SubdomainSnapshot) []SubdomainChange {
	before := make(map[string]SubdomainSnapshot, len(previous))
	after := make(map[string]SubdomainSnapshot, len(current))
	for _, subdomain := range previous {
		before[subdomain.Subdomain] = subdomain
	}
	for _, subdomain := range current {
		after[subdomain.Subdomain] = subdomain
	}

	changes := make([]SubdomainChange, 0)
	for name, previousSubdomain := range before {
		currentSubdomain, ok := after[name]
		if !ok {
			copyPrevious := previousSubdomain
			changes = append(changes, SubdomainChange{Kind: ChangeRemoved, Subdomain: name, Previous: &copyPrevious})
			continue
		}
		if previousSubdomain.StatusCode != currentSubdomain.StatusCode || previousSubdomain.TechGuess != currentSubdomain.TechGuess || previousSubdomain.IP != currentSubdomain.IP {
			copyPrevious := previousSubdomain
			copyCurrent := currentSubdomain
			changes = append(changes, SubdomainChange{Kind: ChangeChanged, Subdomain: name, Previous: &copyPrevious, Current: &copyCurrent})
		}
	}
	for name, currentSubdomain := range after {
		if _, ok := before[name]; ok {
			continue
		}
		copyCurrent := currentSubdomain
		changes = append(changes, SubdomainChange{Kind: ChangeNew, Subdomain: name, Current: &copyCurrent})
	}
	sort.Slice(changes, func(i, j int) bool {
		if changes[i].Subdomain == changes[j].Subdomain {
			return changes[i].Kind < changes[j].Kind
		}
		return changes[i].Subdomain < changes[j].Subdomain
	})
	return changes
}

func DiffContentFindings(previous, current []ContentFindingSnapshot) []ContentFindingChange {
	before := make(map[string]struct{}, len(previous))
	for _, finding := range previous {
		before[contentFindingKey(finding)] = struct{}{}
	}
	changes := make([]ContentFindingChange, 0)
	seen := make(map[string]struct{}, len(current))
	for _, finding := range current {
		key := contentFindingKey(finding)
		if _, exists := before[key]; exists {
			continue
		}
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		changes = append(changes, ContentFindingChange{Kind: ChangeNew, Current: finding})
	}
	sort.Slice(changes, func(i, j int) bool {
		return contentFindingKey(changes[i].Current) < contentFindingKey(changes[j].Current)
	})
	return changes
}

func DiffJSFindings(previous, current []JSFindingSnapshot) []JSFindingChange {
	before := make(map[string]struct{}, len(previous))
	for _, finding := range previous {
		before[jsFindingKey(finding)] = struct{}{}
	}
	changes := make([]JSFindingChange, 0)
	seen := make(map[string]struct{}, len(current))
	for _, finding := range current {
		key := jsFindingKey(finding)
		if _, exists := before[key]; exists {
			continue
		}
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		changes = append(changes, JSFindingChange{Kind: ChangeNew, Current: finding})
	}
	sort.Slice(changes, func(i, j int) bool {
		return jsFindingKey(changes[i].Current) < jsFindingKey(changes[j].Current)
	})
	return changes
}

func contentFindingKey(finding ContentFindingSnapshot) string {
	return finding.Subdomain + "\x00" + finding.Path
}

func jsFindingKey(finding JSFindingSnapshot) string {
	return finding.Subdomain + "\x00" + finding.SourceFile + "\x00" + finding.FindingType + "\x00" + finding.Value
}

func DiffPortFindings(previous, current []PortFindingSnapshot) []PortFindingChange {
	before := make(map[string]struct{}, len(previous))
	for _, finding := range previous {
		before[portFindingKey(finding)] = struct{}{}
	}
	changes := make([]PortFindingChange, 0)
	seen := make(map[string]struct{}, len(current))
	for _, finding := range current {
		key := portFindingKey(finding)
		if _, exists := before[key]; exists {
			continue
		}
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		changes = append(changes, PortFindingChange{Kind: ChangeNew, Current: finding})
	}
	sort.Slice(changes, func(i, j int) bool { return portFindingKey(changes[i].Current) < portFindingKey(changes[j].Current) })
	return changes
}

func DiffVulnFindings(previous, current []VulnFindingSnapshot) []VulnFindingChange {
	before := make(map[string]struct{}, len(previous))
	for _, finding := range previous {
		before[vulnFindingKey(finding)] = struct{}{}
	}
	changes := make([]VulnFindingChange, 0)
	seen := make(map[string]struct{}, len(current))
	for _, finding := range current {
		key := vulnFindingKey(finding)
		if _, exists := before[key]; exists {
			continue
		}
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		changes = append(changes, VulnFindingChange{Kind: ChangeNew, Current: finding})
	}
	sort.Slice(changes, func(i, j int) bool { return vulnFindingKey(changes[i].Current) < vulnFindingKey(changes[j].Current) })
	return changes
}

func portFindingKey(finding PortFindingSnapshot) string {
	return finding.SubdomainOrIP + "\x00" + strconv.Itoa(finding.Port) + "\x00" + finding.Protocol + "\x00" + finding.Source
}

func vulnFindingKey(finding VulnFindingSnapshot) string {
	return finding.Subdomain + "\x00" + finding.TemplateID + "\x00" + finding.MatchedURL
}
