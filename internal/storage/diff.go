package storage

import "sort"

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
