package correlation

type FindingInput struct {
	ProjectID, FindingID, EndpointID string
	EvidenceReferences               []string
}

type Inventory struct {
	ProjectID               string
	Endpoints, Observations map[string]struct{}
}

type FindingResult struct {
	EndpointID         string
	EvidenceReferences []string
	Uncorrelated       bool
}

func CorrelateFinding(finding FindingInput, inventory Inventory) FindingResult {
	if finding.ProjectID == "" || finding.FindingID == "" || finding.ProjectID != inventory.ProjectID {
		return FindingResult{Uncorrelated: true}
	}
	result := FindingResult{}
	if _, exists := inventory.Endpoints[finding.EndpointID]; exists && finding.EndpointID != "" {
		result.EndpointID = finding.EndpointID
	} else if finding.EndpointID != "" {
		result.Uncorrelated = true
	}
	for _, reference := range finding.EvidenceReferences {
		if _, exists := inventory.Observations[reference]; exists && reference != "" {
			result.EvidenceReferences = append(result.EvidenceReferences, reference)
		} else {
			result.Uncorrelated = true
		}
	}
	return result
}
