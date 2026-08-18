// R7 creates bounded request plans only. It has no network, DNS, socket, or HTTP-client behavior.
package fuzzing

import "time"

type Location string

const (
	LocationQuery  Location = "query"
	LocationPath   Location = "path"
	LocationJSON   Location = "json"
	LocationForm   Location = "form"
	LocationHeader Location = "header"
)

type Profile string

const (
	ProfileMinimal  Profile = "minimal"
	ProfileBoundary Profile = "boundary"
	ProfileEncoding Profile = "encoding"
	ProfileType     Profile = "type"
	ProfileCombined Profile = "combined"
)

type SafetyClass string

const SafetyGeneric SafetyClass = "generic"

type Mutation struct {
	ID                    string            `json:"id"`
	Category              string            `json:"category"`
	Input                 string            `json:"input"`
	Value                 any               `json:"-"`
	SafetyClass           SafetyClass       `json:"safety_class"`
	DeterministicMetadata map[string]string `json:"deterministic_metadata"`
}

type MutationInput struct {
	Parameter string
	Location  Location
}

type MutationContext struct{ Limits Limits }

// MutationProvider remains internal to R7; external payload plugins are intentionally unsupported.
type MutationProvider interface {
	Generate(MutationInput, MutationContext) ([]Mutation, error)
}

type RequestTemplate struct {
	Method      string              `json:"method"`
	URL         string              `json:"url"`
	Headers     map[string][]string `json:"headers,omitempty"`
	Body        []byte              `json:"-"`
	ContentType string              `json:"content_type,omitempty"`
}

type FuzzTarget struct {
	EndpointIdentity string   `json:"endpoint_identity"`
	ParameterName    string   `json:"parameter_name"`
	Location         Location `json:"location"`
}

type PlanInput struct {
	ProjectID, ProfileID              string
	Target                            FuzzTarget
	Template                          RequestTemplate
	Profile                           Profile
	Limits                            Limits
	AllowUnsafeMethods, ConfirmUnsafe bool
}

type PlannedRequest struct {
	Mutation Mutation        `json:"mutation"`
	Template RequestTemplate `json:"template"`
}

type FuzzPlan struct {
	ID        string           `json:"id"`
	ProjectID string           `json:"project_id"`
	Target    FuzzTarget       `json:"target"`
	Profile   Profile          `json:"profile"`
	Requests  []PlannedRequest `json:"requests"`
	Estimated int              `json:"estimated_requests"`
}

type Limits struct {
	MaxMutations, MaxRequests, MaxMutationBytes, MaxBodyBytes, MaxJSONDepth int
	MaxDuration                                                             time.Duration
}

func DefaultLimits() Limits {
	return Limits{MaxMutations: 32, MaxRequests: 32, MaxMutationBytes: 512, MaxBodyBytes: 32 << 10, MaxJSONDepth: 4, MaxDuration: 30 * time.Second}
}

func (limits Limits) valid() bool {
	return limits.MaxMutations > 0 && limits.MaxMutations <= 64 && limits.MaxRequests > 0 && limits.MaxRequests <= 64 && limits.MaxMutationBytes > 0 && limits.MaxMutationBytes <= 1024 && limits.MaxBodyBytes > 0 && limits.MaxBodyBytes <= 64<<10 && limits.MaxJSONDepth > 0 && limits.MaxJSONDepth <= 8 && limits.MaxDuration > 0 && limits.MaxDuration <= 2*time.Minute
}
