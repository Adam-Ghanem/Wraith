package fuzzing

import (
	"errors"
	"strings"
)

var errInvalidMutation = errors.New("invalid fuzz mutation input")

type mutationValue struct {
	id, category string
	value        any
}

type minimalProvider struct{}

func (minimalProvider) Generate(input MutationInput, context MutationContext) ([]Mutation, error) {
	return generateFixed(ProfileMinimal, []mutationValue{{"empty", "empty", ""}, {"one-char", "boundary", "a"}, {"zero", "numeric", "0"}}, input, context)
}

type fixedProvider struct {
	profile Profile
	values  []mutationValue
}

func (provider fixedProvider) Generate(input MutationInput, context MutationContext) ([]Mutation, error) {
	return generateFixed(provider.profile, provider.values, input, context)
}

func generateFixed(profile Profile, values []mutationValue, input MutationInput, context MutationContext) ([]Mutation, error) {
	if input.Parameter == "" || !context.Limits.valid() {
		return nil, errInvalidMutation
	}
	result := make([]Mutation, 0, len(values))
	for _, value := range values {
		result = append(result, Mutation{ID: string(profile) + "/" + value.id, Category: value.category, Input: input.Parameter, Value: value.value, SafetyClass: SafetyGeneric, DeterministicMetadata: map[string]string{"profile": string(profile), "location": string(input.Location)}})
	}
	return result, nil
}

var boundaryValues = []mutationValue{{"empty", "empty", ""}, {"one-char", "boundary", "a"}, {"small-integer", "numeric", "1"}, {"zero", "numeric", "0"}, {"negative-integer", "numeric", "-1"}, {"large-integer", "numeric", "2147483647"}, {"bounded-large-integer", "numeric", "999999999999"}, {"short-string", "length", "short"}, {"medium-string", "length", strings.Repeat("m", 16)}, {"bounded-max-string", "length", strings.Repeat("x", 64)}}
var encodingValues = []mutationValue{{"url-space", "encoding", "%20"}, {"double-url-space", "encoding", "%2520"}, {"reserved-slash", "special-character", "/"}, {"unicode-letter", "unicode", "é"}, {"whitespace", "encoding", " a "}}
var typeValues = []mutationValue{{"string", "type-confusion", "value"}, {"integer", "type-confusion", 1}, {"boolean", "boolean", true}, {"null", "type-confusion", nil}, {"empty-array", "structured", []any{}}, {"single-item-array", "structured", []any{"a"}}}

func providersFor(profile Profile) ([]MutationProvider, error) {
	switch profile {
	case ProfileMinimal:
		return []MutationProvider{minimalProvider{}}, nil
	case ProfileBoundary:
		return []MutationProvider{fixedProvider{profile: ProfileBoundary, values: boundaryValues}}, nil
	case ProfileEncoding:
		return []MutationProvider{fixedProvider{profile: ProfileEncoding, values: encodingValues}}, nil
	case ProfileType:
		return []MutationProvider{fixedProvider{profile: ProfileType, values: typeValues}}, nil
	case ProfileCombined:
		return []MutationProvider{minimalProvider{}, fixedProvider{profile: ProfileBoundary, values: boundaryValues}, fixedProvider{profile: ProfileEncoding, values: encodingValues}, fixedProvider{profile: ProfileType, values: typeValues}}, nil
	default:
		return nil, errInvalidMutation
	}
}
