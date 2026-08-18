// R6 persistence writes only local, static metadata through the existing R2 repository; it never fetches a reference.
package jsanalysis

import (
	"context"
	"errors"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/evidence"
)

// PersistStaticEvidence correlates static request references with canonical R2 endpoints and appends value-free client-side evidence to the source asset.
func PersistStaticEvidence(ctx context.Context, repository evidence.Repository, projectID string, asset evidence.WebAsset, report StaticReport, observedAt time.Time) error {
	if repository == nil || strings.TrimSpace(projectID) == "" || asset.ProjectID != projectID || asset.Kind != evidence.AssetKindJavaScript || observedAt.IsZero() {
		return errors.New("invalid static evidence persistence input")
	}
	if !report.Parsed || report.SourceID != asset.Identity {
		return errors.New("static report does not match source asset")
	}
	for _, request := range report.Requests {
		endpoint, err := staticEndpoint(projectID, asset.CanonicalURL, request.Method, request.URL, observedAt)
		if err != nil {
			continue
		}
		if _, err := repository.UpsertEndpoint(ctx, endpoint); err != nil {
			return err
		}
		if err := appendClientEvidence(ctx, repository, projectID, asset, "jsanalysis.url", "url", endpoint.URL, request.Confidence, observedAt); err != nil {
			return err
		}
		if err := appendClientEvidence(ctx, repository, projectID, asset, "jsanalysis.api", "http_request", endpoint.Method+" "+endpoint.URL, request.Confidence, observedAt); err != nil {
			return err
		}
	}
	for _, parameter := range report.Parameters {
		kind := "parameter:" + parameter.Location
		if parameter.SensitiveReference {
			kind = "sensitive_parameter_reference:" + parameter.Location
		}
		if parameter.Endpoint == "" {
			if err := appendClientEvidence(ctx, repository, projectID, asset, "jsanalysis.parameter", kind, parameter.Name, parameter.Confidence, observedAt); err != nil {
				return err
			}
			continue
		}
		endpoint, err := staticEndpoint(projectID, asset.CanonicalURL, requestMethodFor(report, parameter.Endpoint), parameter.Endpoint, observedAt)
		if err != nil {
			continue
		}
		location := evidence.ParameterLocation(parameter.Location)
		if location != evidence.ParameterLocationQuery && location != evidence.ParameterLocationJSON && location != evidence.ParameterLocationBody && location != evidence.ParameterLocationHeader && location != evidence.ParameterLocationPath {
			continue
		}
		record, err := evidence.NewParameter(projectID, endpoint, location, parameter.Name, observedAt)
		if err != nil {
			continue
		}
		if _, err := repository.UpsertParameter(ctx, record); err != nil {
			return err
		}
		if err := appendClientEvidence(ctx, repository, projectID, asset, "jsanalysis.parameter", kind, endpoint.URL+"|"+parameter.Name, parameter.Confidence, observedAt); err != nil {
			return err
		}
	}
	for _, reference := range report.WebSockets {
		if err := appendClientEvidence(ctx, repository, projectID, asset, "jsanalysis.websocket", reference.Kind, reference.Value, reference.Confidence, observedAt); err != nil {
			return err
		}
	}
	for _, reference := range report.Routes {
		if err := appendClientEvidence(ctx, repository, projectID, asset, "jsanalysis.route", reference.Kind, reference.Value, reference.Confidence, observedAt); err != nil {
			return err
		}
	}
	for _, reference := range report.SourceMaps {
		if err := appendClientEvidence(ctx, repository, projectID, asset, "jsanalysis.sourcemap", reference.Kind, reference.Value, reference.Confidence, observedAt); err != nil {
			return err
		}
	}
	for _, reference := range report.GraphQL {
		if err := appendClientEvidence(ctx, repository, projectID, asset, "jsanalysis.graphql", "operation", reference.Operation, reference.Confidence, observedAt); err != nil {
			return err
		}
	}
	for _, flow := range report.ClientFlows {
		if err := appendClientEvidence(ctx, repository, projectID, asset, "jsanalysis."+strings.TrimPrefix(flow.Kind, "client_side_"), flow.Kind, flow.Type, flow.Confidence, observedAt); err != nil {
			return err
		}
	}
	for _, technology := range report.Technologies {
		if err := appendClientEvidence(ctx, repository, projectID, asset, "jsanalysis.technology", "technology:"+technology.Name, technology.Evidence, technology.Confidence, observedAt); err != nil {
			return err
		}
	}
	return nil
}

// PersistLocalSourceMapEvidence stores only source-map structural metadata, never source paths, source content, or mappings.
func PersistLocalSourceMapEvidence(ctx context.Context, repository evidence.Repository, projectID string, asset evidence.WebAsset, summary SourceMapSummary, observedAt time.Time) error {
	if summary.Version <= 0 || summary.MappingsSize < 0 {
		return errors.New("invalid local source map summary")
	}
	reference := "version=" + strconv.Itoa(summary.Version) + ";sources=" + strconv.Itoa(len(summary.Sources)) + ";mappings_bytes=" + strconv.Itoa(summary.MappingsSize)
	return appendClientEvidence(ctx, repository, projectID, asset, "jsanalysis.sourcemap", "local_source_map", reference, "high", observedAt)
}

func staticEndpoint(projectID, sourceURL, method, reference string, observedAt time.Time) (evidence.Endpoint, error) {
	if strings.Contains(reference, "{parameter}") {
		return evidence.Endpoint{}, errors.New("dynamic template cannot form a canonical endpoint")
	}
	base, err := url.Parse(sourceURL)
	if err != nil {
		return evidence.Endpoint{}, err
	}
	candidate, err := url.Parse(reference)
	if err != nil || candidate.User != nil {
		return evidence.Endpoint{}, errors.New("invalid static endpoint reference")
	}
	resolved := base.ResolveReference(candidate)
	if resolved.Scheme != "http" && resolved.Scheme != "https" {
		return evidence.Endpoint{}, errors.New("static endpoint uses unsupported scheme")
	}
	return evidence.NewEndpoint(projectID, method, resolved.String(), observedAt)
}

func requestMethodFor(report StaticReport, endpoint string) string {
	for _, request := range report.Requests {
		if request.URL == endpoint {
			return request.Method
		}
	}
	return "GET"
}

func appendClientEvidence(ctx context.Context, repository evidence.Repository, projectID string, asset evidence.WebAsset, source, kind, reference, confidence string, observedAt time.Time) error {
	observation, err := evidence.NewClientSideEvidence(projectID, asset, evidence.ClientSideEvidenceInput{Source: source, Type: kind, Reference: reference, Confidence: confidence, ObservedAt: observedAt})
	if err != nil {
		return err
	}
	return repository.AppendObservation(ctx, observation.Record())
}
