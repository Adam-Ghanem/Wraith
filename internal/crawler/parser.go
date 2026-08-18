package crawler

import (
	"bytes"
	"net/url"
	"sort"
	"strings"

	"github.com/Adam-Ghanem/Wraith/internal/evidence"
	"golang.org/x/net/html"
)

type Form struct {
	Action     string
	Method     string
	Enctype    string
	Parameters []string
}

type Document struct {
	URLs          []string
	Forms         []Form
	JavaScript    []string
	APIReferences []string
}

func ExtractDocument(rawURL string, body []byte) (Document, error) {
	base, err := evidence.CanonicalizeURL(rawURL)
	if err != nil {
		return Document{}, err
	}
	root, err := html.Parse(bytes.NewReader(body))
	if err != nil {
		return Document{}, err
	}
	baseURL, err := url.Parse(base.String())
	if err != nil {
		return Document{}, err
	}
	urls, scripts, apiReferences := map[string]struct{}{}, map[string]struct{}{}, map[string]struct{}{}
	forms := make([]Form, 0)
	var walk func(*html.Node, *Form)
	walk = func(node *html.Node, form *Form) {
		if node.Type == html.ElementNode {
			attributes := attributesOf(node)
			switch strings.ToLower(node.Data) {
			case "base":
				if resolved, ok := resolveCanonical(baseURL, attributes["href"]); ok {
					if parsed, parseErr := url.Parse(resolved); parseErr == nil {
						baseURL = parsed
					}
				}
			case "a", "link", "img", "iframe", "frame", "video", "audio", "source":
				if resolved, ok := resolveCanonical(baseURL, attributes[map[string]string{"a": "href", "link": "href"}[strings.ToLower(node.Data)]]); ok {
					urls[resolved] = struct{}{}
					if isAPIReference(resolved) {
						apiReferences[resolved] = struct{}{}
					}
				}
				if src := attributes["src"]; src != "" && node.Data != "a" && node.Data != "link" {
					if resolved, ok := resolveCanonical(baseURL, src); ok {
						urls[resolved] = struct{}{}
						if isAPIReference(resolved) {
							apiReferences[resolved] = struct{}{}
						}
					}
				}
			case "object":
				if resolved, ok := resolveCanonical(baseURL, attributes["data"]); ok {
					urls[resolved] = struct{}{}
				}
			case "script":
				if resolved, ok := resolveCanonical(baseURL, attributes["src"]); ok {
					urls[resolved] = struct{}{}
					scripts[resolved] = struct{}{}
					if isAPIReference(resolved) {
						apiReferences[resolved] = struct{}{}
					}
				}
			case "meta":
				if strings.EqualFold(attributes["http-equiv"], "refresh") {
					if target := refreshTarget(attributes["content"]); target != "" {
						if resolved, ok := resolveCanonical(baseURL, target); ok {
							urls[resolved] = struct{}{}
						}
					}
				}
			case "form":
				action := baseURL.String()
				if resolved, ok := resolveCanonical(baseURL, attributes["action"]); ok {
					action = resolved
				}
				method := strings.ToUpper(strings.TrimSpace(attributes["method"]))
				if method == "" {
					method = "GET"
				}
				forms = append(forms, Form{Action: action, Method: method, Enctype: attributes["enctype"]})
				form = &forms[len(forms)-1]
			case "input", "textarea", "select":
				if form != nil && strings.TrimSpace(attributes["name"]) != "" {
					form.Parameters = append(form.Parameters, strings.TrimSpace(attributes["name"]))
				}
			}
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			walk(child, form)
		}
	}
	walk(root, nil)
	for index := range forms {
		forms[index].Parameters = uniqueSorted(forms[index].Parameters)
	}
	return Document{URLs: sortedSet(urls), Forms: forms, JavaScript: sortedSet(scripts), APIReferences: sortedSet(apiReferences)}, nil
}

func attributesOf(node *html.Node) map[string]string {
	result := make(map[string]string, len(node.Attr))
	for _, attribute := range node.Attr {
		result[strings.ToLower(attribute.Key)] = attribute.Val
	}
	return result
}
func resolveCanonical(base *url.URL, raw string) (string, bool) {
	if strings.TrimSpace(raw) == "" {
		return "", false
	}
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", false
	}
	next, err := evidence.CanonicalizeURL(base.ResolveReference(parsed).String())
	if err != nil {
		return "", false
	}
	return next.String(), true
}
func sortedSet(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
func uniqueSorted(values []string) []string {
	set := map[string]struct{}{}
	for _, value := range values {
		set[value] = struct{}{}
	}
	return sortedSet(set)
}
func isAPIReference(raw string) bool {
	lower := strings.ToLower(raw)
	return strings.Contains(lower, "/api/") || strings.Contains(lower, "graphql") || strings.Contains(lower, "swagger") || strings.Contains(lower, "openapi")
}
func refreshTarget(content string) string {
	parts := strings.SplitN(content, ";", 2)
	if len(parts) != 2 {
		return ""
	}
	return strings.Trim(strings.TrimSpace(strings.TrimPrefix(strings.ToLower(parts[1]), "url=")), "\"'")
}
