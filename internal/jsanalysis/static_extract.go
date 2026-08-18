// R6 extractor rules inspect parser-validated source text only; they do not evaluate expressions.
package jsanalysis

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var (
	staticString    = `(?s)(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|` + "`" + `(?:\\.|[^` + "`" + `\\])*` + "`" + `)`
	fetchCall       = regexp.MustCompile(`(?s)\bfetch\s*\(\s*(` + staticString + `)(?:\s*\+\s*([A-Za-z_$][A-Za-z0-9_$]*))?(?:\s*,\s*\{([^}]*)\})?`)
	axiosMethodCall = regexp.MustCompile(`(?is)\baxios\.(get|post|put|patch|delete|head|options)\s*\(\s*(` + staticString + `)`)
	axiosConfigCall = regexp.MustCompile(`(?is)\baxios\s*\(\s*\{([^}]*)\}`)
	xhrOpenCall     = regexp.MustCompile(`(?is)\.open\s*\(\s*(` + staticString + `)\s*,\s*(` + staticString + `)`)
	methodOption    = regexp.MustCompile(`(?is)\bmethod\s*:\s*(` + staticString + `)`)
	urlOption       = regexp.MustCompile(`(?is)\burl\s*:\s*(` + staticString + `)`)
	jsonBody        = regexp.MustCompile(`(?is)JSON\.stringify\s*\(\s*\{([^{}]{0,1000})`)
	objectKey       = regexp.MustCompile(`(?m)(?:^|,)\s*["']?([A-Za-z_$][A-Za-z0-9_$-]{0,255})["']?\s*:`)
	urlSearchParams = regexp.MustCompile(`(?is)\bnew\s+URLSearchParams\s*\(\s*\{([^{}]{0,1000})`)
	formDataAppend  = regexp.MustCompile(`(?is)\.append\s*\(\s*(` + staticString + `)`)
	webSocketCall   = regexp.MustCompile(`(?is)\bnew\s+WebSocket\s*\(\s*(` + staticString + `)`)
	graphqlOp       = regexp.MustCompile(`(?is)\b(?:query|mutation)\s+([A-Za-z_][A-Za-z0-9_]*)`)
	routePath       = regexp.MustCompile(`(?is)\bpath\s*:\s*(` + staticString + `)`)
	sourceMap       = regexp.MustCompile(`(?im)^\s*//[@#]\s*sourceMappingURL\s*=\s*([^\s]+)\s*$`)
	clientSource    = regexp.MustCompile(`\b(location(?:\.search|\.hash|\.href)?|document\.cookie|postMessage|URLSearchParams)\b`)
	clientSink      = regexp.MustCompile(`\b(innerHTML|outerHTML|document\.write|eval|Function|setTimeout\s*\(\s*["'])`)
	reactSignal     = regexp.MustCompile(`(?is)(?:\bfrom\s*["']react["']|\bReact\.createElement\s*\(|\bjsx\s*\()`)
	axiosSignal     = regexp.MustCompile(`(?is)\baxios(?:\.(?:get|post|put|patch|delete|head|options|request))?\s*\(`)
	vueSignal       = regexp.MustCompile(`(?is)(?:\bfrom\s*["']vue["']|\bcreateApp\s*\()`)
	angularSignal   = regexp.MustCompile(`(?is)(?:["']@angular/|\bRouterModule\.)`)
	nextSignal      = regexp.MustCompile(`(?is)\bfrom\s*["']next(?:/router)?["']`)
	nuxtSignal      = regexp.MustCompile(`(?is)(?:\bdefineNuxtConfig\s*\(|\buseFetch\s*\()`)
	webpackSignal   = regexp.MustCompile(`(?is)(?:\b__webpack_require__\s*\(|\bwebpackJsonp\.)`)
	viteSignal      = regexp.MustCompile(`(?is)(?:\bimport\.meta\.env\b|\bVITE_[A-Z0-9_]+\b)`)
	jquerySignal    = regexp.MustCompile(`(?is)(?:\$\.(?:ajax|get|post)\s*\(|\bjQuery\s*\()`)
	dynamicTemplate = regexp.MustCompile(`\$\{[^}]{0,256}\}`)
)

type staticState struct {
	limits  StaticLimits
	report  *StaticReport
	seen    map[string]struct{}
	limited bool
}

func newStaticState(limits StaticLimits, report *StaticReport) *staticState {
	return &staticState{limits: limits, report: report, seen: make(map[string]struct{})}
}

func (state *staticState) add(key string) bool {
	if len(state.seen) >= state.limits.MaxReferences {
		state.limited = true
		return false
	}
	if _, exists := state.seen[key]; exists {
		return false
	}
	state.seen[key] = struct{}{}
	return true
}

func (state *staticState) extractAll(text string) {
	state.extractRequests(text)
	state.extractWebSockets(text)
	state.extractGraphQL(text)
	state.extractRoutes(text)
	state.extractSourceMaps(text)
	state.extractLocalParameters(text)
	state.extractTechnologies(text)
	state.extractClientFlows(text)
}

func (state *staticState) extractRequests(text string) {
	for _, match := range fetchCall.FindAllStringSubmatch(text, -1) {
		url, dynamic, ok := staticLiteral(match[1])
		if len(match) > 2 && match[2] != "" {
			url = strings.TrimRight(url, "/") + "/{parameter}"
			dynamic = true
		}
		url = minimizeQueryReference(url)
		if !ok || !looksLikeReference(url) {
			continue
		}
		method := "GET"
		if len(match) > 3 {
			if option := methodOption.FindStringSubmatch(match[3]); len(option) == 2 {
				if value, _, valid := staticLiteral(option[1]); valid && isHTTPMethod(strings.ToUpper(value)) {
					method = strings.ToUpper(value)
				}
			}
		}
		confidence := "high"
		if dynamic {
			confidence = "medium"
		}
		state.addRequest(StaticRequest{Client: "fetch", Method: method, URL: url, Confidence: confidence, Evidence: "fetch"})
		state.addURL(url, confidence, "fetch")
		state.addQueryParameters(url, confidence)
		if len(match) > 3 {
			state.addJSONParameters(url, match[3], confidence)
		}
	}
	for _, match := range axiosMethodCall.FindAllStringSubmatch(text, -1) {
		url, dynamic, ok := staticLiteral(match[2])
		url = minimizeQueryReference(url)
		if !ok || !looksLikeReference(url) {
			continue
		}
		confidence := "high"
		if dynamic {
			confidence = "medium"
		}
		state.addRequest(StaticRequest{Client: "axios", Method: strings.ToUpper(match[1]), URL: url, Confidence: confidence, Evidence: "axios." + strings.ToLower(match[1])})
		state.addURL(url, confidence, "axios")
		state.addQueryParameters(url, confidence)
	}
	for _, match := range axiosConfigCall.FindAllStringSubmatch(text, -1) {
		methodMatch, urlMatch := methodOption.FindStringSubmatch(match[1]), urlOption.FindStringSubmatch(match[1])
		if len(methodMatch) != 2 || len(urlMatch) != 2 {
			continue
		}
		method, _, methodOK := staticLiteral(methodMatch[1])
		url, dynamic, urlOK := staticLiteral(urlMatch[1])
		url = minimizeQueryReference(url)
		if !methodOK || !urlOK || !isHTTPMethod(strings.ToUpper(method)) || !looksLikeReference(url) {
			continue
		}
		confidence := "high"
		if dynamic {
			confidence = "medium"
		}
		state.addRequest(StaticRequest{Client: "axios", Method: strings.ToUpper(method), URL: url, Confidence: confidence, Evidence: "axios configuration"})
		state.addURL(url, confidence, "axios")
		state.addQueryParameters(url, confidence)
		state.addJSONParameters(url, match[1], confidence)
	}
	for _, match := range xhrOpenCall.FindAllStringSubmatch(text, -1) {
		method, _, methodOK := staticLiteral(match[1])
		url, dynamic, urlOK := staticLiteral(match[2])
		url = minimizeQueryReference(url)
		if !methodOK || !urlOK || !isHTTPMethod(strings.ToUpper(method)) || !looksLikeReference(url) {
			continue
		}
		confidence := "high"
		if dynamic {
			confidence = "medium"
		}
		state.addRequest(StaticRequest{Client: "XMLHttpRequest", Method: strings.ToUpper(method), URL: url, Confidence: confidence, Evidence: "XMLHttpRequest.open"})
		state.addURL(url, confidence, "XMLHttpRequest")
		state.addQueryParameters(url, confidence)
	}
}

func (state *staticState) addRequest(request StaticRequest) {
	if state.add("request\x00" + request.Client + "\x00" + request.Method + "\x00" + request.URL) {
		state.report.Requests = append(state.report.Requests, request)
	}
}

func (state *staticState) addURL(value, confidence, evidence string) {
	if state.add("url\x00" + value) {
		state.report.URLs = append(state.report.URLs, StaticReference{Kind: "url", Value: value, Confidence: confidence, Evidence: evidence})
	}
}

func (state *staticState) addQueryParameters(endpoint, confidence string) {
	queryIndex := strings.IndexByte(endpoint, '?')
	if queryIndex < 0 {
		return
	}
	for _, part := range strings.Split(endpoint[queryIndex+1:], "&") {
		state.addParameter(endpoint, "query", strings.TrimSpace(strings.SplitN(part, "=", 2)[0]), confidence)
	}
}

func (state *staticState) addJSONParameters(endpoint, text, confidence string) {
	for _, object := range jsonBody.FindAllStringSubmatch(text, -1) {
		for _, key := range objectKey.FindAllStringSubmatch(object[1], -1) {
			state.addParameter(endpoint, "json", key[1], confidence)
		}
	}
}

func (state *staticState) addParameter(endpoint, location, name, confidence string) {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 256 || !state.add("parameter\x00"+endpoint+"\x00"+location+"\x00"+name) {
		return
	}
	state.report.Parameters = append(state.report.Parameters, StaticParameter{Endpoint: endpoint, Location: location, Name: name, Confidence: confidence, SensitiveReference: sensitiveName(name)})
}

func (state *staticState) extractWebSockets(text string) {
	for _, match := range webSocketCall.FindAllStringSubmatch(text, -1) {
		value, dynamic, ok := staticLiteral(match[1])
		if !ok || !(strings.HasPrefix(value, "ws://") || strings.HasPrefix(value, "wss://")) || !state.add("websocket\x00"+value) {
			continue
		}
		confidence := "high"
		if dynamic {
			confidence = "medium"
		}
		state.report.WebSockets = append(state.report.WebSockets, StaticReference{Kind: "websocket", Value: value, Confidence: confidence, Evidence: "new WebSocket"})
	}
}

func (state *staticState) extractGraphQL(text string) {
	for _, match := range graphqlOp.FindAllStringSubmatch(text, -1) {
		if state.add("graphql\x00" + match[1]) {
			state.report.GraphQL = append(state.report.GraphQL, GraphQLReference{Operation: match[1], Confidence: "high"})
		}
	}
}

func (state *staticState) extractRoutes(text string) {
	for _, match := range routePath.FindAllStringSubmatch(text, -1) {
		value, dynamic, ok := staticLiteral(match[1])
		if !ok || !strings.HasPrefix(value, "/") || !state.add("route\x00"+value) {
			continue
		}
		confidence := "high"
		if dynamic {
			confidence = "medium"
		}
		state.report.Routes = append(state.report.Routes, StaticReference{Kind: "route", Value: value, Confidence: confidence, Evidence: "route path"})
	}
}

func (state *staticState) extractSourceMaps(text string) {
	for _, match := range sourceMap.FindAllStringSubmatch(text, -1) {
		value := strings.TrimSpace(match[1])
		if value != "" && state.add("sourcemap\x00"+value) {
			state.report.SourceMaps = append(state.report.SourceMaps, StaticReference{Kind: "source_map", Value: value, Confidence: "high", Evidence: "sourceMappingURL"})
		}
	}
}

func (state *staticState) extractLocalParameters(text string) {
	for _, object := range urlSearchParams.FindAllStringSubmatch(text, -1) {
		for _, key := range objectKey.FindAllStringSubmatch(object[1], -1) {
			state.addParameter("", "query", key[1], "medium")
		}
	}
	for _, match := range formDataAppend.FindAllStringSubmatch(text, -1) {
		if name, _, ok := staticLiteral(match[1]); ok {
			state.addParameter("", "body", name, "medium")
		}
	}
}

func (state *staticState) extractTechnologies(text string) {
	if len(reactSignal.FindAllString(text, -1)) >= 2 {
		state.addTechnology("React", "high", "module and runtime API")
	}
	if axiosSignal.MatchString(text) {
		state.addTechnology("Axios", "high", "Axios call expression")
	}
	if len(vueSignal.FindAllString(text, -1)) >= 2 {
		state.addTechnology("Vue", "high", "module and createApp API")
	}
	if len(angularSignal.FindAllString(text, -1)) >= 2 {
		state.addTechnology("Angular", "high", "module and RouterModule API")
	}
	if len(nextSignal.FindAllString(text, -1)) >= 2 {
		state.addTechnology("Next.js", "high", "Next module and router imports")
	}
	if len(nuxtSignal.FindAllString(text, -1)) >= 2 {
		state.addTechnology("Nuxt", "high", "Nuxt configuration and fetch APIs")
	}
	if len(webpackSignal.FindAllString(text, -1)) >= 2 {
		state.addTechnology("Webpack", "high", "bundle loader and chunk registry")
	}
	if len(viteSignal.FindAllString(text, -1)) >= 2 {
		state.addTechnology("Vite", "high", "import-meta environment and VITE variable")
	}
	if jquerySignal.MatchString(text) {
		state.addTechnology("JQuery", "high", "jQuery request API")
	}
}

func (state *staticState) addTechnology(name, confidence, evidence string) {
	if state.add("technology\x00" + name) {
		state.report.Technologies = append(state.report.Technologies, TechnologySignal{Name: name, Confidence: confidence, Evidence: evidence})
	}
}

func (state *staticState) extractClientFlows(text string) {
	for _, match := range clientSink.FindAllStringSubmatch(text, -1) {
		state.addClientFlow("client_side_sink", strings.TrimSpace(match[1]))
	}
	for _, match := range clientSource.FindAllStringSubmatch(text, -1) {
		state.addClientFlow("client_side_source", strings.TrimSpace(match[1]))
	}
}

func (state *staticState) addClientFlow(kind, value string) {
	if value != "" && state.add("flow\x00"+kind+"\x00"+value) {
		state.report.ClientFlows = append(state.report.ClientFlows, ClientFlow{Kind: kind, Type: value, Confidence: "high"})
	}
}

func (state *staticState) sort() {
	sort.Slice(state.report.URLs, func(i, j int) bool { return state.report.URLs[i].Value < state.report.URLs[j].Value })
	sort.Slice(state.report.Requests, func(i, j int) bool {
		if state.report.Requests[i].URL == state.report.Requests[j].URL {
			return state.report.Requests[i].Method < state.report.Requests[j].Method
		}
		return state.report.Requests[i].URL < state.report.Requests[j].URL
	})
	sort.Slice(state.report.Parameters, func(i, j int) bool {
		if state.report.Parameters[i].Endpoint != state.report.Parameters[j].Endpoint {
			return state.report.Parameters[i].Endpoint < state.report.Parameters[j].Endpoint
		}
		if parameterLocationRank(state.report.Parameters[i].Location) != parameterLocationRank(state.report.Parameters[j].Location) {
			return parameterLocationRank(state.report.Parameters[i].Location) < parameterLocationRank(state.report.Parameters[j].Location)
		}
		return state.report.Parameters[i].Name < state.report.Parameters[j].Name
	})
	sort.Slice(state.report.WebSockets, func(i, j int) bool { return state.report.WebSockets[i].Value < state.report.WebSockets[j].Value })
	sort.Slice(state.report.GraphQL, func(i, j int) bool { return state.report.GraphQL[i].Operation < state.report.GraphQL[j].Operation })
	sort.Slice(state.report.Routes, func(i, j int) bool { return state.report.Routes[i].Value < state.report.Routes[j].Value })
	sort.Slice(state.report.SourceMaps, func(i, j int) bool { return state.report.SourceMaps[i].Value < state.report.SourceMaps[j].Value })
	sort.Slice(state.report.Technologies, func(i, j int) bool { return state.report.Technologies[i].Name < state.report.Technologies[j].Name })
	sort.Slice(state.report.ClientFlows, func(i, j int) bool {
		if state.report.ClientFlows[i].Kind == state.report.ClientFlows[j].Kind {
			return state.report.ClientFlows[i].Type < state.report.ClientFlows[j].Type
		}
		return state.report.ClientFlows[i].Kind < state.report.ClientFlows[j].Kind
	})
}

func staticLiteral(raw string) (string, bool, bool) {
	raw = strings.TrimSpace(raw)
	if len(raw) < 2 {
		return "", false, false
	}
	if raw[0] == '`' && raw[len(raw)-1] == '`' {
		value := dynamicTemplate.ReplaceAllString(raw[1:len(raw)-1], "{parameter}")
		return value, strings.Contains(value, "{parameter}"), true
	}
	value, err := strconv.Unquote(raw)
	if err != nil {
		return "", false, false
	}
	return value, false, true
}

func minimizeQueryReference(value string) string {
	queryIndex := strings.IndexByte(value, '?')
	if queryIndex < 0 {
		return value
	}
	prefix := value[:queryIndex]
	seen, names := make(map[string]struct{}), make([]string, 0)
	for _, part := range strings.Split(value[queryIndex+1:], "&") {
		name := strings.TrimSpace(strings.SplitN(part, "=", 2)[0])
		if name != "" {
			if _, exists := seen[name]; !exists {
				seen[name] = struct{}{}
				names = append(names, name)
			}
		}
	}
	if len(names) == 0 {
		return prefix
	}
	sort.Strings(names)
	return prefix + "?" + strings.Join(names, "&")
}

func looksLikeReference(value string) bool {
	return strings.HasPrefix(value, "/") || strings.HasPrefix(value, "./") || strings.HasPrefix(value, "../") || strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "https://") || strings.HasPrefix(value, "ws://") || strings.HasPrefix(value, "wss://")
}
func isHTTPMethod(method string) bool {
	switch method {
	case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS":
		return true
	default:
		return false
	}
}
func sensitiveName(name string) bool {
	switch strings.ToLower(strings.ReplaceAll(name, "-", "_")) {
	case "password", "token", "secret", "api_key", "apikey", "authorization", "session", "csrf", "jwt":
		return true
	default:
		return false
	}
}
func parameterLocationRank(location string) int {
	switch location {
	case "query":
		return 0
	case "json":
		return 1
	case "body":
		return 2
	default:
		return 3
	}
}
