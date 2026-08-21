package httpengine

import "context"

// Client is the minimal policy-aware HTTP transport contract used by Wraith
// collectors. Implementations must execute requests through the R3 boundary.
type Client interface {
	Do(context.Context, Request) (Response, error)
}

// TCPClient is the minimal policy-aware TCP reachability contract used by
// active assessment adapters. Implementations own the socket lifecycle and
// must execute connectivity through the R3 transport boundary.
type TCPClient interface {
	ProbeTCP(context.Context, TCPRequest) (TCPResponse, error)
}

var _ Client = (*Engine)(nil)
var _ TCPClient = (*Engine)(nil)
