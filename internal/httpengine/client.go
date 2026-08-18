package httpengine

import "context"

// Client is the minimal policy-aware transport contract used by Wraith
// collectors. Implementations must execute requests through the R3 boundary.
type Client interface {
	Do(context.Context, Request) (Response, error)
}

var _ Client = (*Engine)(nil)
