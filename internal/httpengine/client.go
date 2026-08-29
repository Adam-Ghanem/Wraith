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

// TCPBannerClient extends the R3 TCP boundary with a bounded application-layer
// probe used by native service/version fingerprinting. Callers never receive a
// socket and may only exchange a small, explicitly bounded payload/banner.
type TCPBannerClient interface {
	ProbeTCPBanner(context.Context, TCPBannerRequest) (TCPBannerResponse, error)
}

// UDPClient is the bounded UDP probe contract owned by the R3 transport.
// Callers supply one datagram and receive at most the configured response cap.
type UDPClient interface {
	ProbeUDP(context.Context, UDPRequest) (UDPResponse, error)
}

// SYNClient owns privileged raw TCP SYN scanning. The batch contract keeps one
// raw socket per target and returns only classified observations/fingerprint
// metadata; callers never receive packet sockets or raw packets.
type SYNClient interface {
	ScanSYN(context.Context, SYNScanRequest) ([]SYNResponse, error)
}

var _ Client = (*Engine)(nil)
var _ TCPClient = (*Engine)(nil)
var _ TCPBannerClient = (*Engine)(nil)
var _ UDPClient = (*Engine)(nil)
var _ SYNClient = (*Engine)(nil)
