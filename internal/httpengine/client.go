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

// SYNClient owns privileged raw IPv4 TCP SYN scanning. The batch contract
// keeps one raw socket per target and returns only classified observations and
// fingerprint metadata; callers never receive packet sockets or raw packets.
type SYNClient interface {
	ScanSYN(context.Context, SYNScanRequest) ([]SYNResponse, error)
}

// SYN6Client is the IPv6 counterpart to SYNClient. It is deliberately a
// separate optional interface so existing IPv4-only adapters remain valid.
type SYN6Client interface {
	ScanSYN6(context.Context, SYNScanRequest) ([]SYNResponse, error)
}

// ICMPClient owns privileged, bounded IPv4 Echo discovery. Callers receive
// only live-host observations and never receive raw ICMP sockets or packets.
type ICMPClient interface {
	DiscoverICMP(context.Context, ICMPScanRequest) ([]ICMPResponse, error)
}

// ICMP6Client is the optional IPv6 Echo discovery counterpart. Keeping it
// separate preserves compatibility with IPv4-only discovery adapters.
type ICMP6Client interface {
	DiscoverICMP6(context.Context, ICMPScanRequest) ([]ICMPResponse, error)
}

var _ Client = (*Engine)(nil)
var _ TCPClient = (*Engine)(nil)
var _ TCPBannerClient = (*Engine)(nil)
var _ UDPClient = (*Engine)(nil)
var _ SYNClient = (*Engine)(nil)
var _ SYN6Client = (*Engine)(nil)
var _ ICMPClient = (*Engine)(nil)
var _ ICMP6Client = (*Engine)(nil)
