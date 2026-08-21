// Package egress implements T6 central egress dispatch. It owns no socket,
// resolver, or protocol implementation; transport remains an injected R3
// capability.
package egress

import (
	"context"
	"errors"

	"github.com/Adam-Ghanem/Wraith/internal/httpengine"
	"github.com/Adam-Ghanem/Wraith/internal/outbound"
)

var (
	ErrDispatchDenied     = errors.New("central egress dispatch denied")
	ErrTransportUnavailable = errors.New("central egress transport unavailable")
	ErrCapabilityMismatch = errors.New("central egress capability mismatch")
)

// TCPDispatcher is the T6 choke point between an already-authorized T5
// operation and the R3 TCP transport. It deliberately receives the R3
// transport as an interface so T6 cannot acquire network capability itself.
type TCPDispatcher struct {
	Transport httpengine.TCPClient
}

// DispatchTCP performs only T6 admission checks and then delegates the actual
// connection attempt to the injected R3 TCP transport. It never opens sockets,
// resolves names, starts subprocesses, or mutates routing state.
func (dispatcher TCPDispatcher) DispatchTCP(ctx context.Context, decision outbound.Decision, operation outbound.Operation, request httpengine.TCPRequest) (httpengine.TCPResponse, error) {
	if ctx == nil {
		return httpengine.TCPResponse{}, ErrDispatchDenied
	}
	if err := ctx.Err(); err != nil {
		return httpengine.TCPResponse{}, errors.Join(ErrDispatchDenied, err)
	}
	if !decision.Allowed || decision.Capability.Operation != outbound.OperationTCP {
		return httpengine.TCPResponse{}, errors.Join(ErrDispatchDenied, ErrCapabilityMismatch)
	}
	if dispatcher.Transport == nil {
		return httpengine.TCPResponse{}, errors.Join(ErrDispatchDenied, ErrTransportUnavailable)
	}
	if operation.ProjectID != request.ProjectID || decision.Capability.ID != operation.CapabilityID || decision.Target.Port != request.Target.Port {
		return httpengine.TCPResponse{}, errors.Join(ErrDispatchDenied, ErrCapabilityMismatch)
	}
	return dispatcher.Transport.ProbeTCP(ctx, request)
}
