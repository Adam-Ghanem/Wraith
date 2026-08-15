package config

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

var (
	ErrMissingInterface   = errors.New("local IPv4 interface is required")
	ErrInvalidInterfaceIP = errors.New("interface must have one valid local IPv4 address")
	ErrInvalidCIDR        = errors.New("a valid local IPv4 CIDR is required")
	ErrScopeMismatch      = errors.New("interface IPv4 address is outside the selected CIDR")
	ErrUnauthorized       = errors.New("explicit target authorization is required")
	ErrLoopbackScope      = errors.New("loopback interface is outside the Phase 1 discovery boundary")
	ErrPublicScope        = errors.New("globally routable CIDRs are outside the Phase 1 local-network boundary")
)

// Scope is the complete Phase 1 network boundary. It must be validated before
// any network discovery or probing object is created.
type Scope struct {
	Interface   string
	InterfaceIP netip.Addr
	CIDR        netip.Prefix
	Authorized  bool
}

// ValidateScope rejects ambiguity rather than widening or inferring the target
// boundary. It intentionally does not perform network I/O.
func ValidateScope(scope Scope) error {
	if strings.TrimSpace(scope.Interface) == "" {
		return ErrMissingInterface
	}
	if !scope.Authorized {
		return ErrUnauthorized
	}
	if !scope.InterfaceIP.IsValid() || !scope.InterfaceIP.Is4() {
		return ErrInvalidInterfaceIP
	}
	if !scope.CIDR.IsValid() || !scope.CIDR.Addr().Is4() || scope.CIDR != scope.CIDR.Masked() {
		return ErrInvalidCIDR
	}
	if scope.InterfaceIP.IsLoopback() || scope.CIDR.Addr().IsLoopback() {
		return ErrLoopbackScope
	}
	if !scope.CIDR.Addr().IsPrivate() && !scope.CIDR.Addr().IsLinkLocalUnicast() {
		return ErrPublicScope
	}
	if !scope.CIDR.Contains(scope.InterfaceIP) {
		return ErrScopeMismatch
	}
	return nil
}

// ValidateTarget ensures a target remains inside the already-approved boundary.
func ValidateTarget(scope Scope, target netip.Addr) error {
	if err := ValidateScope(scope); err != nil {
		return fmt.Errorf("invalid scope: %w", err)
	}
	if !target.IsValid() || !target.Is4() {
		return ErrInvalidInterfaceIP
	}
	if !scope.CIDR.Contains(target) {
		return ErrScopeMismatch
	}
	return nil
}
