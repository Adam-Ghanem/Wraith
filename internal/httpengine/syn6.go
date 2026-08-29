package httpengine

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/policy"
	"golang.org/x/net/ipv6"
)

var ErrSYN6Unsupported = errors.New("raw IPv6 SYN scanning requires an IPv6 destination")

// ScanSYN6 performs a bounded IPv6 half-open TCP scan through the same R3
// transport boundary used by IPv4 SYN scanning. The raw socket is owned by the
// transport, every destination port is authorized before send, and packet
// sockets/raw frames are never exposed to callers.
func (engine *Engine) ScanSYN6(ctx context.Context, request SYNScanRequest) ([]SYNResponse, error) {
	if engine == nil || engine.config.Gateway == nil {
		return nil, fmt.Errorf("%w: missing policy gateway", ErrInvalidSYNRequest)
	}
	if engine.configErr != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidSYNRequest, engine.configErr)
	}
	ports, err := validateSYNRequest(request)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	remote, err := engine.resolveSYNIPv6(ctx, request.Target)
	if err != nil {
		return nil, err
	}
	for _, port := range ports {
		original := policy.Target{IP: request.Target.IP, Hostname: request.Target.Hostname, Port: port}
		if _, err := engine.config.Gateway.Authorize(ctx, request.ProjectID, original, policy.ActionScan); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrTCPPolicyDenied, err)
		}
		resolved := policy.Target{IP: remote, Port: port}
		if _, err := engine.config.Gateway.Authorize(ctx, request.ProjectID, resolved, policy.ActionConnect); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrTCPPolicyDenied, err)
		}
	}

	if err := engine.acquireRequestSlot(ctx); err != nil {
		return nil, err
	}
	defer engine.releaseRequestSlot()

	raw, err := net.ListenPacket("ip6:tcp", "::")
	if err != nil {
		if isRawPermissionError(err) {
			return nil, ErrSYNPermission
		}
		return nil, err
	}
	defer raw.Close()

	local, err := sourceIPv6For(remote, ports[0])
	if err != nil {
		return nil, err
	}
	packetConn := ipv6.NewPacketConn(raw)
	_ = packetConn.SetControlMessage(ipv6.FlagHopLimit, true)

	sourcePort, err := randomSYNSourcePort()
	if err != nil {
		return nil, err
	}

	pending := make(map[uint16]synProbe, len(ports))
	responses := make(map[uint16]SYNResponse, len(ports))
	var mu sync.Mutex
	var receiver sync.WaitGroup
	var allDoneOnce sync.Once
	allDone := make(chan struct{})
	done := make(chan struct{})

	receiver.Add(1)
	go func() {
		defer receiver.Done()
		buffer := make([]byte, 4096)
		for {
			_ = raw.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			n, control, source, readErr := packetConn.ReadFrom(buffer)
			if readErr != nil {
				select {
				case <-done:
					return
				default:
				}
				if netErr, ok := readErr.(net.Error); ok && netErr.Timeout() {
					continue
				}
				if isClosedNetworkError(readErr) {
					return
				}
				continue
			}
			sourceIP := addrIPv6(source)
			if sourceIP == nil || !sourceIP.Equal(net.IP(remote.AsSlice())) {
				continue
			}
			hopLimit := 0
			if control != nil {
				hopLimit = control.HopLimit
			}
			reply, sourceTCPPort, destinationTCPPort, ok := parseSYN6Reply(buffer[:n], hopLimit)
			if !ok || destinationTCPPort != sourcePort {
				continue
			}

			mu.Lock()
			probe, exists := pending[sourceTCPPort]
			if !exists {
				mu.Unlock()
				continue
			}
			if reply.flags&0x10 != 0 && reply.ack != probe.seq+1 {
				mu.Unlock()
				continue
			}
			if _, exists := responses[sourceTCPPort]; exists {
				mu.Unlock()
				continue
			}
			state := SYNState("")
			switch {
			case reply.flags&0x12 == 0x12:
				state = SYNStateOpen
			case reply.flags&0x04 != 0:
				state = SYNStateClosed
			default:
				mu.Unlock()
				continue
			}
			observed := time.Now().UTC()
			responses[sourceTCPPort] = SYNResponse{
				Port:           sourceTCPPort,
				State:          state,
				Duration:       observed.Sub(probe.sentAt),
				ObservedAt:     observed,
				RemoteAddr:     net.JoinHostPort(remote.String(), fmt.Sprintf("%d", sourceTCPPort)),
				TTL:            reply.ttl,
				Window:         reply.window,
				MSS:            reply.mss,
				WindowScale:    reply.windowScale,
				WindowScaleSet: reply.windowScaleSet,
				SACKPermitted:  reply.sackPermitted,
				Timestamp:      reply.timestamp,
				Options:        reply.options,
			}
			finished := len(responses) == len(ports)
			mu.Unlock()

			if state == SYNStateOpen {
				reset := buildTCPReset6(local, net.IP(remote.AsSlice()), sourcePort, sourceTCPPort, reply.ack, reply.seq+1)
				_, _ = packetConn.WriteTo(reset, nil, &net.IPAddr{IP: net.IP(remote.AsSlice()), Zone: remote.Zone()})
			}
			if finished {
				allDoneOnce.Do(func() { close(allDone) })
			}
		}
	}()

	for _, port := range ports {
		if err := ctx.Err(); err != nil {
			close(done)
			_ = raw.Close()
			receiver.Wait()
			return collectSYNResponses(ports, pending, responses, remote), err
		}
		if engine.config.RateLimiter != nil {
			if err := engine.config.RateLimiter.Wait(ctx); err != nil {
				close(done)
				_ = raw.Close()
				receiver.Wait()
				return collectSYNResponses(ports, pending, responses, remote), err
			}
		}
		sequence, err := randomSYNSequence()
		if err != nil {
			mu.Lock()
			responses[port] = SYNResponse{Port: port, State: SYNStateError, ObservedAt: time.Now().UTC(), Error: "transport error"}
			mu.Unlock()
			continue
		}
		sentAt := time.Now().UTC()
		mu.Lock()
		pending[port] = synProbe{seq: sequence, sentAt: sentAt}
		mu.Unlock()
		segment := buildTCPSYN6(local, net.IP(remote.AsSlice()), sourcePort, port, sequence)
		if _, err := packetConn.WriteTo(segment, nil, &net.IPAddr{IP: net.IP(remote.AsSlice()), Zone: remote.Zone()}); err != nil {
			if isRawPermissionError(err) {
				close(done)
				_ = raw.Close()
				receiver.Wait()
				return collectSYNResponses(ports, pending, responses, remote), ErrSYNPermission
			}
			mu.Lock()
			responses[port] = SYNResponse{Port: port, State: SYNStateError, Duration: time.Since(sentAt), ObservedAt: time.Now().UTC(), Error: "transport error"}
			mu.Unlock()
		}
	}

	wait := request.Timeout
	if wait <= 0 || wait > engine.config.RequestTimeout {
		wait = engine.config.RequestTimeout
	}
	timer := time.NewTimer(wait)
	select {
	case <-ctx.Done():
		timer.Stop()
	case <-allDone:
		timer.Stop()
	case <-timer.C:
	}
	close(done)
	_ = raw.Close()
	receiver.Wait()
	result := collectSYNResponses(ports, pending, responses, remote)
	if err := ctx.Err(); err != nil {
		return result, err
	}
	return result, nil
}

func (engine *Engine) resolveSYNIPv6(ctx context.Context, target policy.Target) (netip.Addr, error) {
	addresses := []netip.Addr{}
	if target.IP.IsValid() {
		addresses = append(addresses, target.IP)
	} else {
		if engine.config.Resolver == nil {
			return netip.Addr{}, ErrTCPDNSResolution
		}
		resolved, err := engine.config.Resolver.Resolve(ctx, target.Hostname)
		if err != nil || len(resolved) == 0 {
			return netip.Addr{}, fmt.Errorf("%w: %v", ErrTCPDNSResolution, err)
		}
		addresses = append(addresses, resolved...)
	}
	var selected netip.Addr
	for _, candidate := range addresses {
		if err := engine.config.DestinationPolicy.Validate(candidate); err != nil {
			return netip.Addr{}, fmt.Errorf("%w: %v", ErrTCPDestination, err)
		}
		if candidate.Is6() && !candidate.Is4In6() && !selected.IsValid() {
			selected = candidate
		}
	}
	if !selected.IsValid() {
		return netip.Addr{}, ErrSYN6Unsupported
	}
	return selected, nil
}

func sourceIPv6For(remote netip.Addr, port uint16) (net.IP, error) {
	conn, err := net.DialUDP("udp6", nil, &net.UDPAddr{IP: net.IP(remote.AsSlice()), Port: int(port), Zone: remote.Zone()})
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	local, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || local.IP.To16() == nil || local.IP.To4() != nil {
		return nil, ErrSYN6Unsupported
	}
	return append(net.IP(nil), local.IP.To16()...), nil
}

func buildTCPSYN6(source, destination net.IP, sourcePort, destinationPort uint16, sequence uint32) []byte {
	segment := make([]byte, 40)
	binary.BigEndian.PutUint16(segment[0:2], sourcePort)
	binary.BigEndian.PutUint16(segment[2:4], destinationPort)
	binary.BigEndian.PutUint32(segment[4:8], sequence)
	segment[12] = 10 << 4
	segment[13] = 0x02
	binary.BigEndian.PutUint16(segment[14:16], 64240)
	timestamp := uint32(time.Now().UnixMilli())
	options := []byte{
		2, 4, 0x05, 0xb4,
		4, 2,
		8, 10, byte(timestamp >> 24), byte(timestamp >> 16), byte(timestamp >> 8), byte(timestamp), 0, 0, 0, 0,
		1, 3, 3, 7,
	}
	copy(segment[20:], options)
	binary.BigEndian.PutUint16(segment[16:18], tcpChecksumIPv6(source, destination, segment))
	return segment
}

func buildTCPReset6(source, destination net.IP, sourcePort, destinationPort uint16, sequence, acknowledgment uint32) []byte {
	segment := make([]byte, 20)
	binary.BigEndian.PutUint16(segment[0:2], sourcePort)
	binary.BigEndian.PutUint16(segment[2:4], destinationPort)
	binary.BigEndian.PutUint32(segment[4:8], sequence)
	binary.BigEndian.PutUint32(segment[8:12], acknowledgment)
	segment[12] = 5 << 4
	segment[13] = 0x14
	binary.BigEndian.PutUint16(segment[16:18], tcpChecksumIPv6(source, destination, segment))
	return segment
}

func tcpChecksumIPv6(source, destination net.IP, segment []byte) uint16 {
	src := source.To16()
	dst := destination.To16()
	if src == nil || dst == nil || source.To4() != nil || destination.To4() != nil {
		return 0
	}
	sum := uint32(0)
	add := func(data []byte) {
		for len(data) >= 2 {
			sum += uint32(binary.BigEndian.Uint16(data[:2]))
			data = data[2:]
		}
		if len(data) == 1 {
			sum += uint32(data[0]) << 8
		}
	}
	add(src)
	add(dst)
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(segment)))
	add(length[:])
	sum += 6
	add(segment)
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func parseSYN6Reply(packet []byte, controlHopLimit int) (synReply, uint16, uint16, bool) {
	payload := packet
	hopLimit := controlHopLimit
	if len(packet) >= 60 && packet[0]>>4 == 6 {
		if packet[6] != 6 {
			return synReply{}, 0, 0, false
		}
		if hopLimit == 0 {
			hopLimit = int(packet[7])
		}
		payload = packet[40:]
	}
	if len(payload) < 20 {
		return synReply{}, 0, 0, false
	}
	headerLength := int(payload[12]>>4) * 4
	if headerLength < 20 || headerLength > len(payload) {
		return synReply{}, 0, 0, false
	}
	sourcePort := binary.BigEndian.Uint16(payload[0:2])
	destinationPort := binary.BigEndian.Uint16(payload[2:4])
	reply := synReply{
		seq:    binary.BigEndian.Uint32(payload[4:8]),
		ack:    binary.BigEndian.Uint32(payload[8:12]),
		flags:  payload[13],
		window: binary.BigEndian.Uint16(payload[14:16]),
		ttl:    hopLimit,
	}
	if headerLength > 20 {
		reply.mss, reply.windowScale, reply.windowScaleSet, reply.sackPermitted, reply.timestamp, reply.options = parseTCPOptions(payload[20:headerLength])
	}
	return reply, sourcePort, destinationPort, true
}

func addrIPv6(address net.Addr) net.IP {
	switch value := address.(type) {
	case *net.IPAddr:
		if value.IP.To4() == nil {
			return value.IP.To16()
		}
	case *net.TCPAddr:
		if value.IP.To4() == nil {
			return value.IP.To16()
		}
	}
	return nil
}
