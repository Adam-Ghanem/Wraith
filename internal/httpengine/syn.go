package httpengine

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/policy"
	"golang.org/x/net/ipv4"
)

var (
	ErrInvalidSYNRequest = errors.New("invalid SYN scan request")
	ErrSYNPermission     = errors.New("raw SYN scanning requires CAP_NET_RAW or root privileges")
	ErrSYNUnsupported    = errors.New("raw SYN scanning currently requires an IPv4 destination")
)

type SYNState string

const (
	SYNStateOpen     SYNState = "open"
	SYNStateClosed   SYNState = "closed"
	SYNStateFiltered SYNState = "filtered"
	SYNStateError    SYNState = "transport_error"
)

type SYNScanRequest struct {
	ProjectID string
	Target    policy.Target
	Ports     []uint16
	Timeout   time.Duration
}

type SYNResponse struct {
	Port           uint16
	State          SYNState
	Duration       time.Duration
	ObservedAt     time.Time
	RemoteAddr     string
	TTL            int
	Window         uint16
	MSS            uint16
	WindowScale    uint8
	WindowScaleSet bool
	SACKPermitted  bool
	Timestamp      bool
	Options        string
	Error          string
}

type synProbe struct {
	seq    uint32
	sentAt time.Time
}

type synReply struct {
	seq            uint32
	ack            uint32
	flags          uint8
	window         uint16
	ttl            int
	mss            uint16
	windowScale    uint8
	windowScaleSet bool
	sackPermitted  bool
	timestamp      bool
	options        string
}

// ScanSYN performs a bounded IPv4 half-open TCP scan through the R3 transport
// boundary. It owns the raw socket, authorizes every destination port before
// sending, rate-limits every SYN, and never exposes packet sockets to callers.
func (engine *Engine) ScanSYN(ctx context.Context, request SYNScanRequest) ([]SYNResponse, error) {
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

	remote, err := engine.resolveSYNIPv4(ctx, request.Target)
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

	raw, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
	if err != nil {
		if isRawPermissionError(err) {
			return nil, ErrSYNPermission
		}
		return nil, err
	}
	defer raw.Close()

	local, err := sourceIPv4For(remote, ports[0])
	if err != nil {
		return nil, err
	}
	packetConn := ipv4.NewPacketConn(raw)
	_ = packetConn.SetControlMessage(ipv4.FlagTTL, true)

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
			sourceIP := addrIPv4(source)
			if sourceIP == nil || !sourceIP.Equal(net.IP(remote.AsSlice())) {
				continue
			}
			ttl := 0
			if control != nil {
				ttl = control.TTL
			}
			reply, sourceTCPPort, destinationTCPPort, ok := parseSYNReply(buffer[:n], ttl)
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
				reset := buildTCPReset(local, net.IP(remote.AsSlice()), sourcePort, sourceTCPPort, reply.ack, reply.seq+1)
				_, _ = packetConn.WriteTo(reset, nil, &net.IPAddr{IP: net.IP(remote.AsSlice())})
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
		segment := buildTCPSYN(local, net.IP(remote.AsSlice()), sourcePort, port, sequence)
		if _, err := packetConn.WriteTo(segment, nil, &net.IPAddr{IP: net.IP(remote.AsSlice())}); err != nil {
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

func validateSYNRequest(request SYNScanRequest) ([]uint16, error) {
	if strings.TrimSpace(request.ProjectID) == "" || (!request.Target.IP.IsValid() && strings.TrimSpace(request.Target.Hostname) == "") || request.Target.Port != 0 || request.Target.Path != "" || request.Target.Scheme != "" {
		return nil, ErrInvalidSYNRequest
	}
	if request.Timeout < 0 || request.Timeout > 30*time.Second || len(request.Ports) == 0 || len(request.Ports) > 65535 {
		return nil, ErrInvalidSYNRequest
	}
	ports := append([]uint16(nil), request.Ports...)
	sort.Slice(ports, func(i, j int) bool { return ports[i] < ports[j] })
	for i, port := range ports {
		if port == 0 || (i > 0 && ports[i-1] == port) {
			return nil, ErrInvalidSYNRequest
		}
	}
	return ports, nil
}

func (engine *Engine) resolveSYNIPv4(ctx context.Context, target policy.Target) (netip.Addr, error) {
	addresses := []netip.Addr{}
	if target.IP.IsValid() {
		addresses = append(addresses, target.IP.Unmap())
	} else {
		if engine.config.Resolver == nil {
			return netip.Addr{}, ErrTCPDNSResolution
		}
		resolved, err := engine.config.Resolver.Resolve(ctx, target.Hostname)
		if err != nil || len(resolved) == 0 {
			return netip.Addr{}, fmt.Errorf("%w: %v", ErrTCPDNSResolution, err)
		}
		for _, address := range resolved {
			addresses = append(addresses, address.Unmap())
		}
	}
	var selected netip.Addr
	for _, candidate := range addresses {
		if err := engine.config.DestinationPolicy.Validate(candidate); err != nil {
			return netip.Addr{}, fmt.Errorf("%w: %v", ErrTCPDestination, err)
		}
		if candidate.Is4() && !selected.IsValid() {
			selected = candidate
		}
	}
	if !selected.IsValid() {
		return netip.Addr{}, ErrSYNUnsupported
	}
	return selected, nil
}

func sourceIPv4For(remote netip.Addr, port uint16) (net.IP, error) {
	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IP(remote.AsSlice()), Port: int(port)})
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	local, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || local.IP.To4() == nil {
		return nil, ErrSYNUnsupported
	}
	return append(net.IP(nil), local.IP.To4()...), nil
}

func randomSYNSourcePort() (uint16, error) {
	var raw [2]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return 0, err
	}
	return 40000 + binary.BigEndian.Uint16(raw[:])%20000, nil
}

func randomSYNSequence() (uint32, error) {
	var raw [4]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(raw[:]), nil
}

func buildTCPSYN(source, destination net.IP, sourcePort, destinationPort uint16, sequence uint32) []byte {
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
	binary.BigEndian.PutUint16(segment[16:18], tcpChecksum(source, destination, segment))
	return segment
}

func buildTCPReset(source, destination net.IP, sourcePort, destinationPort uint16, sequence, acknowledgment uint32) []byte {
	segment := make([]byte, 20)
	binary.BigEndian.PutUint16(segment[0:2], sourcePort)
	binary.BigEndian.PutUint16(segment[2:4], destinationPort)
	binary.BigEndian.PutUint32(segment[4:8], sequence)
	binary.BigEndian.PutUint32(segment[8:12], acknowledgment)
	segment[12] = 5 << 4
	segment[13] = 0x14
	binary.BigEndian.PutUint16(segment[16:18], tcpChecksum(source, destination, segment))
	return segment
}

func tcpChecksum(source, destination net.IP, segment []byte) uint16 {
	src := source.To4()
	dst := destination.To4()
	if src == nil || dst == nil {
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
	sum += 6
	sum += uint32(len(segment))
	add(segment)
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func parseSYNReply(packet []byte, controlTTL int) (synReply, uint16, uint16, bool) {
	payload := packet
	ttl := controlTTL
	if len(packet) >= 40 && packet[0]>>4 == 4 && packet[9] == 6 {
		headerLength := int(packet[0]&0x0f) * 4
		if headerLength < 20 || len(packet) < headerLength+20 {
			return synReply{}, 0, 0, false
		}
		if ttl == 0 {
			ttl = int(packet[8])
		}
		payload = packet[headerLength:]
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
		ttl:    ttl,
	}
	if headerLength > 20 {
		reply.mss, reply.windowScale, reply.windowScaleSet, reply.sackPermitted, reply.timestamp, reply.options = parseTCPOptions(payload[20:headerLength])
	}
	return reply, sourcePort, destinationPort, true
}

func parseTCPOptions(options []byte) (uint16, uint8, bool, bool, bool, string) {
	var mss uint16
	var windowScale uint8
	var windowScaleSet bool
	var sack bool
	var timestamp bool
	parts := make([]string, 0, 8)
	for index := 0; index < len(options); {
		kind := options[index]
		switch kind {
		case 0:
			parts = append(parts, "eol")
			return mss, windowScale, windowScaleSet, sack, timestamp, strings.Join(parts, ",")
		case 1:
			parts = append(parts, "nop")
			index++
			continue
		}
		if index+1 >= len(options) {
			break
		}
		length := int(options[index+1])
		if length < 2 || index+length > len(options) {
			break
		}
		switch kind {
		case 2:
			if length == 4 {
				mss = binary.BigEndian.Uint16(options[index+2 : index+4])
				parts = append(parts, fmt.Sprintf("mss%d", mss))
			}
		case 3:
			if length == 3 {
				windowScale = options[index+2]
				windowScaleSet = true
				parts = append(parts, fmt.Sprintf("ws%d", windowScale))
			}
		case 4:
			if length == 2 {
				sack = true
				parts = append(parts, "sack")
			}
		case 8:
			if length == 10 {
				timestamp = true
				parts = append(parts, "ts")
			}
		default:
			parts = append(parts, fmt.Sprintf("opt%d", kind))
		}
		index += length
	}
	return mss, windowScale, windowScaleSet, sack, timestamp, strings.Join(parts, ",")
}

func collectSYNResponses(ports []uint16, pending map[uint16]synProbe, responses map[uint16]SYNResponse, remote netip.Addr) []SYNResponse {
	now := time.Now().UTC()
	result := make([]SYNResponse, 0, len(ports))
	for _, port := range ports {
		response, ok := responses[port]
		if !ok {
			response = SYNResponse{Port: port, State: SYNStateFiltered, ObservedAt: now, RemoteAddr: net.JoinHostPort(remote.String(), fmt.Sprintf("%d", port))}
			if probe, exists := pending[port]; exists {
				response.Duration = now.Sub(probe.sentAt)
			}
		}
		result = append(result, response)
	}
	return result
}

func addrIPv4(address net.Addr) net.IP {
	switch value := address.(type) {
	case *net.IPAddr:
		return value.IP.To4()
	case *net.TCPAddr:
		return value.IP.To4()
	default:
		return nil
	}
}

func isRawPermissionError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, os.ErrPermission) {
		return true
	}
	lower := strings.ToLower(err.Error())
	return strings.Contains(lower, "operation not permitted") || strings.Contains(lower, "permission denied")
}

func isClosedNetworkError(err error) bool {
	if err == nil {
		return false
	}
	lower := strings.ToLower(err.Error())
	return strings.Contains(lower, "use of closed network connection") || strings.Contains(lower, "closed")
}
