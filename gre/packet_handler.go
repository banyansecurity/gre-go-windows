package gre

import (
	"errors"
	"math"
	"math/rand"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/uuid"
	"golang.zx2c4.com/wintun"
)

type PacketHandler interface {
	UseSession(wintun.Session) PacketHandler
	Handle(*RequestMetadata, []byte) error
}

const (
	// Matches the Windows default TTL. Not sure if it matters but the default
	// Linux TTL is half of this.
	defaultTTL = 128

	// Matches the default Linux connector GRE header.
	defaultGREProtocol = 0x0800     // IPv4
	defaultGREKey      = 0x000004D2 // 1234
)

var (
	ErrCannotProxyDNS       = errors.New("cannot proxy because payload does not appear to be dns")
	ErrNotHealthCheckReply  = errors.New("not a health check reply")
	ErrCannotProxyICMPReply = errors.New("cannot proxy because payload does not appear to be icmp reply")
)

type GREDeencapsulator struct {
	adapter   *GREAdapter
	session   wintun.Session
	gre       *layers.GRE
	greParser *gopacket.DecodingLayerParser
	decoded   []gopacket.LayerType
}

func NewGREDeencapsulator(adapter *GREAdapter) *GREDeencapsulator {
	var (
		gre       = &layers.GRE{}
		greParser = gopacket.NewDecodingLayerParser(layers.LayerTypeGRE, gre)
	)
	greParser.IgnoreUnsupported = true

	return &GREDeencapsulator{
		adapter:   adapter,
		gre:       gre,
		greParser: greParser,
		decoded:   make([]gopacket.LayerType, 1),
	}
}

func (gd *GREDeencapsulator) UseSession(session wintun.Session) PacketHandler {
	gd.session = session
	return gd
}

func (gd *GREDeencapsulator) Handle(rm *RequestMetadata, packet []byte) error {
	mustHavePreconditions(rm)

	if err := gd.greParser.DecodeLayers(packet, &gd.decoded); err != nil {
		return err
	}

	var (
		payload   = gd.gre.LayerPayload()
		totalSize = len(payload)
	)
	outgoingPacket, err := gd.session.AllocateSendPacket(totalSize)
	if err != nil {
		return err
	}

	copy(outgoingPacket, payload)
	gd.session.SendPacket(outgoingPacket)
	return nil
}

type GREEncapsulator struct {
	adapter *GREAdapter
	session wintun.Session
	ip4     *layers.IPv4
	gre     *layers.GRE
	buf     gopacket.SerializeBuffer
	opts    gopacket.SerializeOptions
}

func NewGREEncapsulator(adapter *GREAdapter) *GREEncapsulator {
	var (
		ip4 = &layers.IPv4{}
		gre = &layers.GRE{}
	)
	return &GREEncapsulator{
		adapter: adapter,
		ip4:     ip4,
		gre:     gre,
		buf:     gopacket.NewSerializeBuffer(),
		opts: gopacket.SerializeOptions{
			ComputeChecksums: true,
			FixLengths:       true,
		},
	}
}

func (ge *GREEncapsulator) UseSession(session wintun.Session) PacketHandler {
	ge.session = session
	return ge
}

func (ge *GREEncapsulator) Handle(rm *RequestMetadata, packet []byte) error {
	mustHavePreconditions(rm)

	ge.ip4.Version = 4
	ge.ip4.Id = ge.adapter.nextCounter()
	ge.ip4.Flags = layers.IPv4DontFragment
	ge.ip4.TTL = defaultTTL
	ge.ip4.Protocol = layers.IPProtocolGRE
	ge.ip4.SrcIP = ge.adapter.TunnelIP()
	ge.ip4.DstIP = rm.AccessTierGREIP()

	ge.gre.KeyPresent = true
	ge.gre.Protocol = defaultGREProtocol
	ge.gre.Key = defaultGREKey

	serializingPayload := gopacket.Payload(packet)
	if err := gopacket.SerializeLayers(ge.buf, ge.opts, ge.ip4, ge.gre, serializingPayload); err != nil {
		return err
	}

	var (
		payload   = ge.buf.Bytes()
		totalSize = len(payload)
	)
	outgoingPacket, err := ge.session.AllocateSendPacket(totalSize)
	if err != nil {
		return err
	}

	copy(outgoingPacket, payload)
	ge.session.SendPacket(outgoingPacket)
	return nil
}

type DNSPacketInboundProxy struct {
	adapter   *GREAdapter
	session   wintun.Session
	ip4       *layers.IPv4
	udp       *layers.UDP
	udpParser *gopacket.DecodingLayerParser
	decoded   []gopacket.LayerType
	buf       gopacket.SerializeBuffer
	opts      gopacket.SerializeOptions
}

func NewDNSPacketInboundProxy(adapter *GREAdapter) *DNSPacketInboundProxy {
	var (
		ip4       = &layers.IPv4{}
		udp       = &layers.UDP{}
		udpParser = gopacket.NewDecodingLayerParser(layers.LayerTypeUDP, udp)
	)
	udpParser.IgnoreUnsupported = true

	return &DNSPacketInboundProxy{
		adapter:   adapter,
		ip4:       ip4,
		udp:       udp,
		udpParser: udpParser,
		decoded:   make([]gopacket.LayerType, 1),
		buf:       gopacket.NewSerializeBuffer(),
		opts: gopacket.SerializeOptions{
			ComputeChecksums: true,
			FixLengths:       true,
		},
	}
}

func (dp *DNSPacketInboundProxy) UseSession(session wintun.Session) PacketHandler {
	dp.session = session
	return dp
}

func (dp *DNSPacketInboundProxy) Handle(rm *RequestMetadata, packet []byte) error {
	mustHavePreconditions(rm)

	if err := dp.udpParser.DecodeLayers(packet, &dp.decoded); err != nil {
		return err
	}

	if dp.udp.DstPort != 53 {
		return ErrCannotProxyDNS
	}

	dp.ip4.Version = 4
	dp.ip4.Id = dp.adapter.nextCounter()
	dp.ip4.Flags = layers.IPv4DontFragment
	dp.ip4.TTL = defaultTTL
	dp.ip4.Protocol = layers.IPProtocolUDP
	dp.ip4.SrcIP = rm.ConnectorGREIP()
	dp.ip4.DstIP = dp.adapter.DNSIP()

	dp.udp.Checksum = 0
	dp.udp.SetNetworkLayerForChecksum(dp.ip4)

	serializingPayload := gopacket.Payload(dp.udp.LayerPayload())
	if err := gopacket.SerializeLayers(dp.buf, dp.opts, dp.ip4, dp.udp, serializingPayload); err != nil {
		return err
	}

	var (
		payload   = dp.buf.Bytes()
		totalSize = len(payload)
	)
	outgoingPacket, err := dp.session.AllocateSendPacket(totalSize)
	if err != nil {
		return err
	}

	copy(outgoingPacket, payload)
	dp.session.SendPacket(outgoingPacket)
	return nil
}

type DNSPacketOutboundProxy struct {
	adapter   *GREAdapter
	session   wintun.Session
	outerIP4  *layers.IPv4
	gre       *layers.GRE
	innerIP4  *layers.IPv4
	udp       *layers.UDP
	udpParser *gopacket.DecodingLayerParser
	decoded   []gopacket.LayerType
	buf       gopacket.SerializeBuffer
	opts      gopacket.SerializeOptions
}

func NewDNSPacketOutboundProxy(adapter *GREAdapter) *DNSPacketOutboundProxy {
	var (
		outerIP4  = &layers.IPv4{}
		gre       = &layers.GRE{}
		innerIP4  = &layers.IPv4{}
		udp       = &layers.UDP{}
		udpParser = gopacket.NewDecodingLayerParser(layers.LayerTypeUDP, udp)
	)
	udpParser.IgnoreUnsupported = true

	return &DNSPacketOutboundProxy{
		adapter:   adapter,
		outerIP4:  outerIP4,
		gre:       gre,
		innerIP4:  innerIP4,
		udp:       udp,
		udpParser: udpParser,
		decoded:   make([]gopacket.LayerType, 1),
		buf:       gopacket.NewSerializeBuffer(),
		opts: gopacket.SerializeOptions{
			ComputeChecksums: true,
			FixLengths:       true,
		},
	}
}

func (dp *DNSPacketOutboundProxy) UseSession(session wintun.Session) PacketHandler {
	dp.session = session
	return dp
}

func (dp *DNSPacketOutboundProxy) Handle(rm *RequestMetadata, packet []byte) error {
	mustHavePreconditions(rm)

	if err := dp.udpParser.DecodeLayers(packet, &dp.decoded); err != nil {
		return err
	}

	if dp.udp.SrcPort != 53 {
		return ErrCannotProxyDNS
	}

	// Well, this is a little bit of a hack. Note that we apply a NAT rule on
	// this interface which causes Windows to modify the IP header to use the
	// public interface IP. That works for the most part except in the case where
	// we try to send packets direct to the WireGuard interface without the
	// tunnel, such as for DNS packets or pings. In that case, we get into a case
	// where the packets traversing into WireGuard erroneusly have the public
	// interface IP as the source IP!
	//
	// So, to work around this, we *encapsulate* this return payload in the GRE
	// tunnel which causes this traffic to skip past the NAT logic that would
	// usually apply to TCP, UDP, and ICMP traffic. Unfortunately, this looks
	// pretty weird because the inbound packet is not encapsulated while the
	// outbound response packet is.
	dp.outerIP4.Version = 4
	dp.outerIP4.Id = dp.adapter.nextCounter()
	dp.outerIP4.Flags = layers.IPv4DontFragment
	dp.outerIP4.TTL = defaultTTL
	dp.outerIP4.Protocol = layers.IPProtocolGRE
	dp.outerIP4.SrcIP = dp.adapter.TunnelIP()
	dp.outerIP4.DstIP = rm.AccessTierGREIP()

	dp.gre.KeyPresent = true
	dp.gre.Protocol = defaultGREProtocol
	dp.gre.Key = defaultGREKey

	dp.innerIP4.Version = 4
	dp.innerIP4.Id = dp.adapter.nextCounter()
	dp.innerIP4.Flags = layers.IPv4DontFragment
	dp.innerIP4.TTL = defaultTTL
	dp.innerIP4.Protocol = layers.IPProtocolUDP
	dp.innerIP4.SrcIP = dp.adapter.TunnelIP()
	dp.innerIP4.DstIP = rm.AccessTierGREIP()

	dp.udp.Checksum = 0
	dp.udp.SetNetworkLayerForChecksum(dp.innerIP4)

	serializingPayload := gopacket.Payload(dp.udp.LayerPayload())
	if err := gopacket.SerializeLayers(dp.buf, dp.opts, dp.outerIP4, dp.gre, dp.innerIP4, dp.udp, serializingPayload); err != nil {
		return err
	}

	var (
		payload   = dp.buf.Bytes()
		totalSize = len(payload)
	)
	outgoingPacket, err := dp.session.AllocateSendPacket(totalSize)
	if err != nil {
		return err
	}

	copy(outgoingPacket, payload)
	dp.session.SendPacket(outgoingPacket)
	return nil
}

type ICMP4HealthCheck struct {
	adapter    *GREAdapter
	session    wintun.Session
	ip4        *layers.IPv4
	icmp       *layers.ICMPv4
	icmpParser *gopacket.DecodingLayerParser
	decoded    []gopacket.LayerType
	buf        gopacket.SerializeBuffer
	opts       gopacket.SerializeOptions
	payload    gopacket.Payload
	counter    uint16
	numPeers   int
}

const (
	icmp4RequestPayloadSize = 32
	icmp4RequestID          = 7331
)

var (
	icmp4Payload = []byte(uuid.New().String())[:icmp4RequestPayloadSize]
)

func NewICMP4HealthCheck(adapter *GREAdapter) *ICMP4HealthCheck {
	var (
		ip4        = &layers.IPv4{}
		icmp       = &layers.ICMPv4{}
		icmpParser = gopacket.NewDecodingLayerParser(layers.LayerTypeICMPv4, icmp)
	)
	icmpParser.IgnoreUnsupported = true

	return &ICMP4HealthCheck{
		adapter:    adapter,
		ip4:        ip4,
		icmp:       icmp,
		icmpParser: icmpParser,
		decoded:    make([]gopacket.LayerType, 1),
		buf:        gopacket.NewSerializeBuffer(),
		opts: gopacket.SerializeOptions{
			ComputeChecksums: true,
			FixLengths:       true,
		},
		payload: icmp4Payload,
		counter: uint16(rand.Intn(math.MaxUint16 + 1)),
	}
}

func (ic *ICMP4HealthCheck) UseSession(session wintun.Session) *ICMP4HealthCheck {
	ic.session = session
	return ic
}

func (ic *ICMP4HealthCheck) Expect(numPeers int) *ICMP4HealthCheck {
	ic.numPeers = numPeers
	return ic
}

func (ic *ICMP4HealthCheck) HandleRequest(src, dst net.IP) error {
	defer func() {
		ic.counter++
	}()

	ic.ip4.Version = 4
	ic.ip4.Id = ic.adapter.nextCounter()
	ic.ip4.Flags = layers.IPv4DontFragment
	ic.ip4.TTL = defaultTTL
	ic.ip4.Protocol = layers.IPProtocolICMPv4
	ic.ip4.SrcIP = src
	ic.ip4.DstIP = dst

	ic.icmp.TypeCode = layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0)
	ic.icmp.Checksum = 0
	ic.icmp.Id = icmp4RequestID
	ic.icmp.Seq = ic.counter
	ic.icmp.Payload = ic.payload

	serializingPayload := gopacket.Payload(ic.icmp.LayerPayload())
	if err := gopacket.SerializeLayers(ic.buf, ic.opts, ic.ip4, ic.icmp, serializingPayload); err != nil {
		return err
	}

	var (
		payload   = ic.buf.Bytes()
		totalSize = len(payload)
	)
	outgoingPacket, err := ic.session.AllocateSendPacket(totalSize)
	if err != nil {
		return err
	}

	copy(outgoingPacket, payload)
	ic.session.SendPacket(outgoingPacket)
	return nil
}

func (ic *ICMP4HealthCheck) IsHealthCheckReply(packet []byte) bool {
	if err := ic.icmpParser.DecodeLayers(packet, &ic.decoded); err != nil {
		ic.adapter.logger.Debug(
			"not a health check reply",
			"error", err,
		)
		return false
	}

	if icmpType := ic.icmp.TypeCode.Type(); icmpType != layers.ICMPv4TypeEchoReply {
		ic.adapter.logger.Debug(
			"not a health check reply",
			"expected", layers.ICMPv4TypeEchoReply,
			"actual", icmpType,
		)
		return false
	}

	// The return packet has our unique identifier. Not sure if we ought to check
	// the sequence number here as well.
	if ic.icmp.Id == icmp4RequestID {
		ic.adapter.logger.Debug(
			"health check reply",
			"expected", icmp4RequestID,
			"actual", ic.icmp.Id,
		)
		return true
	}

	ic.adapter.logger.Debug(
		"not a health check reply",
		"expected", icmp4RequestID,
		"actual", ic.icmp.Id,
	)
	return false
}

type ICMP4PacketReplyProxy struct {
	adapter    *GREAdapter
	session    wintun.Session
	ip4        *layers.IPv4
	icmp       *layers.ICMPv4
	icmpParser *gopacket.DecodingLayerParser
	decoded    []gopacket.LayerType
	buf        gopacket.SerializeBuffer
	opts       gopacket.SerializeOptions
}

func NewICMP4PacketReplyProxy(adapter *GREAdapter) *ICMP4PacketReplyProxy {
	var (
		ip4        = &layers.IPv4{}
		icmp       = &layers.ICMPv4{}
		icmpParser = gopacket.NewDecodingLayerParser(layers.LayerTypeICMPv4, icmp)
	)
	icmpParser.IgnoreUnsupported = true

	return &ICMP4PacketReplyProxy{
		adapter:    adapter,
		ip4:        ip4,
		icmp:       icmp,
		icmpParser: icmpParser,
		decoded:    make([]gopacket.LayerType, 1),
		buf:        gopacket.NewSerializeBuffer(),
		opts: gopacket.SerializeOptions{
			ComputeChecksums: true,
			FixLengths:       true,
		},
	}
}

func (ic *ICMP4PacketReplyProxy) UseSession(session wintun.Session) PacketHandler {
	ic.session = session
	return ic
}

func (ic *ICMP4PacketReplyProxy) Handle(rm *RequestMetadata, packet []byte) error {
	mustHavePreconditions(rm)

	if err := ic.icmpParser.DecodeLayers(packet, &ic.decoded); err != nil {
		return err
	}

	if ic.icmp.TypeCode.Type() != layers.ICMPv4TypeEchoReply {
		return ErrCannotProxyICMPReply
	}

	ic.ip4.Version = 4
	ic.ip4.Id = ic.adapter.nextCounter()
	ic.ip4.Flags = layers.IPv4DontFragment
	ic.ip4.TTL = defaultTTL
	ic.ip4.Protocol = layers.IPProtocolICMPv4
	ic.ip4.SrcIP = ic.adapter.TunnelIP()
	ic.ip4.DstIP = net.IPv4(172, 31, 28, 127)

	ic.icmp.Checksum = 0

	serializingPayload := gopacket.Payload(ic.icmp.LayerPayload())
	if err := gopacket.SerializeLayers(ic.buf, ic.opts, ic.ip4, ic.icmp, serializingPayload); err != nil {
		return err
	}

	var (
		payload   = ic.buf.Bytes()
		totalSize = len(payload)
	)
	outgoingPacket, err := ic.session.AllocateSendPacket(totalSize)
	if err != nil {
		return err
	}

	copy(outgoingPacket, payload)
	ic.session.SendPacket(outgoingPacket)
	return nil
}

func mustHavePreconditions(rm *RequestMetadata) {
	if rm.OuterIP4() == nil {
		panic("metadata: outerIP4 is nil")
	}

	if rm.AccessTierGREIP() == nil {
		panic("metadata: accessTierGREIP is nil")
	}
}
