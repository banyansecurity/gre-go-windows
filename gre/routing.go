package gre

import (
	"net"
	"strings"
	"sync/atomic"

	"github.com/banyansecurity/gre-go-windows/health"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/pkg/errors"
	"github.com/puzpuzpuz/xsync"
	"golang.zx2c4.com/wintun"
)

type (
	PacketRouting struct {
		packetCounter          atomic.Uint64
		adapter                *GREAdapter
		ip4                    *layers.IPv4
		ipParser               *gopacket.DecodingLayerParser
		decoded                []gopacket.LayerType
		greDeencapsulator      *GREDeencapsulator
		greEncapsulator        *GREEncapsulator
		dnsPacketInboundProxy  *DNSPacketInboundProxy
		dnsPacketOutboundProxy *DNSPacketOutboundProxy
		icmp4PacketRequest     *ICMP4HealthCheck
		icmp4PacketReplyProxy  *ICMP4PacketReplyProxy
		validSrcs              *xsync.MapOf[string, net.IP]
		validDsts              *xsync.MapOf[string, net.IP]
		healthCheck            *health.HealthCheck
	}
)

func NewPacketRouting(adapter *GREAdapter) *PacketRouting {
	var (
		ip4      = &layers.IPv4{}
		ipParser = gopacket.NewDecodingLayerParser(layers.LayerTypeIPv4, ip4)
	)
	ipParser.IgnoreUnsupported = true

	return &PacketRouting{
		packetCounter:          atomic.Uint64{},
		adapter:                adapter,
		ip4:                    ip4,
		ipParser:               ipParser,
		decoded:                make([]gopacket.LayerType, 1),
		greDeencapsulator:      NewGREDeencapsulator(adapter),
		greEncapsulator:        NewGREEncapsulator(adapter),
		dnsPacketInboundProxy:  NewDNSPacketInboundProxy(adapter),
		dnsPacketOutboundProxy: NewDNSPacketOutboundProxy(adapter),
		icmp4PacketRequest:     NewICMP4HealthCheck(adapter),
		icmp4PacketReplyProxy:  NewICMP4PacketReplyProxy(adapter),
		validSrcs:              xsync.NewTypedMapOf[string, net.IP](xsync.StrHash64),
		validDsts:              xsync.NewTypedMapOf[string, net.IP](xsync.StrHash64),
		healthCheck:            health.NewHealthCheck(),
	}
}

func (pr *PacketRouting) Route(session wintun.Session, packet []byte) error {
	if err := pr.ipParser.DecodeLayers(packet, &pr.decoded); err != nil {
		if pr.passthrough(err) {
			if err := pr.sendAsIs(session, packet); err != nil {
				return err
			}

			return nil
		} else {
			return errors.Wrap(err, "ip parser")
		}
	}

	cid := pr.nextCID()
	pr.adapter.logger.Debug(
		"handling packet",
		"cid", cid,
		"ip4", pr.ip4)
	switch pr.ip4.Protocol {
	case layers.IPProtocolGRE:
		if err := pr.handleGREDeencapsulation(cid, session); err != nil {
			return err
		}
	case layers.IPProtocolUDP:
		if err := pr.handleUDPTraffic(cid, session, packet); err != nil {
			return err
		}
	case layers.IPProtocolICMPv4:
		if err := pr.handleICMPTraffic(cid, session, packet); err != nil {
			return err
		}
	default:
		if err := pr.handleGenericTraffic(cid, session, packet); err != nil {
			return err
		}
	}

	return nil
}

func (pr *PacketRouting) PingAccessTiers(session wintun.Session) {
	size := pr.adapter.router.validSrcs.Size()
	pr.adapter.logger.Info(
		"expected health check value",
		"num_expected", size)
	pr.healthCheck.SetNumExpected(pr.adapter.router.validSrcs.Size())

	src := pr.adapter.tunnelIP
	pr.adapter.router.validSrcs.Range(func(atGREIP string, _ net.IP) bool {
		dst := net.ParseIP(atGREIP)
		pr.adapter.logger.Info(
			"pinging access tier",
			"src", src,
			"dst", dst)
		pr.icmp4PacketRequest.UseSession(session).HandleRequest(src, dst)
		return true
	})
}

func (pr *PacketRouting) HealthCheck() ([]string, bool) {
	status, healthy := pr.healthCheck.Status()
	pr.adapter.logger.Info(
		"handled health check",
		"status", status,
		"healthy", healthy,
		"expected", pr.healthCheck.NumExpected(),
		"actual", pr.healthCheck.NumActual())
	return status, healthy
}

func (pr *PacketRouting) AddAccessTierSourceRoute(accessTierSide, connectorSide net.IP) {
	pr.adapter.logger.Info(
		"access tier route",
		"access_tier", accessTierSide,
		"connector", connectorSide)
	pr.validSrcs.Store(accessTierSide.String(), connectorSide)
}

func (pr *PacketRouting) RemoveAccessTierSourceRoute(accessTierSide net.IP) {
	pr.validSrcs.Delete(accessTierSide.String())
}

func (pr *PacketRouting) AddConnectorReturnRoute(connectorSide, accessTierSide net.IP) {
	pr.adapter.logger.Info(
		"connector return route",
		"connector", connectorSide,
		"access_tier", accessTierSide)
	pr.validDsts.Store(connectorSide.String(), accessTierSide)
}

func (pr *PacketRouting) RemoveConnectorReturnRoute(connectorSide net.IP) {
	pr.validDsts.Delete(connectorSide.String())
}

func (pr *PacketRouting) hasAccessTierSourceRoute(ip4 layers.IPv4) (net.IP, bool) {
	return pr.validSrcs.Load(ip4.SrcIP.String())
}

func (pr *PacketRouting) hasConnectorReturnRoute(ip4 layers.IPv4) (net.IP, bool) {
	return pr.validDsts.Load(ip4.DstIP.String())
}

func (pr *PacketRouting) maybeDNSPacket(ip4 layers.IPv4) bool {
	return ip4.Protocol == layers.IPProtocolUDP && ip4.DstIP.Equal(pr.adapter.TunnelIP())
}

func (pr *PacketRouting) maybeHealthCheck(ip4 layers.IPv4) bool {
	var (
		_, srcIsAccessTier = pr.hasAccessTierSourceRoute(ip4)
		dstIsTunnelIP      = ip4.DstIP.Equal(pr.adapter.TunnelIP())
	)

	return ip4.Protocol == layers.IPProtocolICMPv4 && srcIsAccessTier && dstIsTunnelIP
}

// maybeInfinitePingLoop captures the case where a rogue ping might come in on
// the interface IP. We'll just drop this packet if it shows up since it'll
// cause an infinite redirect inside the interface which Windows will detect
// and cause all traffic to the interface to drop. This is probably because of
// the TTL triggering.
func (pr *PacketRouting) maybeInfinitePingLoop(ip4 layers.IPv4) bool {
	return ip4.Protocol == layers.IPProtocolICMPv4 && ip4.SrcIP.Equal(pr.adapter.InterfaceIP()) && ip4.DstIP.Equal(pr.adapter.TunnelIP())
}

func (pr *PacketRouting) sendAsIs(session wintun.Session, packet []byte) error {
	var (
		payload   = packet
		totalSize = len(payload)
	)
	outgoingPacket, err := session.AllocateSendPacket(totalSize)
	if err != nil {
		return errors.Wrap(err, "send as-is")
	}

	copy(outgoingPacket, payload)
	session.SendPacket(outgoingPacket)
	return nil
}

func (pr *PacketRouting) passthrough(err error) bool {
	if strings.Contains(err.Error(), "Invalid (too small) IP header length") {
		return true
	}

	return false
}

func (pr *PacketRouting) nextCID() uint64 {
	pr.packetCounter.Add(1)
	return pr.packetCounter.Load()
}

func (pr *PacketRouting) handleGREDeencapsulation(cid uint64, session wintun.Session) error {
	rm := NewRequestMetadata(cid).WithOuterIP4(pr.ip4).WithAccessTierGREIP(pr.ip4.SrcIP)
	pr.adapter.logger.Debug(
		"handling inbound gre packet",
		"cid", cid)

	if err := pr.greDeencapsulator.UseSession(session).Handle(rm, pr.ip4.LayerPayload()); err != nil {
		return errors.Wrap(err, "gre deencapsulator")
	}

	return nil
}

func (pr *PacketRouting) handleUDPTraffic(cid uint64, session wintun.Session, packet []byte) error {
	if pr.maybeDNSPacket(*pr.ip4) {
		var (
			connectorIP, ok = pr.hasAccessTierSourceRoute(*pr.ip4)
			rm              = NewRequestMetadata(cid).WithOuterIP4(pr.ip4).WithAccessTierGREIP(pr.ip4.SrcIP).WithConnectorGREIP(connectorIP)
		)
		pr.adapter.logger.Debug(
			"handling inbound dns packet",
			"cid", cid,
			"connectorIP", connectorIP)

		if ok {
			if err := pr.dnsPacketInboundProxy.UseSession(session).Handle(rm, pr.ip4.LayerPayload()); err != nil {
				return errors.Wrap(err, "dns inbound proxy")
			}
		} else {
			if err := pr.sendAsIs(session, packet); err != nil {
				return err
			}
		}
	} else if accessTierIP, maybeDNSReturnPacket := pr.hasConnectorReturnRoute(*pr.ip4); maybeDNSReturnPacket {
		rm := NewRequestMetadata(cid).WithOuterIP4(pr.ip4).WithAccessTierGREIP(accessTierIP)
		pr.adapter.logger.Debug(
			"handling outbound dns packet",
			"cid", cid,
			"accessTierIP", accessTierIP)

		if err := pr.dnsPacketOutboundProxy.UseSession(session).Handle(rm, pr.ip4.LayerPayload()); err != nil {
			// If we're not dealing with a DNS packet, then we can treat this as a
			// regular UDP traffic that requires GRE encapsulation on the way back.
			if errors.Is(err, ErrCannotProxyDNS) {
				rm := NewRequestMetadata(cid).WithOuterIP4(pr.ip4).WithAccessTierGREIP(accessTierIP)
				pr.adapter.logger.Debug(
					"handling outbound gre packet",
					"cid", cid,
					"accessTierIP", accessTierIP)

				if err := pr.greEncapsulator.UseSession(session).Handle(rm, packet); err != nil {
					return errors.Wrap(err, "gre encapsulator")
				}
			} else {
				return errors.Wrap(err, "dns outbound proxy")
			}
		}
	} else {
		pr.adapter.logger.Debug(
			"handling generic udp packet",
			"cid", cid)

		if err := pr.sendAsIs(session, packet); err != nil {
			return err
		}
	}

	return nil
}

func (pr *PacketRouting) handleICMPTraffic(cid uint64, session wintun.Session, packet []byte) error {
	if pr.maybeInfinitePingLoop(*pr.ip4) {
		pr.adapter.logger.Warn(
			"infinite ping loop detected, dropping packet",
			"cid", cid,
			"ip4", pr.ip4)

		// NOOP
	} else if pr.maybeHealthCheck(*pr.ip4) {
		pr.adapter.logger.Debug(
			"handling health check",
			"cid", cid)

		if pr.icmp4PacketRequest.IsHealthCheckReply(pr.ip4.LayerPayload()) {
			pr.adapter.logger.Info(
				"got health check reply",
				"cid", cid,
				"ip4", pr.ip4)
			pr.healthCheck.AddReachable(pr.ip4.SrcIP)
		}

		// Black hole this packet since it's the return packet from a health
		// check. Maybe there's a better way to handle this but this should be
		// fine for now.
	} else if accessTierIP, requiresEncapsulation := pr.hasConnectorReturnRoute(*pr.ip4); requiresEncapsulation {
		rm := NewRequestMetadata(cid).WithOuterIP4(pr.ip4).WithAccessTierGREIP(accessTierIP)
		pr.adapter.logger.Debug(
			"handling outbound gre packet (icmp)",
			"cid", cid,
			"accessTierIP", accessTierIP)

		if err := pr.greEncapsulator.UseSession(session).Handle(rm, packet); err != nil {
			return errors.Wrap(err, "gre encapsulator")
		}
	} else {
		pr.adapter.logger.Debug(
			"handling generic icmp packet",
			"cid", cid)

		if err := pr.sendAsIs(session, packet); err != nil {
			return err
		}
	}

	return nil
}

func (pr *PacketRouting) handleGenericTraffic(cid uint64, session wintun.Session, packet []byte) error {
	if accessTierIP, requiresEncapsulation := pr.hasConnectorReturnRoute(*pr.ip4); requiresEncapsulation {
		rm := NewRequestMetadata(cid).WithOuterIP4(pr.ip4).WithAccessTierGREIP(accessTierIP)
		pr.adapter.logger.Debug(
			"handling outbound gre packet",
			"cid", cid,
			"accessTierIP", accessTierIP)

		if err := pr.greEncapsulator.UseSession(session).Handle(rm, packet); err != nil {
			return errors.Wrap(err, "gre encapsulator")
		}
	} else {
		pr.adapter.logger.Debug(
			"handling generic packet",
			"cid", cid)

		if err := pr.sendAsIs(session, packet); err != nil {
			return err
		}
	}

	return nil
}
