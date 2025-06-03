package gre

import (
	"net"
	"strings"

	"github.com/banyansecurity/gre-go-windows/health"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/puzpuzpuz/xsync"
	"golang.zx2c4.com/wintun"
)

type (
	PacketRouting struct {
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

	cid := uuid.New().String()
	pr.adapter.logger.Debug(
		"handling packet",
		"cid", cid,
		"ip4", pr.ip4,
	)

	switch pr.ip4.Protocol {
	case layers.IPProtocolGRE:
		rm := NewRequestMetadata(cid).WithOuterIP4(pr.ip4).WithAccessTierGREIP(pr.ip4.SrcIP)
		pr.adapter.logger.Debug(
			"handling inbound gre packet",
			"metadata", rm.String(),
		)

		if err := pr.greDeencapsulator.UseSession(session).Handle(rm, pr.ip4.LayerPayload()); err != nil {
			return errors.Wrap(err, "gre deencapsulator")
		}
	case layers.IPProtocolUDP:
		if pr.maybeDNSPacket(*pr.ip4) {
			var (
				connectorIP, ok = pr.hasAccessTierSourceRoute(*pr.ip4)
				rm              = NewRequestMetadata(cid).WithOuterIP4(pr.ip4).WithAccessTierGREIP(pr.ip4.SrcIP).WithConnectorGREIP(connectorIP)
			)
			pr.adapter.logger.Debug(
				"handling inbound dns packet",
				"metadata", rm.String(),
				"connectorIP", connectorIP,
			)

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
				"metadata", rm.String(),
				"accessTierIP", accessTierIP,
			)

			if err := pr.dnsPacketOutboundProxy.UseSession(session).Handle(rm, pr.ip4.LayerPayload()); err != nil {
				return errors.Wrap(err, "dns outbound proxy")
			}
		} else {
			pr.adapter.logger.Debug(
				"handling generic udp packet",
				"cid", cid,
			)

			if err := pr.sendAsIs(session, packet); err != nil {
				return err
			}
		}
	case layers.IPProtocolICMPv4:
		if pr.maybeHealthCheck(*pr.ip4) {
			pr.adapter.logger.Debug(
				"handling health check",
				"cid", cid,
			)

			if pr.icmp4PacketRequest.IsHealthCheckReply(pr.ip4.LayerPayload()) {
				pr.adapter.logger.Debug(
					"got health check reply",
					"cid", cid,
					"ip4", pr.ip4,
				)
				pr.healthCheck.AddReachable(pr.ip4.SrcIP)
			}

			// Black hole this packet since it's the return packet from a health
			// check. Maybe there's a better way to handle this but this should be
			// fine for now.
			return nil
		} else if accessTierIP, requiresEncapsulation := pr.hasConnectorReturnRoute(*pr.ip4); requiresEncapsulation {
			rm := NewRequestMetadata(cid).WithOuterIP4(pr.ip4).WithAccessTierGREIP(accessTierIP)
			pr.adapter.logger.Debug(
				"handling outbound gre packet (icmp)",
				"metadata", rm.String(),
				"accessTierIP", accessTierIP,
			)

			if err := pr.greEncapsulator.UseSession(session).Handle(rm, packet); err != nil {
				return errors.Wrap(err, "gre encapsulator")
			}
		} else {
			pr.adapter.logger.Debug(
				"handling generic icmp packet",
				"cid", cid,
			)

			if err := pr.sendAsIs(session, packet); err != nil {
				return err
			}
		}
	default:
		if accessTierIP, requiresEncapsulation := pr.hasConnectorReturnRoute(*pr.ip4); requiresEncapsulation {
			rm := NewRequestMetadata(cid).WithOuterIP4(pr.ip4).WithAccessTierGREIP(accessTierIP)
			pr.adapter.logger.Debug(
				"handling outbound gre packet",
				"metadata", rm.String(),
				"accessTierIP", accessTierIP,
			)

			if err := pr.greEncapsulator.UseSession(session).Handle(rm, packet); err != nil {
				return errors.Wrap(err, "gre encapsulator")
			}
		} else {
			pr.adapter.logger.Debug(
				"handling generic packet",
				"cid", cid,
			)

			if err := pr.sendAsIs(session, packet); err != nil {
				return err
			}
		}
	}

	return nil
}

func (pr *PacketRouting) PingAccessTiers(session wintun.Session) {
	pr.healthCheck.SetNumExpected(pr.adapter.router.validSrcs.Size())

	src := pr.adapter.tunnelIP
	pr.adapter.router.validSrcs.Range(func(atGREIP string, _ net.IP) bool {
		dst := net.ParseIP(atGREIP)
		pr.adapter.logger.Debug(
			"pinging access tier",
			"src", src,
			"dst", dst,
		)
		pr.icmp4PacketRequest.UseSession(session).HandleRequest(src, dst)
		return true
	})
}

func (pr *PacketRouting) HealthCheck() ([]string, bool) {
	return pr.healthCheck.Status()
}

func (pr *PacketRouting) AddAccessTierSourceRoute(accessTierSide, connectorSide net.IP) {
	pr.validSrcs.Store(accessTierSide.String(), connectorSide)
}

func (pr *PacketRouting) RemoveAccessTierSourceRoute(accessTierSide net.IP) {
	pr.validSrcs.Delete(accessTierSide.String())
}

func (pr *PacketRouting) AddConnectorReturnRoute(connectorSide, accessTierSide net.IP) {
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
