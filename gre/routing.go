package gre

import (
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
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
		icmp4PacketReplyProxy  *ICMP4PacketReplyProxy
		validSrcs              *xsync.MapOf[string, net.IP]
		validDsts              *xsync.MapOf[string, net.IP]
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
		icmp4PacketReplyProxy:  NewICMP4PacketReplyProxy(adapter),
		validSrcs:              xsync.NewTypedMapOf[string, net.IP](xsync.StrHash64),
		validDsts:              xsync.NewTypedMapOf[string, net.IP](xsync.StrHash64),
	}
}

func (pr *PacketRouting) Route(session wintun.Session, packet []byte) error {
	if err := pr.ipParser.DecodeLayers(packet, &pr.decoded); err != nil {
		return err
	}

	pr.adapter.logger.Debug(
		"handling packet",
		"ip4", pr.ip4,
	)

	switch pr.ip4.Protocol {
	case layers.IPProtocolGRE:
		rm := NewRequestMetadata().WithOuterIP4(pr.ip4).WithAccessTierGREIP(pr.ip4.SrcIP)
		if err := pr.greDeencapsulator.UseSession(session).Handle(rm, pr.ip4.LayerPayload()); err != nil {
			return err
		}
	case layers.IPProtocolUDP:
		if pr.maybeDNSPacket(*pr.ip4) {
			var (
				connectorIP, _ = pr.hasAccessTierSourceRoute(*pr.ip4)
				rm             = NewRequestMetadata().WithOuterIP4(pr.ip4).WithAccessTierGREIP(pr.ip4.SrcIP).WithConnectorGREIP(connectorIP)
			)
			if err := pr.dnsPacketInboundProxy.UseSession(session).Handle(rm, pr.ip4.LayerPayload()); err != nil {
				return err
			}
		} else if accessTierIP, maybeDNSReturnPacket := pr.hasConnectorReturnRoute(*pr.ip4); maybeDNSReturnPacket {
			rm := NewRequestMetadata().WithOuterIP4(pr.ip4).WithAccessTierGREIP(accessTierIP)
			if err := pr.dnsPacketOutboundProxy.UseSession(session).Handle(rm, pr.ip4.LayerPayload()); err != nil {
				return err
			}
		} else {
			if err := pr.sendAsIs(session, packet); err != nil {
				return err
			}
		}
	default:
		if accessTierIP, requiresEncapsulation := pr.hasConnectorReturnRoute(*pr.ip4); requiresEncapsulation {
			rm := NewRequestMetadata().WithOuterIP4(pr.ip4).WithAccessTierGREIP(accessTierIP)
			if err := pr.greEncapsulator.UseSession(session).Handle(rm, packet); err != nil {
				return err
			}
		} else {
			if err := pr.sendAsIs(session, packet); err != nil {
				return err
			}
		}
	}

	return nil
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

func (pr *PacketRouting) maybePingPacket(ip4 layers.IPv4) bool {
	return ip4.Protocol == layers.IPProtocolICMPv4 && ip4.DstIP.Equal(pr.adapter.TunnelIP())
}

func (pr *PacketRouting) sendAsIs(session wintun.Session, packet []byte) error {
	var (
		payload   = packet
		totalSize = len(payload)
	)
	outgoingPacket, err := session.AllocateSendPacket(totalSize)
	if err != nil {
		return err
	}

	copy(outgoingPacket, payload)
	session.SendPacket(outgoingPacket)
	return nil
}
