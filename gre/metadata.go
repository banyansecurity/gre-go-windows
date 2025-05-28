package gre

import (
	"net"

	"github.com/google/gopacket/layers"
)

type RequestMetadata struct {
	outerIP4        *layers.IPv4
	accessTierGREIP net.IP
	connectorGREIP  net.IP
}

func NewRequestMetadata() *RequestMetadata {
	return &RequestMetadata{}
}

func (rm *RequestMetadata) WithOuterIP4(outerIP4 *layers.IPv4) *RequestMetadata {
	rm.outerIP4 = outerIP4
	return rm
}

func (rm *RequestMetadata) OuterIP4() *layers.IPv4 {
	return rm.outerIP4
}

func (rm *RequestMetadata) WithAccessTierGREIP(accessTierGREIP net.IP) *RequestMetadata {
	rm.accessTierGREIP = accessTierGREIP
	return rm
}

func (rm *RequestMetadata) AccessTierGREIP() net.IP {
	return rm.accessTierGREIP
}

func (rm *RequestMetadata) WithConnectorGREIP(connectorGREIP net.IP) *RequestMetadata {
	rm.connectorGREIP = connectorGREIP
	return rm
}

func (rm *RequestMetadata) ConnectorGREIP() net.IP {
	return rm.connectorGREIP
}
