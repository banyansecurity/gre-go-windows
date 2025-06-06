package gre

import (
	"fmt"
	"net"

	"github.com/google/gopacket/layers"
)

type RequestMetadata struct {
	cid             uint64
	outerIP4        *layers.IPv4
	accessTierGREIP net.IP
	connectorGREIP  net.IP
}

func NewRequestMetadata(cid uint64) *RequestMetadata {
	return &RequestMetadata{
		cid: cid,
	}
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

func (rm *RequestMetadata) String() string {
	return fmt.Sprintf(
		"{cid: %s, outerIP4: (%+v), accessTierGREIP: %s, connectorGREIP: %s}",
		rm.cid, rm.outerIP4, rm.accessTierGREIP.String(), rm.connectorGREIP.String())
}
