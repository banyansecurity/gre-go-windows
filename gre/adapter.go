package gre

import (
	"errors"
	"fmt"
	"log/slog"
	"math"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/puzpuzpuz/xsync"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.zx2c4.com/wintun"
)

var (
	greLogFileName = filepath.Join("Logs", "gre.log")
)

const (
	defaultAdapterName = "mgre1"
	wintunTunnelType   = "Wintun"
	sessionCapacity    = 0x400000
	profilesPath       = "Software\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles"
)

type (
	GREAdapter struct {
		sync.RWMutex
		logFile       *os.File
		logger        *slog.Logger
		name          string
		guid          *windows.GUID
		luid          uint64
		adapter       *wintun.Adapter
		validSrcs     *xsync.MapOf[string, net.IP]
		validDsts     *xsync.MapOf[string, net.IP]
		tunnelIP      net.IP
		dnsIP         net.IP
		shutdownChans []chan struct{}
		shutdownGroup sync.WaitGroup
		counter       uint16
	}
)

func NewDefaultGREAdapter() (*GREAdapter, error) {
	return NewGREAdapter(defaultAdapterName)
}

func NewGREAdapter(adapterName string) (*GREAdapter, error) {
	_ = wintun.Uninstall()
	_ = removeOrphanedProfile(adapterName)

	logFile, err := os.OpenFile(greLogFileName, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, err
	}

	logger := slog.New(slog.NewJSONHandler(logFile, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))

	guid, err := windows.GenerateGUID()
	if err != nil {
		return nil, err
	}

	adapter, err := wintun.CreateAdapter(adapterName, wintunTunnelType, &guid)
	if err != nil {
		return nil, err
	}

	logger.Info(
		"created adapter",
		"luid", adapter.LUID())
	return &GREAdapter{
		logFile:   logFile,
		logger:    logger,
		name:      adapterName,
		guid:      &guid,
		luid:      adapter.LUID(),
		adapter:   adapter,
		validSrcs: xsync.NewTypedMapOf[string, net.IP](xsync.StrHash64),
		validDsts: xsync.NewTypedMapOf[string, net.IP](xsync.StrHash64),
		counter:   uint16(rand.Intn(math.MaxUint16 + 1)),
	}, nil
}

func (a *GREAdapter) WithDNSIP(dnsIP net.IP) *GREAdapter {
	a.Lock()
	defer a.Unlock()

	a.dnsIP = dnsIP
	return a
}

func (a *GREAdapter) DNSIP() net.IP {
	a.RLock()
	defer a.RUnlock()

	return a.dnsIP
}

func (a *GREAdapter) WithTunnelIP(tunnelIP net.IP) *GREAdapter {
	a.Lock()
	defer a.Unlock()

	a.tunnelIP = tunnelIP
	return a
}

func (a *GREAdapter) TunnelIP() net.IP {
	a.RLock()
	defer a.RUnlock()

	return a.tunnelIP
}

func (a *GREAdapter) Name() string {
	a.RLock()
	defer a.RUnlock()

	return a.name
}

func (a *GREAdapter) GUID() *windows.GUID {
	a.RLock()
	defer a.RUnlock()

	return a.guid
}

func (a *GREAdapter) LUID() uint64 {
	a.RLock()
	defer a.RUnlock()

	return a.luid
}

func (a *GREAdapter) Adapter() *wintun.Adapter {
	a.RLock()
	defer a.RUnlock()

	return a.adapter
}

func (a *GREAdapter) Start() {
	a.Lock()
	defer a.Unlock()

	shutdownChan := make(chan struct{})
	a.shutdownChans = append(a.shutdownChans, shutdownChan)

	a.shutdownGroup.Add(1)
	go a.sessionRunner(shutdownChan)
}

func (a *GREAdapter) Close() error {
	a.Lock()
	defer a.Unlock()

	defer a.shutdownGroup.Wait()
	defer func() {
		_ = wintun.Uninstall()
		_ = removeOrphanedProfile(a.name)
		_ = a.logFile.Close()
	}()

	for _, shutdownChan := range a.shutdownChans {
		close(shutdownChan)
	}

	return a.adapter.Close()
}

func (a *GREAdapter) AddAccessTierSourceRoute(accessTierSide, connectorSide net.IP) {
	a.validSrcs.Store(accessTierSide.String(), connectorSide)
}

func (a *GREAdapter) RemoveAccessTierSourceRoute(accessTierSide net.IP) {
	a.validSrcs.Delete(accessTierSide.String())
}

func (a *GREAdapter) AddConnectorReturnRoute(connectorSide, accessTierSide net.IP) {
	a.validDsts.Store(connectorSide.String(), accessTierSide)
}

func (a *GREAdapter) RemoveConnectorReturnRoute(connectorSide net.IP) {
	a.validDsts.Delete(connectorSide.String())
}

const missThreshold = 10

func (a *GREAdapter) sessionRunner(shutdownChan chan struct{}) {
	defer a.shutdownGroup.Done()
	session, err := a.adapter.StartSession(sessionCapacity)
	if err != nil {
		a.logger.Warn(
			"error starting session",
			"error", err)
		return
	}
	defer session.End()

	// Note: Prefer to preallocate *whatever* we can on the stack. This will
	// generally improve performance here when we don't spin on allocations
	// for each packet.
	var (
		ip4      layers.IPv4
		ipParser = gopacket.NewDecodingLayerParser(layers.LayerTypeIPv4, &ip4)
		decoded  = make([]gopacket.LayerType, 1)
	)
	ipParser.IgnoreUnsupported = true

forever:
	for {
		select {
		case <-shutdownChan:
			break forever
		default:
		}

		// This is the primary notification mechanism for us to wake up and
		// receive packets. Note that although we get a single notification here,
		// there are likely multiple packets that we're able to receive at once.
		if _, err := windows.WaitForSingleObject(session.ReadWaitEvent(), windows.INFINITE); err != nil {
			a.logger.Warn(
				"error waiting for read wait event",
				"error", err)
			continue
		}

		// The inner loop spins on receiving packets multiple times before we fall
		// back to waiting for a notification for performance reasons.
		var consecutiveMisses int
		for {
			if consecutiveMisses >= missThreshold {
				break
			}

			packet, err := session.ReceivePacket()
			if err != nil {
				consecutiveMisses++
				continue
			} else {
				consecutiveMisses = 0
			}

			if err := ipParser.DecodeLayers(packet, &decoded); err != nil {
				goto cleanupReceivePacket
			}

			switch ip4.Protocol {
			case layers.IPProtocolGRE:
				a.logger.Debug(
					"deencapsulating gre packet",
					"src", ip4.SrcIP,
					"dst", ip4.DstIP)
				if err := a.handleInboundGRE(session, ip4.LayerPayload()); err != nil {
					a.logger.Warn(
						"error handling inbound gre payload",
						"error", err)
					goto cleanupReceivePacket
				}
			case layers.IPProtocolUDP:
				if a.maybeRequiresOutboundProxying(ip4) {
					if err := a.proxyInboundUDP(session, ip4.LayerPayload(), ip4); err != nil {
						a.logger.Warn(
							"error handling inbound udp payload",
							"error", err)
						goto cleanupReceivePacket
					}
				} else if accessTierIP, requiresProxying := a.hasConnectorReturnRoute(ip4); requiresProxying {
					if err := a.proxyOutboundUDP(session, ip4.LayerPayload(), accessTierIP); err != nil {
						a.logger.Warn(
							"error handling outbound udp payload",
							"error", err)
						goto cleanupReceivePacket
					}
				}
			default:
				if accessTierGREDst, requiresEncapsulation := a.hasConnectorReturnRoute(ip4); requiresEncapsulation {
					a.logger.Debug(
						"encapsulating gre packet",
						"src", ip4.SrcIP,
						"dst", ip4.DstIP)
					if err := a.handleOutboundGRE(session, packet, accessTierGREDst); err != nil {
						a.logger.Warn(
							"error handling outbound gre payload",
							"error", err)
						goto cleanupReceivePacket
					}
				}
			}

		cleanupReceivePacket:
			session.ReleaseReceivePacket(packet)
		} // inner loop
	} // forever loop
}

func (a *GREAdapter) hasAccessTierSourceRoute(ip4 layers.IPv4) (net.IP, bool) {
	return a.validSrcs.Load(ip4.SrcIP.String())
}

func (a *GREAdapter) hasConnectorReturnRoute(ip4 layers.IPv4) (net.IP, bool) {
	return a.validDsts.Load(ip4.DstIP.String())
}

func (a *GREAdapter) maybeRequiresOutboundProxying(ip4 layers.IPv4) bool {
	return ip4.Protocol == layers.IPProtocolUDP && ip4.DstIP.Equal(a.TunnelIP())
}

func (a *GREAdapter) handleInboundGRE(session wintun.Session, packet []byte) error {
	var (
		gre       layers.GRE
		greParser = gopacket.NewDecodingLayerParser(layers.LayerTypeGRE, &gre)
		decoded   = make([]gopacket.LayerType, 1)
	)
	greParser.IgnoreUnsupported = true
	if err := greParser.DecodeLayers(packet, &decoded); err != nil {
		return err
	}

	var (
		payload   = gre.LayerPayload()
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

func (a *GREAdapter) handleOutboundGRE(session wintun.Session, packet []byte, dst net.IP) error {
	var (
		ip4 layers.IPv4
		gre layers.GRE
	)
	ip4.Version = 4
	ip4.Id = a.nextCounter()
	ip4.Flags = layers.IPv4DontFragment
	ip4.TTL = 64
	ip4.Protocol = layers.IPProtocolGRE
	ip4.SrcIP = a.TunnelIP()
	ip4.DstIP = dst

	gre.KeyPresent = true
	gre.Protocol = 0x0800
	gre.Key = 0x000004D2

	var (
		buf  = gopacket.NewSerializeBuffer()
		opts = gopacket.SerializeOptions{
			ComputeChecksums: true,
			FixLengths:       true,
		}
		payload = gopacket.Payload(packet)
	)
	if err := gopacket.SerializeLayers(buf, opts, &ip4, &gre, payload); err != nil {
		return err
	}

	var (
		returnPacketBytes = buf.Bytes()
		totalSize         = len(returnPacketBytes)
	)
	outgoingPacket, err := session.AllocateSendPacket(totalSize)
	if err != nil {
		return err
	}

	copy(outgoingPacket, returnPacketBytes)
	session.SendPacket(outgoingPacket)
	return nil
}

var (
	ErrCannotProxy = errors.New("cannot proxy")
)

func (a *GREAdapter) proxyInboundUDP(session wintun.Session, packet []byte, outerIP4 layers.IPv4) error {
	var (
		ip4       layers.IPv4
		udp       layers.UDP
		udpParser = gopacket.NewDecodingLayerParser(layers.LayerTypeUDP, &udp)
		decoded   = make([]gopacket.LayerType, 1)
	)
	udpParser.IgnoreUnsupported = true
	if err := udpParser.DecodeLayers(packet, &decoded); err != nil {
		return err
	}

	// We only handle proxying for outbound DNS payloads here.
	connectorIP, canProxy := a.hasAccessTierSourceRoute(outerIP4)
	if udp.DstPort != 53 || !canProxy {
		return ErrCannotProxy
	}

	ip4.Version = 4
	ip4.Id = a.nextCounter()
	ip4.Flags = layers.IPv4DontFragment
	ip4.TTL = 64
	ip4.Protocol = layers.IPProtocolUDP
	ip4.SrcIP = connectorIP
	ip4.DstIP = a.DNSIP()

	udp.Checksum = 0
	udp.SetNetworkLayerForChecksum(&ip4)

	var (
		buf  = gopacket.NewSerializeBuffer()
		opts = gopacket.SerializeOptions{
			ComputeChecksums: true,
			FixLengths:       true,
		}
		payload = gopacket.Payload(udp.LayerPayload())
	)
	if err := gopacket.SerializeLayers(buf, opts, &ip4, &udp, payload); err != nil {
		return err
	}

	var (
		returnPacketBytes = buf.Bytes()
		totalSize         = len(returnPacketBytes)
	)
	outgoingPacket, err := session.AllocateSendPacket(totalSize)
	if err != nil {
		return err
	}

	copy(outgoingPacket, returnPacketBytes)
	session.SendPacket(outgoingPacket)
	return nil
}

func (a *GREAdapter) proxyOutboundUDP(session wintun.Session, packet []byte, dst net.IP) error {
	var (
		outerIP4  layers.IPv4
		gre       layers.GRE
		ip4       layers.IPv4
		udp       layers.UDP
		udpParser = gopacket.NewDecodingLayerParser(layers.LayerTypeUDP, &udp)
		decoded   = make([]gopacket.LayerType, 1)
	)
	udpParser.IgnoreUnsupported = true
	if err := udpParser.DecodeLayers(packet, &decoded); err != nil {
		return err
	}

	// We only handle proxying for inbound DNS payloads here.
	if udp.SrcPort != 53 {
		return ErrCannotProxy
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
	outerIP4.Version = 4
	outerIP4.Id = a.nextCounter()
	outerIP4.Flags = layers.IPv4DontFragment
	outerIP4.TTL = 64
	outerIP4.Protocol = layers.IPProtocolGRE
	outerIP4.SrcIP = a.TunnelIP()
	outerIP4.DstIP = dst

	gre.KeyPresent = true
	gre.Protocol = 0x0800
	gre.Key = 0x000004D2

	ip4.Version = 4
	ip4.Id = a.nextCounter()
	ip4.Flags = layers.IPv4DontFragment
	ip4.TTL = 64
	ip4.Protocol = layers.IPProtocolUDP
	ip4.SrcIP = a.TunnelIP()
	ip4.DstIP = dst

	udp.Checksum = 0
	udp.SetNetworkLayerForChecksum(&ip4)

	var (
		buf  = gopacket.NewSerializeBuffer()
		opts = gopacket.SerializeOptions{
			ComputeChecksums: true,
			FixLengths:       true,
		}
		payload = gopacket.Payload(udp.LayerPayload())
	)
	if err := gopacket.SerializeLayers(buf, opts, &outerIP4, &gre, &ip4, &udp, payload); err != nil {
		return err
	}

	var (
		returnPacketBytes = buf.Bytes()
		totalSize         = len(returnPacketBytes)
	)
	outgoingPacket, err := session.AllocateSendPacket(totalSize)
	if err != nil {
		return err
	}

	copy(outgoingPacket, returnPacketBytes)
	session.SendPacket(outgoingPacket)
	return nil
}

func (a *GREAdapter) nextCounter() uint16 {
	defer func() {
		a.counter++
	}()

	if a.counter > math.MaxUint16 {
		a.counter = 0
	}

	return a.counter
}

func removeOrphanedProfile(adapterName string) error {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, profilesPath, registry.ALL_ACCESS)
	if err != nil {
		return err
	}

	subKeys, err := key.ReadSubKeyNames(0)
	if err != nil {
		return err
	}

	for _, k := range subKeys {
		profileKey, err := registry.OpenKey(registry.LOCAL_MACHINE, fmt.Sprintf("%s\\%s", profilesPath, k), registry.ALL_ACCESS)
		if err != nil {
			return err
		}

		profileName, _, err := profileKey.GetStringValue("ProfileName")
		if err != nil {
			return err
		}

		if strings.Contains(profileName, adapterName) {
			if err := registry.DeleteKey(registry.LOCAL_MACHINE, fmt.Sprintf("%s\\%s", profilesPath, k)); err != nil {
				return err
			}
		}
	}

	return nil
}
