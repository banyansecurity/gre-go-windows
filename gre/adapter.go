package gre

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.zx2c4.com/wintun"
)

const (
	defaultAdapterName = "gre0"
	wintunTunnelType   = "Wintun"
	sessionCapacity    = 0x400000
	profilesPath       = "Software\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles"
)

type GREAdapter struct {
	sync.RWMutex
	logger              *slog.Logger
	name                string
	luid                uint64
	adapter             *wintun.Adapter
	thisSide, otherSide net.IP
	shutdownChans       []chan struct{}
	shutdownGroup       sync.WaitGroup
}

func NewDefaultGREAdapter() (*GREAdapter, error) {
	return NewGREAdapter(defaultAdapterName, nil, nil)
}

func NewGREAdapter(adapterName string, thisSide, otherSide net.IP) (*GREAdapter, error) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))
	if existingAdapter, err := wintun.OpenAdapter(adapterName); err == nil {
		logger.Info(
			"opened existing adapter",
			"luid", existingAdapter.LUID())
		return &GREAdapter{
			logger:    logger,
			name:      adapterName,
			luid:      existingAdapter.LUID(),
			adapter:   existingAdapter,
			thisSide:  thisSide,
			otherSide: otherSide,
		}, nil
	}

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
		logger:    logger,
		name:      adapterName,
		luid:      adapter.LUID(),
		adapter:   adapter,
		thisSide:  thisSide,
		otherSide: otherSide,
	}, nil

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
	}()

	for _, shutdownChan := range a.shutdownChans {
		close(shutdownChan)
	}

	return a.adapter.Close()
}

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
		llc           layers.LLC
		gre           layers.GRE
		ip4           layers.IPv4
		payload       gopacket.Payload
		decodedLayers []gopacket.LayerType
		parser        = gopacket.NewDecodingLayerParser(layers.LayerTypeGRE, &llc, &gre, &ip4, &payload)
		buf           = gopacket.NewSerializeBuffer()
	)

forever:
	for {
		select {
		case <-shutdownChan:
			break forever
		default:
		}

		if _, err := windows.WaitForSingleObject(session.ReadWaitEvent(), windows.INFINITE); err != nil {
			a.logger.Warn(
				"error waiting for read wait event",
				"error", err)
			continue
		}

		packet, err := session.ReceivePacket()
		if err != nil {
			a.logger.Warn(
				"error receiving packet",
				"error", err)
			continue
		}

		if err := parser.DecodeLayers(packet, &decodedLayers); err != nil {
			a.logger.Warn(
				"error decoding layers",
				"error", err)
			goto cleanupReceivePacket
		}

		for _, layer := range decodedLayers {
			switch layer {
			case layers.LayerTypeGRE:
				if gre.Protocol != layers.EthernetTypeIPv4 {
					continue
				}
			}
		}

		if ip4.SrcIP.Equal(a.otherSide) && ip4.DstIP.Equal(a.thisSide) {
			if err := a.deencapsulate(buf, payload); err != nil {
				a.logger.Warn(
					"error deencapsulating packet",
					"error", err)
				goto cleanupReceivePacket
			}
		} else {
			if err := a.encapsulate(buf, ip4, payload); err != nil {
				a.logger.Warn(
					"error encapsulating packet",
					"error", err)
				goto cleanupReceivePacket
			}
		}
		session.SendPacket(buf.Bytes())

	cleanupReceivePacket:
		session.ReleaseReceivePacket(packet)
	}
}

func (a *GREAdapter) deencapsulate(buf gopacket.SerializeBuffer, payload gopacket.Payload) error {
	if err := payload.SerializeTo(buf, gopacket.SerializeOptions{
		FixLengths:       false,
		ComputeChecksums: false,
	}); err != nil {
		return err
	}

	return nil
}

func (a *GREAdapter) encapsulate(buf gopacket.SerializeBuffer, ip4 layers.IPv4, payload gopacket.Payload) error {
	returnOpts := gopacket.SerializeOptions{
		FixLengths:       false,
		ComputeChecksums: true,
	}
	if err := payload.SerializeTo(buf, returnOpts); err != nil {
		return err
	}

	ip4.SrcIP = a.thisSide
	ip4.DstIP = a.otherSide
	if err := ip4.SerializeTo(buf, returnOpts); err != nil {
		return err
	}

	gre := layers.GRE{
		ChecksumPresent: true,
		Protocol:        layers.EthernetTypeIPv4,
	}
	if err := gre.SerializeTo(buf, returnOpts); err != nil {
		return err
	}

	return nil
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
