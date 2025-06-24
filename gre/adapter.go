package gre

import (
	"fmt"
	"log/slog"
	"math"
	"math/rand"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.zx2c4.com/wintun"
	"gopkg.in/natefinch/lumberjack.v2"
)

var (
	greLogFileName = filepath.Join("Logs", "gre.log")
)

const (
	defaultAdapterName = "mgre1"
	wintunTunnelType   = "Wintun"
	sessionCapacity    = 0x800000
	profilesPath       = "Software\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles"
)

type (
	GREAdapter struct {
		sync.RWMutex
		logger        *slog.Logger
		name          string
		guid          *windows.GUID
		luid          uint64
		adapter       *wintun.Adapter
		tunnelIP      net.IP
		dnsIP         net.IP
		interfaceIP   net.IP
		shutdownChans []chan struct{}
		shutdownGroup sync.WaitGroup
		counter       uint16
		router        *PacketRouting
	}
)

func NewDefaultGREAdapter() (*GREAdapter, error) {
	return NewGREAdapter(defaultAdapterName)
}

func NewGREAdapter(adapterName string) (*GREAdapter, error) {
	_ = wintun.Uninstall()
	_ = removeOrphanedProfile(adapterName)

	var (
		ljLogger = &lumberjack.Logger{
			Filename:   greLogFileName,
			MaxSize:    5,
			MaxBackups: 2,
			MaxAge:     28,
		}
		_      = ljLogger.Rotate()
		logger = slog.New(slog.NewJSONHandler(ljLogger, &slog.HandlerOptions{
			AddSource: true,
			Level:     slog.LevelWarn,
		}))
	)

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
	greAdapter := &GREAdapter{
		logger:  logger,
		name:    adapterName,
		guid:    &guid,
		luid:    adapter.LUID(),
		adapter: adapter,
		counter: uint16(rand.Intn(math.MaxUint16 + 1)),
	}
	greAdapter.router = NewPacketRouting(greAdapter)
	return greAdapter, nil
}

func (a *GREAdapter) PacketRouting() *PacketRouting {
	return a.router
}

func (a *GREAdapter) Status() ([]string, bool) {
	return a.router.HealthCheck()
}

func (a *GREAdapter) WithInterfaceIP(interfaceIP net.IP) *GREAdapter {
	a.Lock()
	defer a.Unlock()

	a.interfaceIP = interfaceIP
	return a
}

func (a *GREAdapter) InterfaceIP() net.IP {
	a.RLock()
	defer a.RUnlock()

	return a.interfaceIP
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

	a.shutdownGroup.Add(2)
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

const missThreshold = 10_000_000

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

	go a.pinger(session, shutdownChan)

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

			if err := a.router.Route(session, packet); err != nil {
				a.logger.Warn(
					"error routing packet",
					"error", err)
			}

			session.ReleaseReceivePacket(packet)
		} // inner loop
	} // forever loop

	a.logger.Info("session runner shutting down")
}

const pingInterval = 2 * time.Minute

func (a *GREAdapter) pinger(session wintun.Session, shutdownChan chan struct{}) {
	defer a.shutdownGroup.Done()
	ticker := time.NewTicker(pingInterval)

forever:
	for {
		a.router.PingAccessTiers(session)

		select {
		case <-shutdownChan:
			break forever
		case <-ticker.C:
		}
	} // forever loop

	a.logger.Info("pinger shutting down")
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
