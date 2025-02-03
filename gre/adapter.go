package gre

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"

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
	logger        *slog.Logger
	name          string
	luid          uint64
	adapter       *wintun.Adapter
	shutdownChans []chan struct{}
	shutdownGroup sync.WaitGroup
}

func NewDefaultGREAdapter() (*GREAdapter, error) {
	return NewGREAdapter(defaultAdapterName)
}

func NewGREAdapter(adapterName string) (*GREAdapter, error) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if existingAdapter, err := wintun.OpenAdapter(adapterName); err == nil {
		logger.Info(
			"opened existing adapter",
			"luid", existingAdapter.LUID())
		return &GREAdapter{
			logger:  logger,
			name:    adapterName,
			luid:    existingAdapter.LUID(),
			adapter: existingAdapter,
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
		logger:  logger,
		name:    adapterName,
		luid:    adapter.LUID(),
		adapter: adapter,
	}, nil

}

func (a *GREAdapter) LUID() uint64 {
	return a.luid
}

func (a *GREAdapter) Adapter() *wintun.Adapter {
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
	defer a.shutdownGroup.Wait()
	defer wintun.Uninstall()
	defer removeOrphanedProfile(a.name)

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

forever:
	for {
		select {
		case <-shutdownChan:
			break forever
		default:
		}

		windows.WaitForSingleObject(session.ReadWaitEvent(), windows.INFINITE)
	}
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
