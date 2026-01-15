package health

import (
	"net"
	"sync"
	"time"

	"github.com/banyansecurity/gre-go-windows/utils"
)

type ReachablePeers struct {
	Dirty     bool
	Peers     []string
	StartTime time.Time
}

func NewReachablePeers() *ReachablePeers {
	return &ReachablePeers{
		Dirty:     true,
		Peers:     make([]string, 0),
		StartTime: time.Now(),
	}
}

type HealthCheck struct {
	sync.RWMutex
	numExpected   int
	current, next *ReachablePeers
}

func NewHealthCheck() *HealthCheck {
	hc := &HealthCheck{
		numExpected: 0,
	}
	go hc.promoter()
	return hc
}

const (
	pollInterval = 1 * time.Second
	timeout      = 5 * time.Minute
)

func (hc *HealthCheck) promoter() {
	defer utils.PanicCrash()

	for {
		time.Sleep(pollInterval)

		hc.Lock()
		var swap bool
		if hc.next != nil {
			if hc.next.Dirty && time.Now().After(hc.next.StartTime.Add(timeout)) {
				swap = true
			} else if !hc.next.Dirty {
				swap = true
			}
		}

		if swap {
			hc.current = hc.next
			hc.next = NewReachablePeers()
		}
		hc.Unlock()
	}
}

func (hc *HealthCheck) SetNumExpected(numExpected int) *HealthCheck {
	hc.Lock()
	defer hc.Unlock()

	hc.numExpected = numExpected
	return hc
}

func (hc *HealthCheck) NumExpected() int {
	hc.RLock()
	defer hc.RUnlock()

	return hc.numExpected
}

func (hc *HealthCheck) NumActual() int {
	hc.RLock()
	defer hc.RUnlock()

	if hc.current == nil {
		return 0
	}

	return len(hc.current.Peers)
}

func (hc *HealthCheck) AddReachable(ip net.IP) {
	hc.Lock()
	defer hc.Unlock()

	if hc.next == nil {
		hc.next = NewReachablePeers()
	}

	var (
		newIP   = ip.String()
		present bool
	)
	for _, peer := range hc.next.Peers {
		if peer == newIP {
			present = true
			break
		}
	}

	// Check if this IP is already in the peers before adding.
	if !present {
		hc.next.Peers = append(hc.next.Peers, newIP)
	}
	if len(hc.next.Peers) == hc.numExpected {
		hc.next.Dirty = false
	}
}

// Status returns the current reachable peers and whether we have a bad status.
// A bad status would be anything less than the number of expected peers. The
// string slice allows the caller to infer which peers are not reachable.
func (hc *HealthCheck) Status() ([]string, bool) {
	hc.RLock()
	defer hc.RUnlock()

	if hc.current == nil {
		return nil, false
	}

	return hc.current.Peers, len(hc.current.Peers) == hc.NumExpected()
}
