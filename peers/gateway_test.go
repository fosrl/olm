package peers

import (
	"reflect"
	"testing"
	"time"
)

// newGatewayTestManager returns a PeerManager with gateway mode marked active
// for siteResourceId with the given candidate sites, without touching the OS
// routing table or a WireGuard device. Only usable for paths that don't need
// either (sites that aren't tracked peers, no owner of the gateway CIDR).
func newGatewayTestManager(siteResourceId int, siteIds ...int) *PeerManager {
	pm := &PeerManager{
		peers:                 make(map[int]SiteConfig),
		allowedIPOwners:       make(map[string]int),
		allowedIPClaims:       make(map[string]map[int]bool),
		lastOwnerChange:       make(map[string]time.Time),
		gatewaySiteIds:        make(map[int]bool),
		gatewayExcludedIPs:    make(map[string]int),
		gatewayExtraEndpoints: make(map[string]bool),
		gatewayActive:         true,
		gatewaySiteResourceId: siteResourceId,
	}
	for _, id := range siteIds {
		pm.gatewaySiteIds[id] = true
	}
	return pm
}

func TestUpdateGatewaySitesIgnoresOtherResource(t *testing.T) {
	pm := newGatewayTestManager(5, 1)

	matched, active, siteIds := pm.UpdateGatewaySites(6, []int{2}, nil)
	if matched {
		t.Fatalf("update for a different resource must not match")
	}
	if !active || !reflect.DeepEqual(siteIds, []int{1}) {
		t.Fatalf("state must be unchanged, got active=%v siteIds=%v", active, siteIds)
	}
}

func TestUpdateGatewaySitesInactive(t *testing.T) {
	pm := newGatewayTestManager(5, 1)
	pm.gatewayActive = false

	if matched, _, _ := pm.UpdateGatewaySites(5, []int{2}, nil); matched {
		t.Fatalf("update must not match when gateway mode is inactive")
	}
}

func TestUpdateGatewaySitesAddRemove(t *testing.T) {
	pm := newGatewayTestManager(5, 1)

	matched, active, siteIds := pm.UpdateGatewaySites(5, []int{2, 3}, nil)
	if !matched || !active || !reflect.DeepEqual(siteIds, []int{1, 2, 3}) {
		t.Fatalf("add: matched=%v active=%v siteIds=%v", matched, active, siteIds)
	}

	matched, active, siteIds = pm.UpdateGatewaySites(5, nil, []int{2})
	if !matched || !active || !reflect.DeepEqual(siteIds, []int{1, 3}) {
		t.Fatalf("remove: matched=%v active=%v siteIds=%v", matched, active, siteIds)
	}

	// removed wins over added if a message lists an ID in both
	_, _, siteIds = pm.UpdateGatewaySites(5, []int{4}, []int{4})
	if !reflect.DeepEqual(siteIds, []int{1, 3}) {
		t.Fatalf("add+remove of the same ID must leave it out, got %v", siteIds)
	}
}

func TestClearGatewayForResourceIgnoresOtherResource(t *testing.T) {
	pm := newGatewayTestManager(5, 1)

	if pm.ClearGatewayForResource(6) {
		t.Fatalf("clearing for a different resource must not match")
	}
	if active, id, _ := pm.GetGatewayState(); !active || id != 5 {
		t.Fatalf("state must be unchanged, got active=%v resource=%d", active, id)
	}
}
