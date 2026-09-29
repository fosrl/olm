package peers

import "testing"

// newExitNodeTestManager returns a PeerManager for exercising the
// DisableRoutesAndAliasesOnExitNode state machine (resourceRoutesSuppressed,
// exitNodeActive, gatewayActive) without touching the OS routing table, a
// WireGuard device, or a DNS proxy - safe as long as pm.peers stays empty,
// same constraint as newGatewayTestManager in gateway_test.go. Unlike
// NewPeerManager, disableRoutesAndAliasesOnExitNode is the only state seeded
// here; exitNodeActive/gatewayActive/resourceRoutesSuppressed always start
// false, matching NewPeerManager's real (purely reactive, no pre-seeding)
// behavior.
func newExitNodeTestManager(disableRoutesAndAliasesOnExitNode bool) *PeerManager {
	return &PeerManager{
		peers:                             make(map[int]SiteConfig),
		allowedIPOwners:                   make(map[string]int),
		allowedIPClaims:                   make(map[string]map[int]bool),
		disableRoutesAndAliasesOnExitNode: disableRoutesAndAliasesOnExitNode,
	}
}

func TestSetClearExitNodeSuppressesResourceRoutesWhenEnabled(t *testing.T) {
	pm := newExitNodeTestManager(true)

	if pm.resourceRoutesSuppressed {
		t.Fatalf("must start unsuppressed")
	}

	pm.SetExitNode("100.64.0.1", "100.64.0.2")
	if !pm.exitNodeActive {
		t.Fatalf("SetExitNode must mark the exit node active")
	}
	if !pm.resourceRoutesSuppressed {
		t.Fatalf("SetExitNode must suppress resource routes when the feature is enabled")
	}

	pm.ClearExitNode()
	if pm.exitNodeActive {
		t.Fatalf("ClearExitNode must mark the exit node inactive")
	}
	if pm.resourceRoutesSuppressed {
		t.Fatalf("ClearExitNode must restore resource routes")
	}
}

func TestSetClearExitNodeNoopWhenDisabled(t *testing.T) {
	pm := newExitNodeTestManager(false)

	pm.SetExitNode("100.64.0.1", "100.64.0.2")
	if pm.resourceRoutesSuppressed {
		t.Fatalf("resource routes must never be suppressed when the feature is disabled")
	}

	pm.ClearExitNode()
	if pm.resourceRoutesSuppressed {
		t.Fatalf("resource routes must stay unsuppressed when the feature is disabled")
	}
}

// TestClearExitNodeKeepsSuppressedWhileGatewayActive covers the two
// independent "exit node" signals (see exitNodeOrGatewayActiveLocked):
// disconnecting the ExitNodeConfig WireGuard peer must not restore resource
// routes if gateway/full-tunnel mode - what client apps and the CLI actually
// call "select exit node" - is still active. gatewayActive is set directly
// here (bypassing SetGateway, which touches the OS routing table) purely to
// exercise ClearExitNode's OR-check.
func TestClearExitNodeKeepsSuppressedWhileGatewayActive(t *testing.T) {
	pm := newExitNodeTestManager(true)

	pm.SetExitNode("100.64.0.1", "100.64.0.2")
	if !pm.resourceRoutesSuppressed {
		t.Fatalf("SetExitNode must suppress resource routes")
	}

	pm.mu.Lock()
	pm.gatewayActive = true
	pm.mu.Unlock()

	pm.ClearExitNode()
	if pm.exitNodeActive {
		t.Fatalf("ClearExitNode must mark the exit node inactive regardless of gateway state")
	}
	if !pm.resourceRoutesSuppressed {
		t.Fatalf("resource routes must stay suppressed while gateway mode is still active")
	}
}

func TestExitNodeOrGatewayActiveLocked(t *testing.T) {
	pm := newExitNodeTestManager(true)

	if pm.exitNodeOrGatewayActiveLocked() {
		t.Fatalf("neither signal is active yet")
	}

	pm.exitNodeActive = true
	if !pm.exitNodeOrGatewayActiveLocked() {
		t.Fatalf("exit node signal alone must count as active")
	}
	pm.exitNodeActive = false

	pm.gatewayActive = true
	if !pm.exitNodeOrGatewayActiveLocked() {
		t.Fatalf("gateway signal alone must count as active")
	}
}
