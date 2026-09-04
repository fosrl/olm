package olm

import (
	"encoding/json"
	"fmt"

	"github.com/fosrl/newt/logger"
	"github.com/fosrl/newt/network"
	dnsOverride "github.com/fosrl/olm/dns/override"
	"github.com/fosrl/olm/websocket"
)

// applyDNSConfigUpdate merges a server-provided DNS config override into the
// running tunnel config. Every set field always overrides the client's own
// local config (from CLI flags / API connect request, or a previous update);
// an unset field leaves the current value alone. Called both from the
// initial "olm/wg/connect" message, before the DNS proxy exists yet (the
// updated tunnelConfig feeds into its construction in handleConnect), and
// from a later live "olm/wg/dns/update" push, where the running proxy is
// updated directly.
func (o *Olm) applyDNSConfigUpdate(cfg DNSConfigUpdate) {
	logger.Info("Applying DNS config from server: %+v", cfg)

	if len(cfg.UpstreamDNS) > 0 {
		o.tunnelConfig.UpstreamDNS = cfg.UpstreamDNS
		if o.dnsProxy != nil {
			o.dnsProxy.SetUpstreamDNS(cfg.UpstreamDNS)
		}
	}

	if len(cfg.MatchDomains) > 0 {
		o.tunnelConfig.MatchDomains = cfg.MatchDomains
		if o.dnsProxy != nil {
			o.dnsProxy.SetMatchDomains(cfg.MatchDomains)
		}
	}

	if cfg.TunnelDNS != nil {
		o.tunnelConfig.TunnelDNS = *cfg.TunnelDNS
		if o.dnsProxy != nil {
			o.dnsProxy.SetTunnelDNS(*cfg.TunnelDNS)
		}
	}

	if cfg.OverrideDNS != nil && *cfg.OverrideDNS != o.tunnelConfig.OverrideDNS {
		if o.dnsProxy != nil {
			if err := o.applyDNSOverride(*cfg.OverrideDNS); err != nil {
				logger.Error("Failed to apply DNS override update: %v", err)
				return
			}
		}
		o.tunnelConfig.OverrideDNS = *cfg.OverrideDNS
	}
}

// applyDNSOverride installs or removes olm's own system DNS override
// (pointing the host resolver at the DNS proxy) and requires the DNS proxy
// to already be running. When the host platform already manages DNS
// natively (see NativeDNSManaged), this only updates the OS resolver list -
// there's no raw override to add or remove. Used both at initial connect
// (see handleConnect) and for a live "olm/wg/dns/update" toggle of
// OverrideDNS via applyDNSConfigUpdate.
func (o *Olm) applyDNSOverride(enable bool) error {
	if o.dnsProxy == nil {
		return fmt.Errorf("cannot toggle DNS override: DNS proxy is not running")
	}

	if enable {
		if !o.tunnelConfig.NativeDNSManaged {
			if err := dnsOverride.SetupDNSOverride(o.tunnelConfig.InterfaceName, o.dnsProxy.GetProxyIP()); err != nil {
				return fmt.Errorf("failed to setup DNS override: %w", err)
			}

			// Start the external watchdog (if configured). The watchdog will
			// reset DNS if this process dies before it can call
			// RestoreDNSOverride. This is a no-op when no watchdog
			// subcommand has been configured on the OlmConfig.
			o.startDNSWatchdog(o.tunnelConfig.InterfaceName)
		}

		network.SetDNSServers([]string{o.dnsProxy.GetProxyIP().String()})
	} else {
		if !o.tunnelConfig.NativeDNSManaged {
			if err := dnsOverride.RestoreDNSOverride(); err != nil {
				return fmt.Errorf("failed to restore DNS: %w", err)
			}

			o.stopDNSWatchdog()
		}
	}

	return nil
}

// handleDNSConfigUpdate handles a server-initiated request to change the
// client's DNS configuration (upstream DNS, tunnel DNS, override DNS, match
// domains) after it is already connected, without requiring a full
// reconnect. Mirrors the DNSConfig field sent on the initial
// "olm/wg/connect" message - see DNSConfigUpdate.
func (o *Olm) handleDNSConfigUpdate(msg websocket.WSMessage) {
	logger.Debug("Received DNS config update message: %v", msg.Data)

	if !o.tunnelRunning {
		logger.Debug("Tunnel stopped, ignoring DNS config update message")
		return
	}

	jsonData, err := json.Marshal(msg.Data)
	if err != nil {
		logger.Error("Error marshaling DNS config update data: %v", err)
		return
	}

	var update DNSConfigUpdate
	if err := json.Unmarshal(jsonData, &update); err != nil {
		logger.Error("Error unmarshaling DNS config update data: %v", err)
		return
	}

	o.applyDNSConfigUpdate(update)
}
