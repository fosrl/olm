//go:build darwin && !ios

package dns

import (
	"bufio"
	"bytes"
	"fmt"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"

	"github.com/fosrl/newt/logger"
)

const (
	scutilPath      = "/usr/sbin/scutil"
	dscacheutilPath = "/usr/bin/dscacheutil"

	dnsStateKeyFormat    = "State:/Network/Service/Olm-%s/DNS"
	globalIPv4State      = "State:/Network/Global/IPv4"
	primaryServiceFormat = "State:/Network/Service/%s/DNS"

	keySupplementalMatchDomains         = "SupplementalMatchDomains"
	keySupplementalMatchDomainsNoSearch = "SupplementalMatchDomainsNoSearch"
	keyServerAddresses                  = "ServerAddresses"
	keyServerPort                       = "ServerPort"
	arraySymbol                         = "* "
	digitSymbol                         = "# "
)

// DarwinDNSConfigurator manages DNS settings on macOS using scutil
type DarwinDNSConfigurator struct {
	createdKeys   map[string]struct{}
	originalState *DNSState
}

// NewDarwinDNSConfigurator creates a new macOS DNS configurator
func NewDarwinDNSConfigurator() (*DarwinDNSConfigurator, error) {
	return &DarwinDNSConfigurator{
		createdKeys: make(map[string]struct{}),
	}, nil
}

// Name returns the configurator name
func (d *DarwinDNSConfigurator) Name() string {
	return "darwin-scutil"
}

// SetDNS sets the DNS servers and returns the original servers
func (d *DarwinDNSConfigurator) SetDNS(servers []netip.Addr) ([]netip.Addr, error) {
	// Get current DNS settings before overriding
	originalServers, err := d.GetCurrentDNS()
	if err != nil {
		return nil, fmt.Errorf("get current DNS: %w", err)
	}

	// Store original state
	d.originalState = &DNSState{
		OriginalServers:  originalServers,
		ConfiguratorName: d.Name(),
	}

	// Set new DNS servers
	if err := d.applyDNSServers(servers); err != nil {
		return nil, fmt.Errorf("apply DNS servers: %w", err)
	}

	// Flush DNS cache
	if err := d.flushDNSCache(); err != nil {
		// Non-fatal, just log
		fmt.Printf("warning: failed to flush DNS cache: %v\n", err)
	}

	return originalServers, nil
}

// RestoreDNS restores the original DNS configuration
func (d *DarwinDNSConfigurator) RestoreDNS() error {
	// Remove all created keys
	for key := range d.createdKeys {
		if err := d.removeKey(key); err != nil {
			return fmt.Errorf("remove key %s: %w", key, err)
		}
	}

	// Flush DNS cache
	if err := d.flushDNSCache(); err != nil {
		fmt.Printf("warning: failed to flush DNS cache: %v\n", err)
	}

	return nil
}

// GetCurrentDNS returns the currently configured DNS servers
func (d *DarwinDNSConfigurator) GetCurrentDNS() ([]netip.Addr, error) {
	primaryServiceKey, err := d.getPrimaryServiceKey()
	if err != nil || primaryServiceKey == "" {
		return nil, fmt.Errorf("get primary service: %w", err)
	}

	dnsKey := fmt.Sprintf(primaryServiceFormat, primaryServiceKey)
	cmd := fmt.Sprintf("show %s\n", dnsKey)

	output, err := d.runScutil(cmd)
	if err != nil {
		return nil, fmt.Errorf("run scutil: %w", err)
	}

	servers := d.parseServerAddresses(output)
	return servers, nil
}

// applyDNSServers applies the DNS server configuration
func (d *DarwinDNSConfigurator) applyDNSServers(servers []netip.Addr) error {
	if len(servers) == 0 {
		return fmt.Errorf("no DNS servers provided")
	}

	key := fmt.Sprintf(dnsStateKeyFormat, "Override")

	// Use SupplementalMatchDomains with empty string to match ALL domains
	// This is the key to making DNS override work on macOS
	// Setting SupplementalMatchDomainsNoSearch to 0 enables search domain behavior
	err := d.addDNSState(key, "\"\"", servers[0], 53, true)
	if err != nil {
		return fmt.Errorf("set DNS servers: %w", err)
	}

	d.createdKeys[key] = struct{}{}
	return nil
}

// addDNSState adds a DNS state entry with the specified configuration
func (d *DarwinDNSConfigurator) addDNSState(state, domains string, dnsServer netip.Addr, port int, enableSearch bool) error {
	noSearch := "1"
	if enableSearch {
		noSearch = "0"
	}

	// Build the scutil command following NetBird's approach
	var commands strings.Builder
	commands.WriteString("d.init\n")
	commands.WriteString(fmt.Sprintf("d.add %s %s%s\n", keySupplementalMatchDomains, arraySymbol, domains))
	commands.WriteString(fmt.Sprintf("d.add %s %s%s\n", keySupplementalMatchDomainsNoSearch, digitSymbol, noSearch))
	commands.WriteString(fmt.Sprintf("d.add %s %s%s\n", keyServerAddresses, arraySymbol, dnsServer.String()))
	commands.WriteString(fmt.Sprintf("d.add %s %s%s\n", keyServerPort, digitSymbol, strconv.Itoa(port)))
	commands.WriteString(fmt.Sprintf("set %s\n", state))

	if _, err := d.runScutil(commands.String()); err != nil {
		return fmt.Errorf("applying state for domains %s, error: %w", domains, err)
	}

	logger.Info("Added DNS override with server %s:%d for domains: %s", dnsServer.String(), port, domains)
	return nil
}

// removeKey removes a DNS configuration key
func (d *DarwinDNSConfigurator) removeKey(key string) error {
	cmd := fmt.Sprintf("remove %s\n", key)

	if _, err := d.runScutil(cmd); err != nil {
		return fmt.Errorf("remove key: %w", err)
	}

	delete(d.createdKeys, key)
	return nil
}

// getPrimaryServiceKey gets the primary network service key
func (d *DarwinDNSConfigurator) getPrimaryServiceKey() (string, error) {
	cmd := fmt.Sprintf("show %s\n", globalIPv4State)

	output, err := d.runScutil(cmd)
	if err != nil {
		return "", fmt.Errorf("run scutil: %w", err)
	}

	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "PrimaryService") {
			parts := strings.Split(line, ":")
			if len(parts) >= 2 {
				return strings.TrimSpace(parts[1]), nil
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("scan output: %w", err)
	}

	return "", fmt.Errorf("primary service not found")
}

// parseServerAddresses parses DNS server addresses from scutil output
func (d *DarwinDNSConfigurator) parseServerAddresses(output []byte) []netip.Addr {
	var servers []netip.Addr
	inServerArray := false

	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if strings.HasPrefix(line, "ServerAddresses : <array> {") {
			inServerArray = true
			continue
		}

		if line == "}" {
			inServerArray = false
			continue
		}

		if inServerArray {
			// Line format: "0 : 8.8.8.8"
			parts := strings.Split(line, " : ")
			if len(parts) >= 2 {
				if addr, err := netip.ParseAddr(parts[1]); err == nil {
					servers = append(servers, addr)
				}
			}
		}
	}

	return servers
}

// flushDNSCache flushes the system DNS cache
func (d *DarwinDNSConfigurator) flushDNSCache() error {
	logger.Debug("Flushing dscacheutil cache")
	cmd := exec.Command(dscacheutilPath, "-flushcache")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("flush cache: %w", err)
	}

	logger.Debug("Flushing mDNSResponder cache")

	cmd = exec.Command("killall", "-HUP", "mDNSResponder")
	if err := cmd.Run(); err != nil {
		// Non-fatal, mDNSResponder might not be running
		return nil
	}

	return nil
}

// runScutil executes an scutil command
func (d *DarwinDNSConfigurator) runScutil(commands string) ([]byte, error) {
	// Wrap commands with open/quit
	wrapped := fmt.Sprintf("open\n%squit\n", commands)

	logger.Debug("Running scutil with commands:\n%s\n", wrapped)

	cmd := exec.Command(scutilPath)
	cmd.Stdin = strings.NewReader(wrapped)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("scutil command failed: %w, output: %s", err, output)
	}

	logger.Debug("scutil output:\n%s\n", output)

	return output, nil
}
