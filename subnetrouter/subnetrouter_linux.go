//go:build linux

// Package subnetrouter lets this client forward LAN traffic out over its own
// WireGuard tunnel, source-NAT'd to the tunnel's own IP. Pangolin's
// server-side routing/ACLs are keyed on the client's tunnel IP as its
// identity, so traffic merely forwarded from the LAN (which arrives with the
// LAN device's own source address) would not be recognized - it must be
// rewritten to look like it came from this client before it goes out over
// the tunnel, the same way a NAT router masquerades LAN traffic behind its
// WAN IP.
package subnetrouter

import (
	"fmt"
	"net/netip"
	"os"
	"strings"
	"sync"

	"github.com/fosrl/newt/logger"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

const (
	tableName    = "olm_subnet_router"
	ipForwardSys = "/proc/sys/net/ipv4/ip_forward"
)

// ipForwardMu guards the two package-level fields below, which record
// whether Enable had to flip ip_forward on itself, so Disable only ever
// restores a value it actually changed - mirroring dns/override's
// instance-free save/restore convention.
var (
	ipForwardMu      sync.Mutex
	weEnabledForward bool
)

// Enable turns this host into a subnet router: it enables IPv4 forwarding
// (if not already on) and installs an nftables table that SNATs anything
// leaving interfaceName whose source isn't already tunnelIP, and accepts
// forwarding to/from interfaceName so a default-deny FORWARD policy
// elsewhere on the host doesn't drop it.
//
// It is idempotent: any table left behind by a previous run (e.g. after a
// crash) is torn down first, so repeated Enable/Disable cycles across
// reconnects never conflict with stale state.
func Enable(interfaceName string, tunnelIP netip.Addr) error {
	if !tunnelIP.Is4() {
		return fmt.Errorf("subnet router requires an IPv4 tunnel address, got %v", tunnelIP)
	}

	// Best-effort cleanup of anything left over from a previous run.
	if err := Disable(interfaceName); err != nil {
		logger.Debug("subnetrouter: pre-enable cleanup: %v", err)
	}

	if err := enableIPForward(); err != nil {
		return fmt.Errorf("failed to enable IPv4 forwarding: %w", err)
	}

	conn := &nftables.Conn{}

	table := conn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   tableName,
	})

	postrouting := conn.AddChain(&nftables.Chain{
		Name:     "postrouting",
		Table:    table,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPostrouting,
		Priority: nftables.ChainPriorityNATSource,
	})

	addr := tunnelIP.As4()
	conn.AddRule(&nftables.Rule{
		Table: table,
		Chain: postrouting,
		Exprs: []expr.Any{
			// oifname == interfaceName
			&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifname(interfaceName)},
			// ip saddr != tunnelIP
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       12, // IPv4 source address offset
				Len:          4,
			},
			&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: addr[:]},
			// snat to tunnelIP
			&expr.Immediate{Register: 1, Data: addr[:]},
			&expr.NAT{
				Type:       expr.NATTypeSourceNAT,
				Family:     unix.NFPROTO_IPV4,
				RegAddrMin: 1,
				RegAddrMax: 1,
			},
		},
	})

	forward := conn.AddChain(&nftables.Chain{
		Name:     "forward",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookForward,
		Priority: nftables.ChainPriorityFilter,
	})

	for _, key := range []expr.MetaKey{expr.MetaKeyIIFNAME, expr.MetaKeyOIFNAME} {
		conn.AddRule(&nftables.Rule{
			Table: table,
			Chain: forward,
			Exprs: []expr.Any{
				&expr.Meta{Key: key, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifname(interfaceName)},
				&expr.Verdict{Kind: expr.VerdictAccept},
			},
		})
	}

	if err := conn.Flush(); err != nil {
		// Roll back the forwarding sysctl change too, so a failed Enable
		// doesn't leave the host with forwarding on and no NAT rules.
		_ = disableIPForwardIfWeEnabledIt()
		return fmt.Errorf("failed to apply nftables rules: %w", err)
	}

	logger.Debug("subnetrouter: enabled on %s (snat to %s)", interfaceName, tunnelIP)
	return nil
}

// Disable removes the nftables table added by Enable (a no-op if it doesn't
// exist) and restores ip_forward to whatever it was before Enable, but only
// if Enable is what changed it.
func Disable(interfaceName string) error {
	conn := &nftables.Conn{}

	tables, err := conn.ListTables()
	if err != nil {
		return fmt.Errorf("failed to list nftables tables: %w", err)
	}

	var found bool
	for _, t := range tables {
		if t.Name == tableName && t.Family == nftables.TableFamilyIPv4 {
			conn.DelTable(t)
			found = true
			break
		}
	}

	var flushErr error
	if found {
		flushErr = conn.Flush()
	}

	forwardErr := disableIPForwardIfWeEnabledIt()

	if flushErr != nil {
		return fmt.Errorf("failed to remove nftables table: %w", flushErr)
	}
	return forwardErr
}

// enableIPForward turns on IPv4 forwarding if it isn't already on, recording
// whether this call is the one that changed it.
func enableIPForward() error {
	ipForwardMu.Lock()
	defer ipForwardMu.Unlock()

	current, err := readIPForward()
	if err != nil {
		return err
	}
	if current {
		weEnabledForward = false
		return nil
	}

	if err := os.WriteFile(ipForwardSys, []byte("1\n"), 0644); err != nil {
		return err
	}
	weEnabledForward = true
	return nil
}

// disableIPForwardIfWeEnabledIt restores ip_forward to 0, but only if a
// prior enableIPForward call is what turned it on.
func disableIPForwardIfWeEnabledIt() error {
	ipForwardMu.Lock()
	defer ipForwardMu.Unlock()

	if !weEnabledForward {
		return nil
	}

	if err := os.WriteFile(ipForwardSys, []byte("0\n"), 0644); err != nil {
		return err
	}
	weEnabledForward = false
	return nil
}

func readIPForward() (bool, error) {
	data, err := os.ReadFile(ipForwardSys)
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(string(data)) == "1", nil
}

// ifname encodes an interface name the way nftables expects it: NUL-padded
// to IFNAMSIZ (16) bytes.
func ifname(name string) []byte {
	b := make([]byte, 16)
	copy(b, name)
	return b
}
