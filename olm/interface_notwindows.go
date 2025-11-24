//go:build !windows

package olm

import (
	"fmt"
	"net"
)

func configureWindows(interfaceName string, ip net.IP, ipNet *net.IPNet) error {
	return fmt.Errorf("configureWindows called on non-Windows platform")
}
