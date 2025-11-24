//go:build !windows

package olm

import (
	"fmt"

	"golang.zx2c4.com/wireguard/tun"
)

// GetInterfaceGUIDString is only implemented for Windows
// This stub is provided for compilation on other platforms
func GetInterfaceGUIDString(tunDevice tun.Device) (string, error) {
	return "", fmt.Errorf("GetInterfaceGUIDString is only supported on Windows")
}
