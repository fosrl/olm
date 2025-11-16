//go:build !windows

package olm

import (
	"net"
	"os"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"
)

func createTUNFromFD(tunFd uint32, mtuInt int) (tun.Device, error) {
	err := unix.SetNonblock(int(tunFd), true)
	if err != nil {
		return nil, err
	}

	file := os.NewFile(uintptr(tunFd), "")
	return tun.CreateTUNFromFile(file, mtuInt)
}
func uapiOpen(interfaceName string) (*os.File, error) {
	return ipc.UAPIOpen(interfaceName)
}

func uapiListen(interfaceName string, fileUAPI *os.File) (net.Listener, error) {
	return ipc.UAPIListen(interfaceName, fileUAPI)
}
