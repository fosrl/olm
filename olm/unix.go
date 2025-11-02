//go:build !windows

package olm

import (
	"net"
	"os"
	"strconv"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"
)

func createTUNFromFD(tunFdStr string, mtuInt int) (tun.Device, error) {
	fd, err := strconv.ParseUint(tunFdStr, 10, 32)
	if err != nil {
		return nil, err
	}

	err = unix.SetNonblock(int(fd), true)
	if err != nil {
		return nil, err
	}

	file := os.NewFile(uintptr(fd), "")
	return tun.CreateTUNFromFile(file, mtuInt)
}
func uapiOpen(interfaceName string) (*os.File, error) {
	return ipc.UAPIOpen(interfaceName)
}

func uapiListen(interfaceName string, fileUAPI *os.File) (net.Listener, error) {
	return ipc.UAPIListen(interfaceName, fileUAPI)
}
