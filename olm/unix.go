//go:build !windows

package olm

import (
	"net"
	"os"

	"github.com/fosrl/newt/logger"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"
)

func createTUNFromFD(tunFd uint32, mtuInt int) (tun.Device, error) {
	dupTunFd, err := unix.Dup(int(tunFd))
	if err != nil {
		logger.Error("Unable to dup tun fd: %v", err)
		return nil, err
	}

	err = unix.SetNonblock(dupTunFd, true)
	if err != nil {
		unix.Close(dupTunFd)
		return nil, err
	}

	file := os.NewFile(uintptr(dupTunFd), "/dev/tun")
	device, err := tun.CreateTUNFromFile(file, mtuInt)
	if err != nil {
		file.Close()
		return nil, err
	}

	return device, nil
}

func uapiOpen(interfaceName string) (*os.File, error) {
	return ipc.UAPIOpen(interfaceName)
}

func uapiListen(interfaceName string, fileUAPI *os.File) (net.Listener, error) {
	return ipc.UAPIListen(interfaceName, fileUAPI)
}
