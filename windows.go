//go:build windows

package main

import (
	"errors"
	"net"
	"os"

	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"
)

func createTUNFromFD(tunFdStr string, mtuInt int) (tun.Device, error) {
	return nil, errors.New("CreateTUNFromFile not supported on Windows")
}

func uapiOpen(interfaceName string) (*os.File, error) {
	return nil, nil
}

func uapiListen(interfaceName string, fileUAPI *os.File) (net.Listener, error) {
	// On Windows, UAPIListen only takes one parameter
	return ipc.UAPIListen(interfaceName)
}
