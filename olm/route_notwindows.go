//go:build !windows

package olm

func WindowsAddRoute(destination string, gateway string, interfaceName string) error {
	return nil
}

func WindowsRemoveRoute(destination string) error {
	return nil
}
