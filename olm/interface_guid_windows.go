//go:build windows

package olm

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/tun"
)

// GetInterfaceGUIDString retrieves the GUID string for a Windows TUN interface
// This is required for registry-based DNS configuration on Windows
func GetInterfaceGUIDString(tunDevice tun.Device) (string, error) {
	if tunDevice == nil {
		return "", fmt.Errorf("TUN device is nil")
	}

	// The wireguard-go Windows TUN device has a LUID() method
	// We need to use type assertion to access it
	type nativeTun interface {
		LUID() uint64
	}

	nativeDev, ok := tunDevice.(nativeTun)
	if !ok {
		return "", fmt.Errorf("TUN device does not support LUID retrieval (not a native Windows TUN device)")
	}

	luid := nativeDev.LUID()

	// Convert LUID to GUID using Windows API
	guid, err := luidToGUID(luid)
	if err != nil {
		return "", fmt.Errorf("failed to convert LUID to GUID: %w", err)
	}

	return guid, nil
}

// luidToGUID converts a Windows LUID (Locally Unique Identifier) to a GUID string
// using the Windows ConvertInterface* APIs
func luidToGUID(luid uint64) (string, error) {
	var guid windows.GUID

	// Load the iphlpapi.dll and get the ConvertInterfaceLuidToGuid function
	iphlpapi := windows.NewLazySystemDLL("iphlpapi.dll")
	convertLuidToGuid := iphlpapi.NewProc("ConvertInterfaceLuidToGuid")

	// Call the Windows API
	// NET_LUID is a 64-bit value on Windows
	ret, _, err := convertLuidToGuid.Call(
		uintptr(unsafe.Pointer(&luid)),
		uintptr(unsafe.Pointer(&guid)),
	)

	if ret != 0 {
		return "", fmt.Errorf("ConvertInterfaceLuidToGuid failed with code %d: %w", ret, err)
	}

	// Format the GUID as a string with curly braces
	guidStr := fmt.Sprintf("{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
		guid.Data1, guid.Data2, guid.Data3,
		guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3],
		guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7])

	return guidStr, nil
}
