package main

import (
	"fmt"
	"log"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/your-org/olm/dns/platform"
)

func main() {
	// Example 1: Automatic detection and DNS override
	exampleAutoDetection()

	// Example 2: Manual platform selection
	// exampleManualSelection()

	// Example 3: Get current system DNS
	// exampleGetCurrentDNS()
}

// exampleAutoDetection demonstrates automatic detection of the best DNS configurator
func exampleAutoDetection() {
	fmt.Println("=== Example 1: Automatic Detection ===")

	// On Linux/Unix, provide an interface name for better detection
	// On macOS, the interface name is ignored
	// On Windows, provide the interface GUID
	ifaceName := "eth0" // Change this to your interface name

	configurator, err := platform.DetectBestConfigurator(ifaceName)
	if err != nil {
		log.Fatalf("Failed to detect DNS configurator: %v", err)
	}

	fmt.Printf("Using DNS configurator: %s\n", configurator.Name())

	// Get current DNS servers before changing
	currentDNS, err := configurator.GetCurrentDNS()
	if err != nil {
		log.Printf("Warning: Could not get current DNS: %v", err)
	} else {
		fmt.Printf("Current DNS servers: %v\n", currentDNS)
	}

	// Set new DNS servers
	newDNS := []netip.Addr{
		netip.MustParseAddr("1.1.1.1"),     // Cloudflare
		netip.MustParseAddr("8.8.8.8"),     // Google
	}

	fmt.Printf("Setting DNS servers to: %v\n", newDNS)
	originalDNS, err := configurator.SetDNS(newDNS)
	if err != nil {
		log.Fatalf("Failed to set DNS: %v", err)
	}

	fmt.Printf("Original DNS servers (backed up): %v\n", originalDNS)

	// Set up signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Run for 30 seconds or until interrupted
	fmt.Println("\nDNS override active. Press Ctrl+C to restore original DNS.")
	fmt.Println("Waiting 30 seconds...")

	select {
	case <-time.After(30 * time.Second):
		fmt.Println("\nTimeout reached.")
	case sig := <-sigChan:
		fmt.Printf("\nReceived signal: %v\n", sig)
	}

	// Restore original DNS
	fmt.Println("Restoring original DNS servers...")
	if err := configurator.RestoreDNS(); err != nil {
		log.Fatalf("Failed to restore DNS: %v", err)
	}

	fmt.Println("DNS restored successfully!")
}

// exampleManualSelection demonstrates manual selection of DNS configurator
func exampleManualSelection() {
	fmt.Println("=== Example 2: Manual Selection ===")

	// Linux - systemd-resolved
	configurator, err := platform.NewSystemdResolvedDNSConfigurator("eth0")
	if err != nil {
		log.Fatalf("Failed to create systemd-resolved configurator: %v", err)
	}

	fmt.Printf("Using: %s\n", configurator.Name())

	newDNS := []netip.Addr{
		netip.MustParseAddr("1.1.1.1"),
	}

	originalDNS, err := configurator.SetDNS(newDNS)
	if err != nil {
		log.Fatalf("Failed to set DNS: %v", err)
	}

	fmt.Printf("Changed from %v to %v\n", originalDNS, newDNS)

	// Restore after 10 seconds
	time.Sleep(10 * time.Second)
	configurator.RestoreDNS()
}

// exampleGetCurrentDNS demonstrates getting current system DNS
func exampleGetCurrentDNS() {
	fmt.Println("=== Example 3: Get Current DNS ===")

	configurator, err := platform.DetectBestConfigurator("eth0")
	if err != nil {
		log.Fatalf("Failed to detect configurator: %v", err)
	}

	servers, err := configurator.GetCurrentDNS()
	if err != nil {
		log.Fatalf("Failed to get DNS: %v", err)
	}

	fmt.Printf("Current DNS servers (%s):\n", configurator.Name())
	for i, server := range servers {
		fmt.Printf("  %d. %s\n", i+1, server)
	}
}

// Platform-specific examples

// exampleLinuxFile demonstrates direct file manipulation on Linux
func exampleLinuxFile() {
	configurator, err := platform.NewFileDNSConfigurator()
	if err != nil {
		log.Fatal(err)
	}

	newDNS := []netip.Addr{
		netip.MustParseAddr("8.8.8.8"),
	}

	originalDNS, err := configurator.SetDNS(newDNS)
	if err != nil {
		log.Fatal(err)
	}

	defer configurator.RestoreDNS()

	fmt.Printf("Changed from %v to %v\n", originalDNS, newDNS)
	time.Sleep(10 * time.Second)
}

// exampleLinuxNetworkManager demonstrates NetworkManager on Linux
func exampleLinuxNetworkManager() {
	if !platform.IsNetworkManagerAvailable() {
		fmt.Println("NetworkManager is not available")
		return
	}

	configurator, err := platform.NewNetworkManagerDNSConfigurator("eth0")
	if err != nil {
		log.Fatal(err)
	}

	newDNS := []netip.Addr{
		netip.MustParseAddr("1.1.1.1"),
	}

	originalDNS, err := configurator.SetDNS(newDNS)
	if err != nil {
		log.Fatal(err)
	}

	defer configurator.RestoreDNS()

	fmt.Printf("Changed from %v to %v\n", originalDNS, newDNS)
	time.Sleep(10 * time.Second)
}

// exampleMacOS demonstrates macOS DNS override
func exampleMacOS() {
	configurator, err := platform.NewDarwinDNSConfigurator()
	if err != nil {
		log.Fatal(err)
	}

	newDNS := []netip.Addr{
		netip.MustParseAddr("1.1.1.1"),
		netip.MustParseAddr("1.0.0.1"),
	}

	originalDNS, err := configurator.SetDNS(newDNS)
	if err != nil {
		log.Fatal(err)
	}

	defer configurator.RestoreDNS()

	fmt.Printf("Changed from %v to %v\n", originalDNS, newDNS)
	time.Sleep(10 * time.Second)
}

// exampleWindows demonstrates Windows DNS override
func exampleWindows() {
	// You need to get the interface GUID first
	// This can be obtained from:
	// - ipconfig /all (look for the interface's GUID)
	// - registry: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces
	guid := "{YOUR-INTERFACE-GUID-HERE}"

	configurator, err := platform.NewWindowsDNSConfigurator(guid)
	if err != nil {
		log.Fatal(err)
	}

	newDNS := []netip.Addr{
		netip.MustParseAddr("1.1.1.1"),
	}

	originalDNS, err := configurator.SetDNS(newDNS)
	if err != nil {
		log.Fatal(err)
	}

	defer configurator.RestoreDNS()

	fmt.Printf("Changed from %v to %v\n", originalDNS, newDNS)
	time.Sleep(10 * time.Second)
}
