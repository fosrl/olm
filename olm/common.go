package olm

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/fosrl/newt/logger"
	"github.com/fosrl/olm/peermonitor"
	"github.com/fosrl/olm/websocket"
	"github.com/vishvananda/netlink"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/exp/rand"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type WgData struct {
	Sites    []SiteConfig `json:"sites"`
	TunnelIP string       `json:"tunnelIP"`
}

type SiteConfig struct {
	SiteId        int    `json:"siteId"`
	Endpoint      string `json:"endpoint"`
	PublicKey     string `json:"publicKey"`
	ServerIP      string `json:"serverIP"`
	ServerPort    uint16 `json:"serverPort"`
	RemoteSubnets string `json:"remoteSubnets,omitempty"` // optional, comma-separated list of subnets that this site can access
}

type TargetsByType struct {
	UDP []string `json:"udp"`
	TCP []string `json:"tcp"`
}

type TargetData struct {
	Targets []string `json:"targets"`
}

type HolePunchMessage struct {
	NewtID string `json:"newtId"`
}

type ExitNode struct {
	Endpoint  string `json:"endpoint"`
	PublicKey string `json:"publicKey"`
}

type HolePunchData struct {
	ExitNodes []ExitNode `json:"exitNodes"`
}

type EncryptedHolePunchMessage struct {
	EphemeralPublicKey string `json:"ephemeralPublicKey"`
	Nonce              []byte `json:"nonce"`
	Ciphertext         []byte `json:"ciphertext"`
}

var (
	peerMonitor      *peermonitor.PeerMonitor
	stopHolepunch    chan struct{}
	stopRegister     func()
	stopPing         chan struct{}
	olmToken         string
	holePunchRunning bool
)

const (
	ENV_WG_TUN_FD             = "WG_TUN_FD"
	ENV_WG_UAPI_FD            = "WG_UAPI_FD"
	ENV_WG_PROCESS_FOREGROUND = "WG_PROCESS_FOREGROUND"
)

type fixedPortBind struct {
	port uint16
	conn.Bind
}

// PeerAction represents a request to add, update, or remove a peer
type PeerAction struct {
	Action   string     `json:"action"`   // "add", "update", or "remove"
	SiteInfo SiteConfig `json:"siteInfo"` // Site configuration information
}

// UpdatePeerData represents the data needed to update a peer
type UpdatePeerData struct {
	SiteId        int    `json:"siteId"`
	Endpoint      string `json:"endpoint"`
	PublicKey     string `json:"publicKey"`
	ServerIP      string `json:"serverIP"`
	ServerPort    uint16 `json:"serverPort"`
	RemoteSubnets string `json:"remoteSubnets,omitempty"` // optional, comma-separated list of subnets that this site can access
}

// AddPeerData represents the data needed to add a peer
type AddPeerData struct {
	SiteId        int    `json:"siteId"`
	Endpoint      string `json:"endpoint"`
	PublicKey     string `json:"publicKey"`
	ServerIP      string `json:"serverIP"`
	ServerPort    uint16 `json:"serverPort"`
	RemoteSubnets string `json:"remoteSubnets,omitempty"` // optional, comma-separated list of subnets that this site can access
}

// RemovePeerData represents the data needed to remove a peer
type RemovePeerData struct {
	SiteId int `json:"siteId"`
}

type RelayPeerData struct {
	SiteId    int    `json:"siteId"`
	Endpoint  string `json:"endpoint"`
	PublicKey string `json:"publicKey"`
}

func (b *fixedPortBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	// Ignore the requested port and use our fixed port
	return b.Bind.Open(b.port)
}

// Helper function to format endpoints correctly
func formatEndpoint(endpoint string) string {
	if endpoint == "" {
		return ""
	}
	// Check if it's already a valid host:port that SplitHostPort can parse (e.g., [::1]:8080 or 1.2.3.4:8080)
	_, _, err := net.SplitHostPort(endpoint)
	if err == nil {
		return endpoint // Already valid, no change needed
	}

	// If it failed, it might be our malformed "ipv6:port" string. Let's check and fix it.
	lastColon := strings.LastIndex(endpoint, ":")
	if lastColon > 0 { // Ensure there is a colon and it's not the first character
		hostPart := endpoint[:lastColon]
		// Check if the host part is a literal IPv6 address
		if ip := net.ParseIP(hostPart); ip != nil && ip.To4() == nil {
			// It is! Reformat it with brackets.
			portPart := endpoint[lastColon+1:]
			return fmt.Sprintf("[%s]:%s", hostPart, portPart)
		}
	}

	// If it's not the specific malformed case, return it as is.
	return endpoint
}

func NewFixedPortBind(port uint16) conn.Bind {
	return &fixedPortBind{
		port: port,
		Bind: conn.NewDefaultBind(),
	}
}

func fixKey(key string) string {
	// Remove any whitespace
	key = strings.TrimSpace(key)

	// Decode from base64
	decoded, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		logger.Fatal("Error decoding base64")
	}

	// Convert to hex
	return hex.EncodeToString(decoded)
}

func parseLogLevel(level string) logger.LogLevel {
	switch strings.ToUpper(level) {
	case "DEBUG":
		return logger.DEBUG
	case "INFO":
		return logger.INFO
	case "WARN":
		return logger.WARN
	case "ERROR":
		return logger.ERROR
	case "FATAL":
		return logger.FATAL
	default:
		return logger.INFO // default to INFO if invalid level provided
	}
}

func mapToWireGuardLogLevel(level logger.LogLevel) int {
	switch level {
	case logger.DEBUG:
		return device.LogLevelVerbose
	// case logger.INFO:
	// return device.LogLevel
	case logger.WARN:
		return device.LogLevelError
	case logger.ERROR, logger.FATAL:
		return device.LogLevelSilent
	default:
		return device.LogLevelSilent
	}
}

func resolveDomain(domain string) (string, error) {
	// First handle any protocol prefix
	domain = strings.TrimPrefix(strings.TrimPrefix(domain, "https://"), "http://")

	// if there are any trailing slashes, remove them
	domain = strings.TrimSuffix(domain, "/")

	// Now split host and port
	host, port, err := net.SplitHostPort(domain)
	if err != nil {
		// No port found, use the domain as is
		host = domain
		port = ""
	}

	// Lookup IP addresses
	ips, err := net.LookupIP(host)
	if err != nil {
		return "", fmt.Errorf("DNS lookup failed: %v", err)
	}

	if len(ips) == 0 {
		return "", fmt.Errorf("no IP addresses found for domain %s", host)
	}

	// Get the first IPv4 address if available
	var ipAddr string
	for _, ip := range ips {
		if ipv4 := ip.To4(); ipv4 != nil {
			ipAddr = ipv4.String()
			break
		}
	}

	// If no IPv4 found, use the first IP (might be IPv6)
	if ipAddr == "" {
		ipAddr = ips[0].String()
	}

	// Add port back if it existed
	if port != "" {
		ipAddr = net.JoinHostPort(ipAddr, port)
	}

	return ipAddr, nil
}

func sendUDPHolePunchWithConn(conn *net.UDPConn, remoteAddr *net.UDPAddr, olmID string, serverPubKey string) error {
	if serverPubKey == "" || olmToken == "" {
		return nil
	}

	payload := struct {
		OlmID string `json:"olmId"`
		Token string `json:"token"`
	}{
		OlmID: olmID,
		Token: olmToken,
	}

	// Convert payload to JSON
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %v", err)
	}

	// Encrypt the payload using the server's WireGuard public key
	encryptedPayload, err := encryptPayload(payloadBytes, serverPubKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt payload: %v", err)
	}

	jsonData, err := json.Marshal(encryptedPayload)
	if err != nil {
		return fmt.Errorf("failed to marshal encrypted payload: %v", err)
	}

	_, err = conn.WriteToUDP(jsonData, remoteAddr)
	if err != nil {
		return fmt.Errorf("failed to send UDP packet: %v", err)
	}

	logger.Debug("Sent UDP hole punch to %s: %s", remoteAddr.String(), string(jsonData))

	return nil
}

func encryptPayload(payload []byte, serverPublicKey string) (interface{}, error) {
	// Generate an ephemeral keypair for this message
	ephemeralPrivateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral private key: %v", err)
	}
	ephemeralPublicKey := ephemeralPrivateKey.PublicKey()

	// Parse the server's public key
	serverPubKey, err := wgtypes.ParseKey(serverPublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse server public key: %v", err)
	}

	// Use X25519 for key exchange (replacing deprecated ScalarMult)
	var ephPrivKeyFixed [32]byte
	copy(ephPrivKeyFixed[:], ephemeralPrivateKey[:])

	// Perform X25519 key exchange
	sharedSecret, err := curve25519.X25519(ephPrivKeyFixed[:], serverPubKey[:])
	if err != nil {
		return nil, fmt.Errorf("failed to perform X25519 key exchange: %v", err)
	}

	// Create an AEAD cipher using the shared secret
	aead, err := chacha20poly1305.New(sharedSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to create AEAD cipher: %v", err)
	}

	// Generate a random nonce
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %v", err)
	}

	// Encrypt the payload
	ciphertext := aead.Seal(nil, nonce, payload, nil)

	// Prepare the final encrypted message
	encryptedMsg := struct {
		EphemeralPublicKey string `json:"ephemeralPublicKey"`
		Nonce              []byte `json:"nonce"`
		Ciphertext         []byte `json:"ciphertext"`
	}{
		EphemeralPublicKey: ephemeralPublicKey.String(),
		Nonce:              nonce,
		Ciphertext:         ciphertext,
	}

	return encryptedMsg, nil
}

func keepSendingUDPHolePunchToMultipleExitNodes(exitNodes []ExitNode, olmID string, sourcePort uint16) {
	if len(exitNodes) == 0 {
		logger.Warn("No exit nodes provided for hole punching")
		return
	}

	// Check if hole punching is already running
	if holePunchRunning {
		logger.Debug("UDP hole punch already running, skipping new request")
		return
	}

	// Set the flag to indicate hole punching is running
	holePunchRunning = true
	defer func() {
		holePunchRunning = false
		logger.Info("UDP hole punch goroutine ended")
	}()

	logger.Info("Starting UDP hole punch to %d exit nodes", len(exitNodes))
	defer logger.Info("UDP hole punch goroutine ended for all exit nodes")

	// Create the UDP connection once and reuse it for all exit nodes
	localAddr := &net.UDPAddr{
		Port: int(sourcePort),
		IP:   net.IPv4zero,
	}

	conn, err := net.ListenUDP("udp", localAddr)
	if err != nil {
		logger.Error("Failed to bind UDP socket: %v", err)
		return
	}
	defer conn.Close()

	// Resolve all endpoints upfront
	type resolvedExitNode struct {
		remoteAddr   *net.UDPAddr
		publicKey    string
		endpointName string
	}

	var resolvedNodes []resolvedExitNode
	for _, exitNode := range exitNodes {
		host, err := resolveDomain(exitNode.Endpoint)
		if err != nil {
			logger.Error("Failed to resolve endpoint %s: %v", exitNode.Endpoint, err)
			continue
		}

		serverAddr := net.JoinHostPort(host, "21820")
		remoteAddr, err := net.ResolveUDPAddr("udp", serverAddr)
		if err != nil {
			logger.Error("Failed to resolve UDP address for %s: %v", exitNode.Endpoint, err)
			continue
		}

		resolvedNodes = append(resolvedNodes, resolvedExitNode{
			remoteAddr:   remoteAddr,
			publicKey:    exitNode.PublicKey,
			endpointName: exitNode.Endpoint,
		})
		logger.Info("Resolved exit node: %s -> %s", exitNode.Endpoint, remoteAddr.String())
	}

	if len(resolvedNodes) == 0 {
		logger.Error("No exit nodes could be resolved")
		return
	}

	// Send initial hole punch to all exit nodes
	for _, node := range resolvedNodes {
		if err := sendUDPHolePunchWithConn(conn, node.remoteAddr, olmID, node.publicKey); err != nil {
			logger.Error("Failed to send initial UDP hole punch to %s: %v", node.endpointName, err)
		}
	}

	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()

	timeout := time.NewTimer(15 * time.Second)
	defer timeout.Stop()

	for {
		select {
		case <-stopHolepunch:
			logger.Info("Stopping UDP holepunch for all exit nodes")
			return
		case <-timeout.C:
			logger.Info("UDP holepunch routine timed out after 15 seconds for all exit nodes")
			return
		case <-ticker.C:
			// Send hole punch to all exit nodes
			for _, node := range resolvedNodes {
				if err := sendUDPHolePunchWithConn(conn, node.remoteAddr, olmID, node.publicKey); err != nil {
					logger.Error("Failed to send UDP hole punch to %s: %v", node.endpointName, err)
				}
			}
		}
	}
}

func keepSendingUDPHolePunch(endpoint string, olmID string, sourcePort uint16, serverPubKey string) {

	// Check if hole punching is already running
	if holePunchRunning {
		logger.Debug("UDP hole punch already running, skipping new request")
		return
	}

	// Set the flag to indicate hole punching is running
	holePunchRunning = true
	defer func() {
		holePunchRunning = false
		logger.Info("UDP hole punch goroutine ended")
	}()

	logger.Info("Starting UDP hole punch to %s", endpoint)
	defer logger.Info("UDP hole punch goroutine ended for %s", endpoint)

	host, err := resolveDomain(endpoint)
	if err != nil {
		logger.Error("Failed to resolve endpoint: %v", err)
		return
	}

	serverAddr := net.JoinHostPort(host, "21820")

	// Create the UDP connection once and reuse it
	localAddr := &net.UDPAddr{
		Port: int(sourcePort),
		IP:   net.IPv4zero,
	}

	remoteAddr, err := net.ResolveUDPAddr("udp", serverAddr)
	if err != nil {
		logger.Error("Failed to resolve UDP address: %v", err)
		return
	}

	conn, err := net.ListenUDP("udp", localAddr)
	if err != nil {
		logger.Error("Failed to bind UDP socket: %v", err)
		return
	}
	defer conn.Close()

	// Execute once immediately before starting the loop
	if err := sendUDPHolePunchWithConn(conn, remoteAddr, olmID, serverPubKey); err != nil {
		logger.Error("Failed to send UDP hole punch: %v", err)
	}

	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()

	timeout := time.NewTimer(15 * time.Second)
	defer timeout.Stop()

	for {
		select {
		case <-stopHolepunch:
			logger.Info("Stopping UDP holepunch")
			return
		case <-timeout.C:
			logger.Info("UDP holepunch routine timed out after 15 seconds")
			return
		case <-ticker.C:
			if err := sendUDPHolePunchWithConn(conn, remoteAddr, olmID, serverPubKey); err != nil {
				logger.Error("Failed to send UDP hole punch: %v", err)
			}
		}
	}
}

func FindAvailableUDPPort(minPort, maxPort uint16) (uint16, error) {
	if maxPort < minPort {
		return 0, fmt.Errorf("invalid port range: min=%d, max=%d", minPort, maxPort)
	}

	// Create a slice of all ports in the range
	portRange := make([]uint16, maxPort-minPort+1)
	for i := range portRange {
		portRange[i] = minPort + uint16(i)
	}

	// Fisher-Yates shuffle to randomize the port order
	rand.Seed(uint64(time.Now().UnixNano()))
	for i := len(portRange) - 1; i > 0; i-- {
		j := rand.Intn(i + 1)
		portRange[i], portRange[j] = portRange[j], portRange[i]
	}

	// Try each port in the randomized order
	for _, port := range portRange {
		addr := &net.UDPAddr{
			IP:   net.ParseIP("127.0.0.1"),
			Port: int(port),
		}
		conn, err := net.ListenUDP("udp", addr)
		if err != nil {
			continue // Port is in use or there was an error, try next port
		}
		_ = conn.SetDeadline(time.Now())
		conn.Close()
		return port, nil
	}

	return 0, fmt.Errorf("no available UDP ports found in range %d-%d", minPort, maxPort)
}

func sendPing(olm *websocket.Client) error {
	err := olm.SendMessage("olm/ping", map[string]interface{}{
		"timestamp": time.Now().Unix(),
		"userToken": olm.GetConfig().UserToken,
	})
	if err != nil {
		logger.Error("Failed to send ping message: %v", err)
		return err
	}
	logger.Debug("Sent ping message")
	return nil
}

func keepSendingPing(olm *websocket.Client) {
	// Send ping immediately on startup
	if err := sendPing(olm); err != nil {
		logger.Error("Failed to send initial ping: %v", err)
	} else {
		logger.Info("Sent initial ping message")
	}

	// Set up ticker for one minute intervals
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-stopPing:
			logger.Info("Stopping ping messages")
			return
		case <-ticker.C:
			if err := sendPing(olm); err != nil {
				logger.Error("Failed to send periodic ping: %v", err)
			}
		}
	}
}

// ConfigurePeer sets up or updates a peer within the WireGuard device
func ConfigurePeer(dev *device.Device, siteConfig SiteConfig, privateKey wgtypes.Key, endpoint string) error {
	siteHost, err := resolveDomain(siteConfig.Endpoint)
	if err != nil {
		return fmt.Errorf("failed to resolve endpoint for site %d: %v", siteConfig.SiteId, err)
	}

	// Split off the CIDR of the server IP which is just a string and add /32 for the allowed IP
	allowedIp := strings.Split(siteConfig.ServerIP, "/")
	if len(allowedIp) > 1 {
		allowedIp[1] = "32"
	} else {
		allowedIp = append(allowedIp, "32")
	}
	allowedIpStr := strings.Join(allowedIp, "/")

	// Collect all allowed IPs in a slice
	var allowedIPs []string
	allowedIPs = append(allowedIPs, allowedIpStr)

	// If we have anything in remoteSubnets, add those as well
	if siteConfig.RemoteSubnets != "" {
		// Split remote subnets by comma and add each one
		remoteSubnets := strings.Split(siteConfig.RemoteSubnets, ",")
		for _, subnet := range remoteSubnets {
			subnet = strings.TrimSpace(subnet)
			if subnet != "" {
				allowedIPs = append(allowedIPs, subnet)
			}
		}
	}

	// Construct WireGuard config for this peer
	var configBuilder strings.Builder
	configBuilder.WriteString(fmt.Sprintf("private_key=%s\n", fixKey(privateKey.String())))
	configBuilder.WriteString(fmt.Sprintf("public_key=%s\n", fixKey(siteConfig.PublicKey)))

	// Add each allowed IP separately
	for _, allowedIP := range allowedIPs {
		configBuilder.WriteString(fmt.Sprintf("allowed_ip=%s\n", allowedIP))
	}

	configBuilder.WriteString(fmt.Sprintf("endpoint=%s\n", siteHost))
	configBuilder.WriteString("persistent_keepalive_interval=1\n")

	config := configBuilder.String()
	logger.Debug("Configuring peer with config: %s", config)

	err = dev.IpcSet(config)
	if err != nil {
		return fmt.Errorf("failed to configure WireGuard peer: %v", err)
	}

	// Set up peer monitoring
	if peerMonitor != nil {
		monitorAddress := strings.Split(siteConfig.ServerIP, "/")[0]
		monitorPeer := net.JoinHostPort(monitorAddress, strconv.Itoa(int(siteConfig.ServerPort+1))) // +1 for the monitor port
		logger.Debug("Setting up peer monitor for site %d at %s", siteConfig.SiteId, monitorPeer)

		primaryRelay, err := resolveDomain(endpoint) // Using global endpoint variable
		if err != nil {
			logger.Warn("Failed to resolve primary relay endpoint: %v", err)
		}

		wgConfig := &peermonitor.WireGuardConfig{
			SiteID:       siteConfig.SiteId,
			PublicKey:    fixKey(siteConfig.PublicKey),
			ServerIP:     strings.Split(siteConfig.ServerIP, "/")[0],
			Endpoint:     siteConfig.Endpoint,
			PrimaryRelay: primaryRelay,
		}

		err = peerMonitor.AddPeer(siteConfig.SiteId, monitorPeer, wgConfig)
		if err != nil {
			logger.Warn("Failed to setup monitoring for site %d: %v", siteConfig.SiteId, err)
		} else {
			logger.Info("Started monitoring for site %d at %s", siteConfig.SiteId, monitorPeer)
		}
	}

	return nil
}

// RemovePeer removes a peer from the WireGuard device
func RemovePeer(dev *device.Device, siteId int, publicKey string) error {
	// Construct WireGuard config to remove the peer
	var configBuilder strings.Builder
	configBuilder.WriteString(fmt.Sprintf("public_key=%s\n", fixKey(publicKey)))
	configBuilder.WriteString("remove=true\n")

	config := configBuilder.String()
	logger.Debug("Removing peer with config: %s", config)

	err := dev.IpcSet(config)
	if err != nil {
		return fmt.Errorf("failed to remove WireGuard peer: %v", err)
	}

	// Stop monitoring this peer
	if peerMonitor != nil {
		peerMonitor.RemovePeer(siteId)
		logger.Info("Stopped monitoring for site %d", siteId)
	}

	return nil
}

// ConfigureInterface configures a network interface with an IP address and brings it up
func ConfigureInterface(interfaceName string, wgData WgData) error {
	var ipAddr string = wgData.TunnelIP

	// Parse the IP address and network
	ip, ipNet, err := net.ParseCIDR(ipAddr)
	if err != nil {
		return fmt.Errorf("invalid IP address: %v", err)
	}

	switch runtime.GOOS {
	case "linux":
		return configureLinux(interfaceName, ip, ipNet)
	case "darwin":
		return configureDarwin(interfaceName, ip, ipNet)
	case "windows":
		return configureWindows(interfaceName, ip, ipNet)
	default:
		return fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
	}
}

func configureWindows(interfaceName string, ip net.IP, ipNet *net.IPNet) error {
	logger.Info("Configuring Windows interface: %s", interfaceName)

	// Calculate mask string (e.g., 255.255.255.0)
	maskBits, _ := ipNet.Mask.Size()
	mask := net.CIDRMask(maskBits, 32)
	maskIP := net.IP(mask)

	// Set the IP address using netsh
	cmd := exec.Command("netsh", "interface", "ipv4", "set", "address",
		fmt.Sprintf("name=%s", interfaceName),
		"source=static",
		fmt.Sprintf("addr=%s", ip.String()),
		fmt.Sprintf("mask=%s", maskIP.String()))

	logger.Info("Running command: %v", cmd)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("netsh command failed: %v, output: %s", err, out)
	}

	// Bring up the interface if needed (in Windows, setting the IP usually brings it up)
	// But we'll explicitly enable it to be sure
	cmd = exec.Command("netsh", "interface", "set", "interface",
		interfaceName,
		"admin=enable")

	logger.Info("Running command: %v", cmd)
	out, err = cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("netsh enable interface command failed: %v, output: %s", err, out)
	}

	// delay 2 seconds
	time.Sleep(8 * time.Second)

	// Wait for the interface to be up and have the correct IP
	err = waitForInterfaceUp(interfaceName, ip, 30*time.Second)
	if err != nil {
		return fmt.Errorf("interface did not come up within timeout: %v", err)
	}

	return nil
}

// waitForInterfaceUp polls the network interface until it's up or times out
func waitForInterfaceUp(interfaceName string, expectedIP net.IP, timeout time.Duration) error {
	logger.Info("Waiting for interface %s to be up with IP %s", interfaceName, expectedIP)
	deadline := time.Now().Add(timeout)
	pollInterval := 500 * time.Millisecond

	for time.Now().Before(deadline) {
		// Check if interface exists and is up
		iface, err := net.InterfaceByName(interfaceName)
		if err == nil {
			// Check if interface is up
			if iface.Flags&net.FlagUp != 0 {
				// Check if it has the expected IP
				addrs, err := iface.Addrs()
				if err == nil {
					for _, addr := range addrs {
						ipNet, ok := addr.(*net.IPNet)
						if ok && ipNet.IP.Equal(expectedIP) {
							logger.Info("Interface %s is up with correct IP", interfaceName)
							return nil // Interface is up with correct IP
						}
					}
					logger.Info("Interface %s is up but doesn't have expected IP yet", interfaceName)
				}
			} else {
				logger.Info("Interface %s exists but is not up yet", interfaceName)
			}
		} else {
			logger.Info("Interface %s not found yet: %v", interfaceName, err)
		}

		// Wait before next check
		time.Sleep(pollInterval)
	}

	return fmt.Errorf("timed out waiting for interface %s to be up with IP %s", interfaceName, expectedIP)
}

func WindowsAddRoute(destination string, gateway string, interfaceName string) error {
	if runtime.GOOS != "windows" {
		return nil
	}

	var cmd *exec.Cmd

	// Parse destination to get the IP and subnet
	ip, ipNet, err := net.ParseCIDR(destination)
	if err != nil {
		return fmt.Errorf("invalid destination address: %v", err)
	}

	// Calculate the subnet mask
	maskBits, _ := ipNet.Mask.Size()
	mask := net.CIDRMask(maskBits, 32)
	maskIP := net.IP(mask)

	if gateway != "" {
		// Route with specific gateway
		cmd = exec.Command("route", "add",
			ip.String(),
			"mask", maskIP.String(),
			gateway,
			"metric", "1")
	} else if interfaceName != "" {
		// First, get the interface index
		indexCmd := exec.Command("netsh", "interface", "ipv4", "show", "interfaces")
		output, err := indexCmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("failed to get interface index: %v, output: %s", err, output)
		}

		// Parse the output to find the interface index
		lines := strings.Split(string(output), "\n")
		var ifIndex string
		for _, line := range lines {
			if strings.Contains(line, interfaceName) {
				fields := strings.Fields(line)
				if len(fields) > 0 {
					ifIndex = fields[0]
					break
				}
			}
		}

		if ifIndex == "" {
			return fmt.Errorf("could not find index for interface %s", interfaceName)
		}

		// Convert to integer to validate
		idx, err := strconv.Atoi(ifIndex)
		if err != nil {
			return fmt.Errorf("invalid interface index: %v", err)
		}

		// Route via interface using the index
		cmd = exec.Command("route", "add",
			ip.String(),
			"mask", maskIP.String(),
			"0.0.0.0",
			"if", strconv.Itoa(idx))
	} else {
		return fmt.Errorf("either gateway or interface must be specified")
	}

	logger.Info("Running command: %v", cmd)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("route command failed: %v, output: %s", err, out)
	}

	return nil
}

func WindowsRemoveRoute(destination string) error {
	// Parse destination to get the IP
	ip, ipNet, err := net.ParseCIDR(destination)
	if err != nil {
		return fmt.Errorf("invalid destination address: %v", err)
	}

	// Calculate the subnet mask
	maskBits, _ := ipNet.Mask.Size()
	mask := net.CIDRMask(maskBits, 32)
	maskIP := net.IP(mask)

	cmd := exec.Command("route", "delete",
		ip.String(),
		"mask", maskIP.String())

	logger.Info("Running command: %v", cmd)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("route delete command failed: %v, output: %s", err, out)
	}

	return nil
}

func findUnusedUTUN() (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", fmt.Errorf("failed to list interfaces: %v", err)
	}
	used := make(map[int]bool)
	re := regexp.MustCompile(`^utun(\d+)$`)
	for _, iface := range ifaces {
		if matches := re.FindStringSubmatch(iface.Name); len(matches) == 2 {
			if num, err := strconv.Atoi(matches[1]); err == nil {
				used[num] = true
			}
		}
	}
	// Try utun0 up to utun255.
	for i := 0; i < 256; i++ {
		if !used[i] {
			return fmt.Sprintf("utun%d", i), nil
		}
	}
	return "", fmt.Errorf("no unused utun interface found")
}

func configureDarwin(interfaceName string, ip net.IP, ipNet *net.IPNet) error {
	logger.Info("Configuring darwin interface: %s", interfaceName)

	prefix, _ := ipNet.Mask.Size()
	ipStr := fmt.Sprintf("%s/%d", ip.String(), prefix)

	cmd := exec.Command("ifconfig", interfaceName, "inet", ipStr, ip.String(), "alias")
	logger.Info("Running command: %v", cmd)

	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ifconfig command failed: %v, output: %s", err, out)
	}

	// Bring up the interface
	cmd = exec.Command("ifconfig", interfaceName, "up")
	logger.Info("Running command: %v", cmd)

	out, err = cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ifconfig up command failed: %v, output: %s", err, out)
	}

	return nil
}

func configureLinux(interfaceName string, ip net.IP, ipNet *net.IPNet) error {
	// Get the interface
	link, err := netlink.LinkByName(interfaceName)
	if err != nil {
		return fmt.Errorf("failed to get interface %s: %v", interfaceName, err)
	}

	// Create the IP address attributes
	addr := &netlink.Addr{
		IPNet: &net.IPNet{
			IP:   ip,
			Mask: ipNet.Mask,
		},
	}

	// Add the IP address to the interface
	if err := netlink.AddrAdd(link, addr); err != nil {
		return fmt.Errorf("failed to add IP address: %v", err)
	}

	// Bring up the interface
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("failed to bring up interface: %v", err)
	}

	return nil
}

func DarwinAddRoute(destination string, gateway string, interfaceName string) error {
	if runtime.GOOS != "darwin" {
		return nil
	}

	var cmd *exec.Cmd

	if gateway != "" {
		// Route with specific gateway
		cmd = exec.Command("route", "-q", "-n", "add", "-inet", destination, "-gateway", gateway)
	} else if interfaceName != "" {
		// Route via interface
		cmd = exec.Command("route", "-q", "-n", "add", "-inet", destination, "-interface", interfaceName)
	} else {
		return fmt.Errorf("either gateway or interface must be specified")
	}

	logger.Info("Running command: %v", cmd)

	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("route command failed: %v, output: %s", err, out)
	}

	return nil
}

func DarwinRemoveRoute(destination string) error {
	if runtime.GOOS != "darwin" {
		return nil
	}

	cmd := exec.Command("route", "-q", "-n", "delete", "-inet", destination)
	logger.Info("Running command: %v", cmd)

	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("route delete command failed: %v, output: %s", err, out)
	}

	return nil
}

func LinuxAddRoute(destination string, gateway string, interfaceName string) error {
	if runtime.GOOS != "linux" {
		return nil
	}

	var cmd *exec.Cmd

	if gateway != "" {
		// Route with specific gateway
		cmd = exec.Command("ip", "route", "add", destination, "via", gateway)
	} else if interfaceName != "" {
		// Route via interface
		cmd = exec.Command("ip", "route", "add", destination, "dev", interfaceName)
	} else {
		return fmt.Errorf("either gateway or interface must be specified")
	}

	logger.Info("Running command: %v", cmd)

	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip route command failed: %v, output: %s", err, out)
	}

	return nil
}

func LinuxRemoveRoute(destination string) error {
	if runtime.GOOS != "linux" {
		return nil
	}

	cmd := exec.Command("ip", "route", "del", destination)
	logger.Info("Running command: %v", cmd)

	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip route delete command failed: %v, output: %s", err, out)
	}

	return nil
}

// addRouteForServerIP adds an OS-specific route for the server IP
func addRouteForServerIP(serverIP, interfaceName string) error {
	if runtime.GOOS == "darwin" {
		return DarwinAddRoute(serverIP, "", interfaceName)
	}
	// else if runtime.GOOS == "windows" {
	//	return WindowsAddRoute(serverIP, "", interfaceName)
	// } else if runtime.GOOS == "linux" {
	//	return LinuxAddRoute(serverIP, "", interfaceName)
	// }
	return nil
}

// removeRouteForServerIP removes an OS-specific route for the server IP
func removeRouteForServerIP(serverIP string) error {
	if runtime.GOOS == "darwin" {
		return DarwinRemoveRoute(serverIP)
	}
	// else if runtime.GOOS == "windows" {
	// 	return WindowsRemoveRoute(serverIP)
	// } else if runtime.GOOS == "linux" {
	// 	return LinuxRemoveRoute(serverIP)
	// }
	return nil
}

// addRoutesForRemoteSubnets adds routes for each comma-separated CIDR in RemoteSubnets
func addRoutesForRemoteSubnets(remoteSubnets, interfaceName string) error {
	if remoteSubnets == "" {
		return nil
	}

	// Split remote subnets by comma and add routes for each one
	subnets := strings.Split(remoteSubnets, ",")
	for _, subnet := range subnets {
		subnet = strings.TrimSpace(subnet)
		if subnet == "" {
			continue
		}

		// Add route based on operating system
		if runtime.GOOS == "darwin" {
			if err := DarwinAddRoute(subnet, "", interfaceName); err != nil {
				logger.Error("Failed to add Darwin route for subnet %s: %v", subnet, err)
				return err
			}
		} else if runtime.GOOS == "windows" {
			if err := WindowsAddRoute(subnet, "", interfaceName); err != nil {
				logger.Error("Failed to add Windows route for subnet %s: %v", subnet, err)
				return err
			}
		} else if runtime.GOOS == "linux" {
			if err := LinuxAddRoute(subnet, "", interfaceName); err != nil {
				logger.Error("Failed to add Linux route for subnet %s: %v", subnet, err)
				return err
			}
		}

		logger.Info("Added route for remote subnet: %s", subnet)
	}
	return nil
}

// removeRoutesForRemoteSubnets removes routes for each comma-separated CIDR in RemoteSubnets
func removeRoutesForRemoteSubnets(remoteSubnets string) error {
	if remoteSubnets == "" {
		return nil
	}

	// Split remote subnets by comma and remove routes for each one
	subnets := strings.Split(remoteSubnets, ",")
	for _, subnet := range subnets {
		subnet = strings.TrimSpace(subnet)
		if subnet == "" {
			continue
		}

		// Remove route based on operating system
		if runtime.GOOS == "darwin" {
			if err := DarwinRemoveRoute(subnet); err != nil {
				logger.Error("Failed to remove Darwin route for subnet %s: %v", subnet, err)
				return err
			}
		} else if runtime.GOOS == "windows" {
			if err := WindowsRemoveRoute(subnet); err != nil {
				logger.Error("Failed to remove Windows route for subnet %s: %v", subnet, err)
				return err
			}
		} else if runtime.GOOS == "linux" {
			if err := LinuxRemoveRoute(subnet); err != nil {
				logger.Error("Failed to remove Linux route for subnet %s: %v", subnet, err)
				return err
			}
		}

		logger.Info("Removed route for remote subnet: %s", subnet)
	}
	return nil
}
