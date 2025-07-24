package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"syscall"
	"time"

	"github.com/fosrl/newt/websocket"
	"github.com/fosrl/olm/httpserver"
	"github.com/fosrl/olm/logger"
	"github.com/fosrl/olm/peermonitor"
	"github.com/fosrl/olm/wgtester"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func main() {
	// Check if we're running as a Windows service
	if isWindowsService() {
		runService("OlmWireguardService", false, os.Args[1:])
		fmt.Println("Running as Windows service")
		return
	}

	// Handle service management commands on Windows
	if runtime.GOOS == "windows" && len(os.Args) > 1 {
		switch os.Args[1] {
		case "install":
			err := installService()
			if err != nil {
				fmt.Printf("Failed to install service: %v\n", err)
				os.Exit(1)
			}
			fmt.Println("Service installed successfully")
			return
		case "remove", "uninstall":
			err := removeService()
			if err != nil {
				fmt.Printf("Failed to remove service: %v\n", err)
				os.Exit(1)
			}
			fmt.Println("Service removed successfully")
			return
		case "start":
			err := startService()
			if err != nil {
				fmt.Printf("Failed to start service: %v\n", err)
				os.Exit(1)
			}
			fmt.Println("Service started successfully")
			return
		case "stop":
			err := stopService()
			if err != nil {
				fmt.Printf("Failed to stop service: %v\n", err)
				os.Exit(1)
			}
			fmt.Println("Service stopped successfully")
			return
		case "status":
			status, err := getServiceStatus()
			if err != nil {
				fmt.Printf("Failed to get service status: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("Service status: %s\n", status)
			return
		case "debug":
			err := debugService()
			if err != nil {
				fmt.Printf("Failed to debug service: %v\n", err)
				os.Exit(1)
			}
			return
		case "help", "--help", "-h":
			fmt.Println("Olm WireGuard VPN Client")
			fmt.Println("\nWindows Service Management:")
			fmt.Println("  install     Install the service")
			fmt.Println("  remove      Remove the service")
			fmt.Println("  start       Start the service")
			fmt.Println("  stop        Stop the service")
			fmt.Println("  status      Show service status")
			fmt.Println("  debug       Run service in debug mode")
			fmt.Println("\nFor console mode, run without arguments or with standard flags.")
			return
		default:
			fmt.Println("Unknown command:", os.Args[1])
			fmt.Println("Use 'olm --help' for usage information.")
			return
		}
	}

	// Run in console mode
	runOlmMain(context.Background())
}

func runOlmMain(ctx context.Context) {
	runOlmMainWithArgs(ctx, os.Args[1:])
}

func runOlmMainWithArgs(ctx context.Context, args []string) {
	// Log that we've entered the main function
	fmt.Printf("runOlmMainWithArgs() called with args: %v\n", args)

	// Create a new FlagSet for parsing service arguments
	serviceFlags := flag.NewFlagSet("service", flag.ContinueOnError)

	var (
		endpoint      string
		id            string
		secret        string
		mtu           string
		mtuInt        int
		dns           string
		privateKey    wgtypes.Key
		err           error
		logLevel      string
		interfaceName string
		enableHTTP    bool
		httpAddr      string
		testMode      bool   // Add this var for the test flag
		testTarget    string // Add this var for test target
		pingInterval  time.Duration
		pingTimeout   time.Duration
	)

	stopHolepunch = make(chan struct{})
	stopRegister = make(chan struct{})
	stopPing = make(chan struct{})

	// if PANGOLIN_ENDPOINT, OLM_ID, and OLM_SECRET are set as environment variables, they will be used as default values
	endpoint = os.Getenv("PANGOLIN_ENDPOINT")
	id = os.Getenv("OLM_ID")
	secret = os.Getenv("OLM_SECRET")
	mtu = os.Getenv("MTU")
	dns = os.Getenv("DNS")
	logLevel = os.Getenv("LOG_LEVEL")
	interfaceName = os.Getenv("INTERFACE")
	httpAddr = os.Getenv("HTTP_ADDR")
	pingIntervalStr := os.Getenv("PING_INTERVAL")
	pingTimeoutStr := os.Getenv("PING_TIMEOUT")

	// Debug: Print all environment variables we're checking
	// fmt.Printf("Environment variables: PANGOLIN_ENDPOINT='%s', OLM_ID='%s', OLM_SECRET='%s'\n", endpoint, id, secret)

	// Setup flags for service mode
	// serviceFlags.StringVar(&endpoint, "endpoint", endpoint, "Endpoint of your Pangolin server")
	// serviceFlags.StringVar(&id, "id", id, "Olm ID")
	// serviceFlags.StringVar(&secret, "secret", secret, "Olm secret")
	// serviceFlags.StringVar(&mtu, "mtu", "1280", "MTU to use")
	// serviceFlags.StringVar(&dns, "dns", "8.8.8.8", "DNS server to use")
	// serviceFlags.StringVar(&logLevel, "log-level", "INFO", "Log level (DEBUG, INFO, WARN, ERROR, FATAL)")
	// serviceFlags.StringVar(&interfaceName, "interface", "olm", "Name of the WireGuard interface")
	// serviceFlags.StringVar(&httpAddr, "http-addr", ":9452", "HTTP server address (e.g., ':9452')")
	// serviceFlags.StringVar(&pingIntervalStr, "ping-interval", "3s", "Interval for pinging the server (default 3s)")
	// serviceFlags.StringVar(&pingTimeoutStr, "ping-timeout", "5s", "Timeout for each ping (default 5s)")
	// serviceFlags.BoolVar(&enableHTTP, "http", false, "Enable HTTP server")
	// serviceFlags.BoolVar(&testMode, "test", false, "Test WireGuard connectivity to a target")
	// serviceFlags.StringVar(&testTarget, "test-target", "", "Target server:port for test mode")
	if endpoint == "" {
		serviceFlags.StringVar(&endpoint, "endpoint", "", "Endpoint of your Pangolin server")
	}
	if id == "" {
		serviceFlags.StringVar(&id, "id", "", "Olm ID")
	}
	if secret == "" {
		serviceFlags.StringVar(&secret, "secret", "", "Olm secret")
	}
	if mtu == "" {
		serviceFlags.StringVar(&mtu, "mtu", "1280", "MTU to use")
	}
	if dns == "" {
		serviceFlags.StringVar(&dns, "dns", "8.8.8.8", "DNS server to use")
	}
	if logLevel == "" {
		serviceFlags.StringVar(&logLevel, "log-level", "INFO", "Log level (DEBUG, INFO, WARN, ERROR, FATAL)")
	}
	if interfaceName == "" {
		serviceFlags.StringVar(&interfaceName, "interface", "olm", "Name of the WireGuard interface")
	}
	if httpAddr == "" {
		serviceFlags.StringVar(&httpAddr, "http-addr", ":9452", "HTTP server address (e.g., ':9452')")
	}
	if pingIntervalStr == "" {
		serviceFlags.StringVar(&pingIntervalStr, "ping-interval", "3s", "Interval for pinging the server (default 3s)")
	}
	if pingTimeoutStr == "" {
		serviceFlags.StringVar(&pingTimeoutStr, "ping-timeout", "5s", "	Timeout for each ping (default 3s)")
	}

	// Parse the service arguments
	if err := serviceFlags.Parse(args); err != nil {
		fmt.Printf("Error parsing service arguments: %v\n", err)
		return
	}

	// Debug: Print final values after flag parsing
	fmt.Printf("After flag parsing: endpoint='%s', id='%s', secret='%s'\n", endpoint, id, secret)

	// Parse ping intervals
	if pingIntervalStr != "" {
		pingInterval, err = time.ParseDuration(pingIntervalStr)
		if err != nil {
			fmt.Printf("Invalid PING_INTERVAL value: %s, using default 3 seconds\n", pingIntervalStr)
			pingInterval = 3 * time.Second
		}
	} else {
		pingInterval = 3 * time.Second
	}

	if pingTimeoutStr != "" {
		pingTimeout, err = time.ParseDuration(pingTimeoutStr)
		if err != nil {
			fmt.Printf("Invalid PING_TIMEOUT value: %s, using default 5 seconds\n", pingTimeoutStr)
			pingTimeout = 5 * time.Second
		}
	} else {
		pingTimeout = 5 * time.Second
	}

	// Setup Windows event logging if on Windows
	if runtime.GOOS == "windows" {
		setupWindowsEventLog()
	} else {
		// Initialize logger for non-Windows platforms
		logger.Init()
	}
	loggerLevel := parseLogLevel(logLevel)
	logger.GetLogger().SetLevel(parseLogLevel(logLevel))

	// Log startup information
	logger.Info("Olm service starting...")
	logger.Info("Parameters: endpoint='%s', id='%s', secret='%s'", endpoint, id, secret)
	logger.Info("HTTP enabled: %v, HTTP addr: %s", enableHTTP, httpAddr)

	// Handle test mode
	if testMode {
		if testTarget == "" {
			logger.Fatal("Test mode requires -test-target to be set to a server:port")
		}

		logger.Info("Running in test mode, connecting to %s", testTarget)

		// Create a new tester client
		tester, err := wgtester.NewClient(testTarget)
		if err != nil {
			logger.Fatal("Failed to create tester client: %v", err)
		}
		defer tester.Close()

		// Test connection with a 2-second timeout
		connected, rtt := tester.TestConnectionWithTimeout(2 * time.Second)

		if connected {
			logger.Info("Connection test successful! RTT: %v", rtt)
			fmt.Printf("Connection test successful! RTT: %v\n", rtt)
			os.Exit(0)
		} else {
			logger.Error("Connection test failed - no response received")
			fmt.Println("Connection test failed - no response received")
			os.Exit(1)
		}
	}

	var httpServer *httpserver.HTTPServer
	if enableHTTP {
		httpServer = httpserver.NewHTTPServer(httpAddr)
		if err := httpServer.Start(); err != nil {
			logger.Fatal("Failed to start HTTP server: %v", err)
		}

		// Use a goroutine to handle connection requests
		go func() {
			for req := range httpServer.GetConnectionChannel() {
				logger.Info("Received connection request via HTTP: id=%s, endpoint=%s", req.ID, req.Endpoint)

				// Set the connection parameters
				id = req.ID
				secret = req.Secret
				endpoint = req.Endpoint
			}
		}()
	}

	// Check if required parameters are missing and provide helpful guidance
	missingParams := []string{}
	if id == "" {
		missingParams = append(missingParams, "id (use -id flag or OLM_ID env var)")
	}
	if secret == "" {
		missingParams = append(missingParams, "secret (use -secret flag or OLM_SECRET env var)")
	}
	if endpoint == "" {
		missingParams = append(missingParams, "endpoint (use -endpoint flag or PANGOLIN_ENDPOINT env var)")
	}

	if len(missingParams) > 0 {
		logger.Error("Missing required parameters: %v", missingParams)
		logger.Error("Either provide them as command line flags or set as environment variables")
		fmt.Printf("ERROR: Missing required parameters: %v\n", missingParams)
		fmt.Printf("Please provide them as command line flags or set as environment variables\n")
		if !enableHTTP {
			logger.Error("HTTP server is disabled, cannot receive parameters via API")
			fmt.Printf("HTTP server is disabled, cannot receive parameters via API\n")
			return
		}
	}

	// wait until we have a client id and secret and endpoint
	waitCount := 0
	for id == "" || secret == "" || endpoint == "" {
		select {
		case <-ctx.Done():
			logger.Info("Context cancelled while waiting for credentials")
			return
		default:
			missing := []string{}
			if id == "" {
				missing = append(missing, "id")
			}
			if secret == "" {
				missing = append(missing, "secret")
			}
			if endpoint == "" {
				missing = append(missing, "endpoint")
			}
			waitCount++
			if waitCount%10 == 1 { // Log every 10 seconds instead of every second
				logger.Debug("Waiting for missing parameters: %v (waiting %d seconds)", missing, waitCount)
			}
			time.Sleep(1 * time.Second)
		}
	}

	// parse the mtu string into an int
	mtuInt, err = strconv.Atoi(mtu)
	if err != nil {
		logger.Fatal("Failed to parse MTU: %v", err)
	}

	privateKey, err = wgtypes.GeneratePrivateKey()
	if err != nil {
		logger.Fatal("Failed to generate private key: %v", err)
	}

	// Create a new olm
	olm, err := websocket.NewClient(
		"olm",
		id,     // CLI arg takes precedence
		secret, // CLI arg takes precedence
		endpoint,
		pingInterval,
		pingTimeout,
	)
	if err != nil {
		logger.Fatal("Failed to create olm: %v", err)
	}

	// Create TUN device and network stack
	var dev *device.Device
	var wgData WgData
	var holePunchData HolePunchData
	var uapiListener net.Listener
	var tdev tun.Device

	sourcePort, err := FindAvailableUDPPort(49152, 65535)
	if err != nil {
		fmt.Printf("Error finding available port: %v\n", err)
		os.Exit(1)
	}

	olm.RegisterHandler("olm/wg/holepunch", func(msg websocket.WSMessage) {
		logger.Debug("Received message: %v", msg.Data)

		jsonData, err := json.Marshal(msg.Data)
		if err != nil {
			logger.Info("Error marshaling data: %v", err)
			return
		}

		if err := json.Unmarshal(jsonData, &holePunchData); err != nil {
			logger.Info("Error unmarshaling target data: %v", err)
			return
		}

		gerbilServerPubKey = holePunchData.ServerPubKey

		go keepSendingUDPHolePunch(holePunchData.Endpoint, id, sourcePort)
	})

	connectTimes := 0
	// Register handlers for different message types
	olm.RegisterHandler("olm/wg/connect", func(msg websocket.WSMessage) {
		logger.Debug("Received message: %v", msg.Data)

		if connectTimes > 0 {
			logger.Info("Already connected. Ignoring new connection request.")
			return
		}

		connectTimes++

		close(stopRegister)

		// if there is an existing tunnel then close it
		if dev != nil {
			logger.Info("Got new message. Closing existing tunnel!")
			dev.Close()
		}

		jsonData, err := json.Marshal(msg.Data)
		if err != nil {
			logger.Info("Error marshaling data: %v", err)
			return
		}

		if err := json.Unmarshal(jsonData, &wgData); err != nil {
			logger.Info("Error unmarshaling target data: %v", err)
			return
		}

		tdev, err = func() (tun.Device, error) {
			tunFdStr := os.Getenv(ENV_WG_TUN_FD)

			// if on macOS, call findUnusedUTUN to get a new utun device
			if runtime.GOOS == "darwin" {
				interfaceName, err := findUnusedUTUN()
				if err != nil {
					return nil, err
				}
				return tun.CreateTUN(interfaceName, mtuInt)
			}

			if tunFdStr == "" {
				return tun.CreateTUN(interfaceName, mtuInt)
			}

			return createTUNFromFD(tunFdStr, mtuInt)
		}()

		if err != nil {
			logger.Error("Failed to create TUN device: %v", err)
			return
		}

		realInterfaceName, err2 := tdev.Name()
		if err2 == nil {
			interfaceName = realInterfaceName
		}

		// open UAPI file (or use supplied fd)
		fileUAPI, err := func() (*os.File, error) {
			uapiFdStr := os.Getenv(ENV_WG_UAPI_FD)
			if uapiFdStr == "" {
				return uapiOpen(interfaceName)
			}

			// use supplied fd

			fd, err := strconv.ParseUint(uapiFdStr, 10, 32)
			if err != nil {
				return nil, err
			}

			return os.NewFile(uintptr(fd), ""), nil
		}()
		if err != nil {
			logger.Error("UAPI listen error: %v", err)
			os.Exit(1)
			return
		}

		dev = device.NewDevice(tdev, NewFixedPortBind(uint16(sourcePort)), device.NewLogger(
			mapToWireGuardLogLevel(loggerLevel),
			"wireguard: ",
		))

		errs := make(chan error)

		uapiListener, err = uapiListen(interfaceName, fileUAPI)
		if err != nil {
			logger.Error("Failed to listen on uapi socket: %v", err)
			os.Exit(1)
		}

		go func() {
			for {
				conn, err := uapiListener.Accept()
				if err != nil {
					errs <- err
					return
				}
				go dev.IpcHandle(conn)
			}
		}()

		logger.Info("UAPI listener started")

		close(stopHolepunch)

		// Bring up the device
		err = dev.Up()
		if err != nil {
			logger.Error("Failed to bring up WireGuard device: %v", err)
		}

		// configure the interface
		err = ConfigureInterface(realInterfaceName, wgData)
		if err != nil {
			logger.Error("Failed to configure interface: %v", err)
		}

		peerMonitor = peermonitor.NewPeerMonitor(
			func(siteID int, connected bool, rtt time.Duration) {
				if httpServer != nil {
					httpServer.UpdatePeerStatus(siteID, connected, rtt)
				}
				if connected {
					logger.Info("Peer %d is now connected (RTT: %v)", siteID, rtt)
				} else {
					logger.Warn("Peer %d is disconnected", siteID)
				}
			},
			fixKey(privateKey.String()),
			olm,
			dev,
		)

		// loop over the sites and call ConfigurePeer for each one
		for _, site := range wgData.Sites {
			if httpServer != nil {
				httpServer.UpdatePeerStatus(site.SiteId, false, 0)
			}
			err = ConfigurePeer(dev, site, privateKey, endpoint)
			if err != nil {
				logger.Error("Failed to configure peer: %v", err)
				return
			}

			err = DarwinAddRoute(site.ServerIP, "", interfaceName)
			if err != nil {
				logger.Error("Failed to add route for peer: %v", err)
				return
			}
			// err = WindowsAddRoute(site.ServerIP, "", interfaceName)
			// if err != nil {
			// 	logger.Error("Failed to add route for peer: %v", err)
			// 	return
			// }

			logger.Info("Configured peer %s", site.PublicKey)
		}

		peerMonitor.Start()

		logger.Info("WireGuard device created.")
	})

	olm.RegisterHandler("olm/wg/peer/update", func(msg websocket.WSMessage) {
		logger.Debug("Received update-peer message: %v", msg.Data)

		jsonData, err := json.Marshal(msg.Data)
		if err != nil {
			logger.Error("Error marshaling data: %v", err)
			return
		}

		var updateData UpdatePeerData
		if err := json.Unmarshal(jsonData, &updateData); err != nil {
			logger.Error("Error unmarshaling update data: %v", err)
			return
		}

		// Convert to SiteConfig
		siteConfig := SiteConfig{
			SiteId:     updateData.SiteId,
			Endpoint:   updateData.Endpoint,
			PublicKey:  updateData.PublicKey,
			ServerIP:   updateData.ServerIP,
			ServerPort: updateData.ServerPort,
		}

		// Update the peer in WireGuard
		if dev != nil {
			if err := ConfigurePeer(dev, siteConfig, privateKey, endpoint); err != nil {
				logger.Error("Failed to update peer: %v", err)
				// Send error response if needed
				return
			}

			// Update successful
			logger.Info("Successfully updated peer for site %d", updateData.SiteId)
			// If this is part of a WgData structure, update it
			for i, site := range wgData.Sites {
				if site.SiteId == updateData.SiteId {
					wgData.Sites[i] = siteConfig
					break
				}
			}
		} else {
			logger.Error("WireGuard device not initialized")
		}
	})

	// Handler for adding a new peer
	olm.RegisterHandler("olm/wg/peer/add", func(msg websocket.WSMessage) {
		logger.Debug("Received add-peer message: %v", msg.Data)

		jsonData, err := json.Marshal(msg.Data)
		if err != nil {
			logger.Error("Error marshaling data: %v", err)
			return
		}

		var addData AddPeerData
		if err := json.Unmarshal(jsonData, &addData); err != nil {
			logger.Error("Error unmarshaling add data: %v", err)
			return
		}

		// Convert to SiteConfig
		siteConfig := SiteConfig{
			SiteId:     addData.SiteId,
			Endpoint:   addData.Endpoint,
			PublicKey:  addData.PublicKey,
			ServerIP:   addData.ServerIP,
			ServerPort: addData.ServerPort,
		}

		// Add the peer to WireGuard
		if dev != nil {
			if err := ConfigurePeer(dev, siteConfig, privateKey, endpoint); err != nil {
				logger.Error("Failed to add peer: %v", err)
				return
			}

			// Add route for the new peer
			err = DarwinAddRoute(siteConfig.ServerIP, "", interfaceName)
			if err != nil {
				logger.Error("Failed to add route for new peer: %v", err)
				return
			}
			// err = WindowsAddRoute(siteConfig.ServerIP, "", interfaceName)
			// if err != nil {
			// 	logger.Error("Failed to add route for new peer: %v", err)
			// 	return
			// }

			// Add successful
			logger.Info("Successfully added peer for site %d", addData.SiteId)

			// Update WgData with the new peer
			wgData.Sites = append(wgData.Sites, siteConfig)
		} else {
			logger.Error("WireGuard device not initialized")
		}
	})

	// Handler for removing a peer
	olm.RegisterHandler("olm/wg/peer/remove", func(msg websocket.WSMessage) {
		logger.Debug("Received remove-peer message: %v", msg.Data)

		jsonData, err := json.Marshal(msg.Data)
		if err != nil {
			logger.Error("Error marshaling data: %v", err)
			return
		}

		var removeData RemovePeerData
		if err := json.Unmarshal(jsonData, &removeData); err != nil {
			logger.Error("Error unmarshaling remove data: %v", err)
			return
		}

		// Find the peer to remove
		var peerToRemove *SiteConfig
		var newSites []SiteConfig

		for _, site := range wgData.Sites {
			if site.SiteId == removeData.SiteId {
				peerToRemove = &site
			} else {
				newSites = append(newSites, site)
			}
		}

		if peerToRemove == nil {
			logger.Error("Peer with site ID %d not found", removeData.SiteId)
			return
		}

		// Remove the peer from WireGuard
		if dev != nil {
			if err := RemovePeer(dev, removeData.SiteId, peerToRemove.PublicKey); err != nil {
				logger.Error("Failed to remove peer: %v", err)
				// Send error response if needed
				return
			}

			// Remove route for the peer
			err = DarwinRemoveRoute(peerToRemove.ServerIP)
			if err != nil {
				logger.Error("Failed to remove route for peer: %v", err)
				return
			}
			err = WindowsRemoveRoute(peerToRemove.ServerIP)
			if err != nil {
				logger.Error("Failed to remove route for peer: %v", err)
				return
			}

			// Remove successful
			logger.Info("Successfully removed peer for site %d", removeData.SiteId)

			// Update WgData to remove the peer
			wgData.Sites = newSites
		} else {
			logger.Error("WireGuard device not initialized")
		}
	})

	olm.RegisterHandler("olm/wg/peer/relay", func(msg websocket.WSMessage) {
		logger.Debug("Received relay-peer message: %v", msg.Data)

		jsonData, err := json.Marshal(msg.Data)
		if err != nil {
			logger.Error("Error marshaling data: %v", err)
			return
		}

		var removeData RelayPeerData
		if err := json.Unmarshal(jsonData, &removeData); err != nil {
			logger.Error("Error unmarshaling remove data: %v", err)
			return
		}

		primaryRelay, err := resolveDomain(removeData.Endpoint)
		if err != nil {
			logger.Warn("Failed to resolve primary relay endpoint: %v", err)
		}

		peerMonitor.HandleFailover(removeData.SiteId, primaryRelay)
	})

	olm.RegisterHandler("olm/terminate", func(msg websocket.WSMessage) {
		logger.Info("Received terminate message")
		olm.Close()
	})

	olm.OnConnect(func() error {
		publicKey := privateKey.PublicKey()
		logger.Debug("Public key: %s", publicKey)

		go keepSendingRegistration(olm, publicKey.String())
		go keepSendingPing(olm)

		if httpServer != nil {
			httpServer.SetConnectionStatus(true)
		}

		logger.Info("Sent registration message")
		return nil
	})

	olm.OnTokenUpdate(func(token string) {
		olmToken = token
	})

	// Connect to the WebSocket server
	if err := olm.Connect(); err != nil {
		logger.Fatal("Failed to connect to server: %v", err)
	}
	defer olm.Close()

	// Wait for interrupt signal or context cancellation
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case <-sigCh:
		logger.Info("Received interrupt signal")
	case <-ctx.Done():
		logger.Info("Context cancelled")
	}

	select {
	case <-stopHolepunch:
		// Channel already closed, do nothing
	default:
		close(stopHolepunch)
	}

	select {
	case <-stopRegister:
		// Channel already closed
	default:
		close(stopRegister)
	}

	select {
	case <-stopPing:
		// Channel already closed
	default:
		close(stopPing)
	}

	if uapiListener != nil {
		uapiListener.Close()
	}
	if dev != nil {
		dev.Close()
	}

	logger.Info("runOlmMain() exiting")
	fmt.Printf("runOlmMain() exiting\n")
}
