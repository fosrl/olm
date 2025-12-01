package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/fosrl/newt/logger"
	"github.com/fosrl/newt/updates"
	"github.com/fosrl/olm/olm"
)

func main() {
	// Check if we're running as a Windows service
	if isWindowsService() {
		runService("OlmWireguardService", false, os.Args[1:])
		fmt.Println("Running as Windows service")
		return
	}

	// Handle service management commands on Windows
	if runtime.GOOS == "windows" {
		var command string
		if len(os.Args) > 1 {
			command = os.Args[1]
		} else {
			command = "default"
		}

		switch command {
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
			// Pass the remaining arguments (after "start") to the service
			serviceArgs := os.Args[2:]
			err := startService(serviceArgs)
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
			// get the status and if it is Not Installed then install it first
			status, err := getServiceStatus()
			if err != nil {
				fmt.Printf("Failed to get service status: %v\n", err)
				os.Exit(1)
			}
			if status == "Not Installed" {
				err := installService()
				if err != nil {
					fmt.Printf("Failed to install service: %v\n", err)
					os.Exit(1)
				}
				fmt.Println("Service installed successfully, now running in debug mode")
			}

			// Pass the remaining arguments (after "debug") to the service
			serviceArgs := os.Args[2:]
			err = debugService(serviceArgs)
			if err != nil {
				fmt.Printf("Failed to debug service: %v\n", err)
				os.Exit(1)
			}
			return
		case "logs":
			err := watchLogFile(false)
			if err != nil {
				fmt.Printf("Failed to watch log file: %v\n", err)
				os.Exit(1)
			}
			return
		case "config":
			if runtime.GOOS == "windows" {
				showServiceConfig()
			} else {
				fmt.Println("Service configuration is only available on Windows")
			}
			return
		case "help", "--help", "-h":
			fmt.Println("Olm WireGuard VPN Client")
			fmt.Println("\nWindows Service Management:")
			fmt.Println("  install     Install the service")
			fmt.Println("  remove      Remove the service")
			fmt.Println("  start [args]   Start the service with optional arguments")
			fmt.Println("  stop        Stop the service")
			fmt.Println("  status      Show service status")
			fmt.Println("  debug [args]   Run service in debug mode with optional arguments")
			fmt.Println("  logs        Tail the service log file")
			fmt.Println("  config      Show current service configuration")
			fmt.Println("\nExamples:")
			fmt.Println("  olm start --enable-http --http-addr :9452")
			fmt.Println("  olm debug --endpoint https://example.com --id myid --secret mysecret")
			fmt.Println("\nFor console mode, run without arguments or with standard flags.")
			return
		default:
			// get the status and if it is Not Installed then install it first
			status, err := getServiceStatus()
			if err != nil {
				fmt.Printf("Failed to get service status: %v\n", err)
				os.Exit(1)
			}
			if status == "Not Installed" {
				err := installService()
				if err != nil {
					fmt.Printf("Failed to install service: %v\n", err)
					os.Exit(1)
				}
				fmt.Println("Service installed successfully, now running")
			}

			// Pass the remaining arguments (after "debug") to the service
			serviceArgs := os.Args[1:]
			err = debugService(serviceArgs)
			if err != nil {
				fmt.Printf("Failed to debug service: %v\n", err)
				os.Exit(1)
			}
			return
		}
	}

	// Create a context that will be cancelled on interrupt signals
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Run in console mode
	runOlmMainWithArgs(ctx, os.Args[1:])
}

func runOlmMainWithArgs(ctx context.Context, args []string) {
	// Setup Windows event logging if on Windows
	if runtime.GOOS == "windows" {
		setupWindowsEventLog()
	} else {
		// Initialize logger for non-Windows platforms
		logger.Init(nil)
	}

	// Load configuration from file, env vars, and CLI args
	// Priority: CLI args > Env vars > Config file > Defaults
	config, showVersion, showConfig, err := LoadConfig(os.Args[1:])
	if err != nil {
		fmt.Printf("Failed to load configuration: %v\n", err)
		return
	}

	// Handle --show-config flag
	if showConfig {
		config.ShowConfig()
		os.Exit(0)
	}

	olmVersion := "version_replaceme"
	if showVersion {
		fmt.Println("Olm version " + olmVersion)
		os.Exit(0)
	}
	logger.Info("Olm version " + olmVersion)

	config.Version = olmVersion

	if err := SaveConfig(config); err != nil {
		logger.Error("Failed to save full olm config: %v", err)
	} else {
		logger.Debug("Saved full olm config with all options")
	}

	if err := updates.CheckForUpdate("fosrl", "olm", config.Version); err != nil {
		logger.Debug("Failed to check for updates: %v", err)
	}

	// Create a new olm.Config struct and copy values from the main config
	olmConfig := olm.GlobalConfig{
		LogLevel:   config.LogLevel,
		EnableAPI:  config.EnableAPI,
		HTTPAddr:   config.HTTPAddr,
		SocketPath: config.SocketPath,
		Version:    config.Version,
	}

	olm.Init(ctx, olmConfig)
	if err := olm.StartApi(); err != nil {
		logger.Fatal("Failed to start API server: %v", err)
	}

	if config.ID != "" && config.Secret != "" && config.Endpoint != "" {
		tunnelConfig := olm.TunnelConfig{
			Endpoint:             config.Endpoint,
			ID:                   config.ID,
			Secret:               config.Secret,
			UserToken:            config.UserToken,
			MTU:                  config.MTU,
			DNS:                  config.DNS,
			UpstreamDNS:          config.UpstreamDNS,
			InterfaceName:        config.InterfaceName,
			Holepunch:            config.Holepunch,
			TlsClientCert:        config.TlsClientCert,
			PingIntervalDuration: config.PingIntervalDuration,
			PingTimeoutDuration:  config.PingTimeoutDuration,
			OrgID:                config.OrgID,
			OverrideDNS:          config.OverrideDNS,
			EnableUAPI:           true,
			DisableRelay:         true,
		}
		go olm.StartTunnel(tunnelConfig)
	} else {
		logger.Info("Incomplete tunnel configuration, not starting tunnel")
	}

	// Wait for context cancellation (from signals or API shutdown)
	<-ctx.Done()
	logger.Info("Shutdown signal received, cleaning up...")

	// Clean up resources
	olm.Close()
	logger.Info("Shutdown complete")
}
