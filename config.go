package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// OlmConfig holds all configuration options for the Olm client
type OlmConfig struct {
	// Connection settings
	Endpoint  string `json:"endpoint"`
	ID        string `json:"id"`
	Secret    string `json:"secret"`
	OrgID     string `json:"org"`
	UserToken string `json:"userToken"`

	// Network settings
	MTU           int      `json:"mtu"`
	DNS           string   `json:"dns"`
	UpstreamDNS   []string `json:"upstreamDNS"`
	InterfaceName string   `json:"interface"`

	// Logging
	LogLevel string `json:"logLevel"`

	// HTTP server
	EnableAPI  bool   `json:"enableApi"`
	HTTPAddr   string `json:"httpAddr"`
	SocketPath string `json:"socketPath"`

	// Ping settings
	PingInterval string `json:"pingInterval"`
	PingTimeout  string `json:"pingTimeout"`

	// Advanced
	Holepunch     bool   `json:"holepunch"`
	TlsClientCert string `json:"tlsClientCert"`
	OverrideDNS   bool   `json:"overrideDNS"`
	DisableRelay  bool   `json:"disableRelay"`
	// DoNotCreateNewClient bool   `json:"doNotCreateNewClient"`

	// Parsed values (not in JSON)
	PingIntervalDuration time.Duration `json:"-"`
	PingTimeoutDuration  time.Duration `json:"-"`

	// Source tracking (not in JSON)
	sources map[string]string `json:"-"`

	Version string
}

// ConfigSource tracks where each config value came from
type ConfigSource string

const (
	SourceDefault ConfigSource = "default"
	SourceFile    ConfigSource = "file"
	SourceEnv     ConfigSource = "environment"
	SourceCLI     ConfigSource = "cli"
)

// DefaultConfig returns a config with default values
func DefaultConfig() *OlmConfig {
	// Set OS-specific socket path
	var socketPath string
	switch runtime.GOOS {
	case "windows":
		socketPath = "olm"
	default: // darwin, linux, and others
		socketPath = "/var/run/olm.sock"
	}

	config := &OlmConfig{
		MTU:           1280,
		DNS:           "8.8.8.8",
		UpstreamDNS:   []string{"8.8.8.8:53"},
		LogLevel:      "INFO",
		InterfaceName: "olm",
		EnableAPI:     false,
		SocketPath:    socketPath,
		PingInterval:  "3s",
		PingTimeout:   "5s",
		Holepunch:     false,
		// DoNotCreateNewClient: false,
		sources: make(map[string]string),
	}

	// Track default sources
	config.sources["mtu"] = string(SourceDefault)
	config.sources["dns"] = string(SourceDefault)
	config.sources["upstreamDNS"] = string(SourceDefault)
	config.sources["logLevel"] = string(SourceDefault)
	config.sources["interface"] = string(SourceDefault)
	config.sources["enableApi"] = string(SourceDefault)
	config.sources["httpAddr"] = string(SourceDefault)
	config.sources["socketPath"] = string(SourceDefault)
	config.sources["pingInterval"] = string(SourceDefault)
	config.sources["pingTimeout"] = string(SourceDefault)
	config.sources["holepunch"] = string(SourceDefault)
	config.sources["overrideDNS"] = string(SourceDefault)
	config.sources["disableRelay"] = string(SourceDefault)
	// config.sources["doNotCreateNewClient"] = string(SourceDefault)

	return config
}

// getOlmConfigPath returns the path to the olm config file
func getOlmConfigPath() string {
	configFile := os.Getenv("CONFIG_FILE")
	if configFile != "" {
		return configFile
	}

	var configDir string
	switch runtime.GOOS {
	case "darwin":
		configDir = filepath.Join(os.Getenv("HOME"), "Library", "Application Support", "olm-client")
	case "windows":
		configDir = filepath.Join(os.Getenv("PROGRAMDATA"), "olm", "olm-client")
	default: // linux and others
		configDir = filepath.Join(os.Getenv("HOME"), ".config", "olm-client")
	}

	if err := os.MkdirAll(configDir, 0755); err != nil {
		fmt.Printf("Warning: Failed to create config directory: %v\n", err)
	}

	return filepath.Join(configDir, "config.json")
}

// LoadConfig loads configuration from file, env vars, and CLI args
// Priority: CLI args > Env vars > Config file > Defaults
// Returns: (config, showVersion, showConfig, error)
func LoadConfig(args []string) (*OlmConfig, bool, bool, error) {
	// Start with defaults
	config := DefaultConfig()

	// Load from config file (if exists)
	fileConfig, err := loadConfigFromFile()
	if err != nil {
		return nil, false, false, fmt.Errorf("failed to load config file: %w", err)
	}
	if fileConfig != nil {
		mergeConfigs(config, fileConfig)
	}

	// Override with environment variables
	loadConfigFromEnv(config)

	// Override with CLI arguments
	showVersion, showConfig, err := loadConfigFromCLI(config, args)
	if err != nil {
		return nil, false, false, err
	}

	// Parse duration strings
	if err := config.parseDurations(); err != nil {
		return nil, false, false, err
	}

	return config, showVersion, showConfig, nil
}

// loadConfigFromFile loads configuration from the JSON config file
func loadConfigFromFile() (*OlmConfig, error) {
	configPath := getOlmConfigPath()
	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // File doesn't exist, not an error
		}
		return nil, err
	}

	var config OlmConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	return &config, nil
}

// loadConfigFromEnv loads configuration from environment variables
func loadConfigFromEnv(config *OlmConfig) {
	if val := os.Getenv("PANGOLIN_ENDPOINT"); val != "" {
		config.Endpoint = val
		config.sources["endpoint"] = string(SourceEnv)
	}
	if val := os.Getenv("OLM_ID"); val != "" {
		config.ID = val
		config.sources["id"] = string(SourceEnv)
	}
	if val := os.Getenv("OLM_SECRET"); val != "" {
		config.Secret = val
		config.sources["secret"] = string(SourceEnv)
	}
	if val := os.Getenv("ORG"); val != "" {
		config.OrgID = val
		config.sources["org"] = string(SourceEnv)
	}
	if val := os.Getenv("USER_TOKEN"); val != "" {
		config.UserToken = val
		config.sources["userToken"] = string(SourceEnv)
	}
	if val := os.Getenv("MTU"); val != "" {
		if mtu, err := strconv.Atoi(val); err == nil {
			config.MTU = mtu
			config.sources["mtu"] = string(SourceEnv)
		} else {
			fmt.Printf("Invalid MTU value: %s, keeping current value\n", val)
		}
	}
	if val := os.Getenv("DNS"); val != "" {
		config.DNS = val
		config.sources["dns"] = string(SourceEnv)
	}
	if val := os.Getenv("UPSTREAM_DNS"); val != "" {
		config.UpstreamDNS = []string{val}
		config.sources["upstreamDNS"] = string(SourceEnv)
	}
	if val := os.Getenv("LOG_LEVEL"); val != "" {
		config.LogLevel = val
		config.sources["logLevel"] = string(SourceEnv)
	}
	if val := os.Getenv("INTERFACE"); val != "" {
		config.InterfaceName = val
		config.sources["interface"] = string(SourceEnv)
	}
	if val := os.Getenv("HTTP_ADDR"); val != "" {
		config.HTTPAddr = val
		config.sources["httpAddr"] = string(SourceEnv)
	}
	if val := os.Getenv("PING_INTERVAL"); val != "" {
		config.PingInterval = val
		config.sources["pingInterval"] = string(SourceEnv)
	}
	if val := os.Getenv("PING_TIMEOUT"); val != "" {
		config.PingTimeout = val
		config.sources["pingTimeout"] = string(SourceEnv)
	}
	if val := os.Getenv("ENABLE_API"); val == "true" {
		config.EnableAPI = true
		config.sources["enableApi"] = string(SourceEnv)
	}
	if val := os.Getenv("SOCKET_PATH"); val != "" {
		config.SocketPath = val
		config.sources["socketPath"] = string(SourceEnv)
	}
	if val := os.Getenv("HOLEPUNCH"); val == "true" {
		config.Holepunch = true
		config.sources["holepunch"] = string(SourceEnv)
	}
	if val := os.Getenv("OVERRIDE_DNS"); val == "true" {
		config.OverrideDNS = true
		config.sources["overrideDNS"] = string(SourceEnv)
	}
	if val := os.Getenv("DISABLE_RELAY"); val == "true" {
		config.DisableRelay = true
		config.sources["disableRelay"] = string(SourceEnv)
	}
	// if val := os.Getenv("DO_NOT_CREATE_NEW_CLIENT"); val == "true" {
	// 	config.DoNotCreateNewClient = true
	// 	config.sources["doNotCreateNewClient"] = string(SourceEnv)
	// }
}

// loadConfigFromCLI loads configuration from command-line arguments
func loadConfigFromCLI(config *OlmConfig, args []string) (bool, bool, error) {
	serviceFlags := flag.NewFlagSet("service", flag.ContinueOnError)

	// Store original values to detect changes
	origValues := map[string]interface{}{
		"endpoint":     config.Endpoint,
		"id":           config.ID,
		"secret":       config.Secret,
		"org":          config.OrgID,
		"userToken":    config.UserToken,
		"mtu":          config.MTU,
		"dns":          config.DNS,
		"upstreamDNS":  fmt.Sprintf("%v", config.UpstreamDNS),
		"logLevel":     config.LogLevel,
		"interface":    config.InterfaceName,
		"httpAddr":     config.HTTPAddr,
		"socketPath":   config.SocketPath,
		"pingInterval": config.PingInterval,
		"pingTimeout":  config.PingTimeout,
		"enableApi":    config.EnableAPI,
		"holepunch":    config.Holepunch,
		"overrideDNS":  config.OverrideDNS,
		"disableRelay": config.DisableRelay,
		// "doNotCreateNewClient": config.DoNotCreateNewClient,
	}

	// Define flags
	serviceFlags.StringVar(&config.Endpoint, "endpoint", config.Endpoint, "Endpoint of your Pangolin server")
	serviceFlags.StringVar(&config.ID, "id", config.ID, "Olm ID")
	serviceFlags.StringVar(&config.Secret, "secret", config.Secret, "Olm secret")
	serviceFlags.StringVar(&config.OrgID, "org", config.OrgID, "Organization ID")
	serviceFlags.StringVar(&config.UserToken, "user-token", config.UserToken, "User token (optional)")
	serviceFlags.IntVar(&config.MTU, "mtu", config.MTU, "MTU to use")
	serviceFlags.StringVar(&config.DNS, "dns", config.DNS, "DNS server to use")
	var upstreamDNSFlag string
	serviceFlags.StringVar(&upstreamDNSFlag, "upstream-dns", "", "Upstream DNS server(s) (comma-separated, default: 8.8.8.8:53)")
	serviceFlags.StringVar(&config.LogLevel, "log-level", config.LogLevel, "Log level (DEBUG, INFO, WARN, ERROR, FATAL)")
	serviceFlags.StringVar(&config.InterfaceName, "interface", config.InterfaceName, "Name of the WireGuard interface")
	serviceFlags.StringVar(&config.HTTPAddr, "http-addr", config.HTTPAddr, "HTTP server address (e.g., ':9452')")
	serviceFlags.StringVar(&config.SocketPath, "socket-path", config.SocketPath, "Unix socket path (or named pipe on Windows)")
	serviceFlags.StringVar(&config.PingInterval, "ping-interval", config.PingInterval, "Interval for pinging the server")
	serviceFlags.StringVar(&config.PingTimeout, "ping-timeout", config.PingTimeout, "Timeout for each ping")
	serviceFlags.BoolVar(&config.EnableAPI, "enable-api", config.EnableAPI, "Enable API server for receiving connection requests")
	serviceFlags.BoolVar(&config.Holepunch, "holepunch", config.Holepunch, "Enable hole punching")
	serviceFlags.BoolVar(&config.OverrideDNS, "override-dns", config.OverrideDNS, "Override system DNS settings")
	serviceFlags.BoolVar(&config.DisableRelay, "disable-relay", config.DisableRelay, "Disable relay connections")
	// serviceFlags.BoolVar(&config.DoNotCreateNewClient, "do-not-create-new-client", config.DoNotCreateNewClient, "Do not create new client")

	version := serviceFlags.Bool("version", false, "Print the version")
	showConfig := serviceFlags.Bool("show-config", false, "Show configuration sources and exit")

	// Parse the arguments
	if err := serviceFlags.Parse(args); err != nil {
		return false, false, err
	}

	// Parse upstream DNS flag if provided
	if upstreamDNSFlag != "" {
		config.UpstreamDNS = []string{}
		for _, dns := range splitComma(upstreamDNSFlag) {
			if dns != "" {
				config.UpstreamDNS = append(config.UpstreamDNS, dns)
			}
		}
	}

	// Track which values were changed by CLI args
	if config.Endpoint != origValues["endpoint"].(string) {
		config.sources["endpoint"] = string(SourceCLI)
	}
	if config.ID != origValues["id"].(string) {
		config.sources["id"] = string(SourceCLI)
	}
	if config.Secret != origValues["secret"].(string) {
		config.sources["secret"] = string(SourceCLI)
	}
	if config.OrgID != origValues["org"].(string) {
		config.sources["org"] = string(SourceCLI)
	}
	if config.UserToken != origValues["userToken"].(string) {
		config.sources["userToken"] = string(SourceCLI)
	}
	if config.MTU != origValues["mtu"].(int) {
		config.sources["mtu"] = string(SourceCLI)
	}
	if config.DNS != origValues["dns"].(string) {
		config.sources["dns"] = string(SourceCLI)
	}
	if fmt.Sprintf("%v", config.UpstreamDNS) != origValues["upstreamDNS"].(string) {
		config.sources["upstreamDNS"] = string(SourceCLI)
	}
	if config.LogLevel != origValues["logLevel"].(string) {
		config.sources["logLevel"] = string(SourceCLI)
	}
	if config.InterfaceName != origValues["interface"].(string) {
		config.sources["interface"] = string(SourceCLI)
	}
	if config.HTTPAddr != origValues["httpAddr"].(string) {
		config.sources["httpAddr"] = string(SourceCLI)
	}
	if config.SocketPath != origValues["socketPath"].(string) {
		config.sources["socketPath"] = string(SourceCLI)
	}
	if config.PingInterval != origValues["pingInterval"].(string) {
		config.sources["pingInterval"] = string(SourceCLI)
	}
	if config.PingTimeout != origValues["pingTimeout"].(string) {
		config.sources["pingTimeout"] = string(SourceCLI)
	}
	if config.EnableAPI != origValues["enableApi"].(bool) {
		config.sources["enableApi"] = string(SourceCLI)
	}
	if config.Holepunch != origValues["holepunch"].(bool) {
		config.sources["holepunch"] = string(SourceCLI)
	}
	if config.OverrideDNS != origValues["overrideDNS"].(bool) {
		config.sources["overrideDNS"] = string(SourceCLI)
	}
	if config.DisableRelay != origValues["disableRelay"].(bool) {
		config.sources["disableRelay"] = string(SourceCLI)
	}
	// if config.DoNotCreateNewClient != origValues["doNotCreateNewClient"].(bool) {
	// 	config.sources["doNotCreateNewClient"] = string(SourceCLI)
	// }

	return *version, *showConfig, nil
}

// parseDurations parses the duration strings into time.Duration
func (c *OlmConfig) parseDurations() error {
	var err error

	// Parse ping interval
	if c.PingInterval != "" {
		c.PingIntervalDuration, err = time.ParseDuration(c.PingInterval)
		if err != nil {
			fmt.Printf("Invalid PING_INTERVAL value: %s, using default 3 seconds\n", c.PingInterval)
			c.PingIntervalDuration = 3 * time.Second
			c.PingInterval = "3s"
		}
	} else {
		c.PingIntervalDuration = 3 * time.Second
		c.PingInterval = "3s"
	}

	// Parse ping timeout
	if c.PingTimeout != "" {
		c.PingTimeoutDuration, err = time.ParseDuration(c.PingTimeout)
		if err != nil {
			fmt.Printf("Invalid PING_TIMEOUT value: %s, using default 5 seconds\n", c.PingTimeout)
			c.PingTimeoutDuration = 5 * time.Second
			c.PingTimeout = "5s"
		}
	} else {
		c.PingTimeoutDuration = 5 * time.Second
		c.PingTimeout = "5s"
	}

	return nil
}

// mergeConfigs merges source config into destination (only non-empty values)
// Also tracks that these values came from a file
func mergeConfigs(dest, src *OlmConfig) {
	if src.Endpoint != "" {
		dest.Endpoint = src.Endpoint
		dest.sources["endpoint"] = string(SourceFile)
	}
	if src.ID != "" {
		dest.ID = src.ID
		dest.sources["id"] = string(SourceFile)
	}
	if src.Secret != "" {
		dest.Secret = src.Secret
		dest.sources["secret"] = string(SourceFile)
	}
	if src.OrgID != "" {
		dest.OrgID = src.OrgID
		dest.sources["org"] = string(SourceFile)
	}
	if src.UserToken != "" {
		dest.UserToken = src.UserToken
		dest.sources["userToken"] = string(SourceFile)
	}
	if src.MTU != 0 && src.MTU != 1280 {
		dest.MTU = src.MTU
		dest.sources["mtu"] = string(SourceFile)
	}
	if src.DNS != "" && src.DNS != "8.8.8.8" {
		dest.DNS = src.DNS
		dest.sources["dns"] = string(SourceFile)
	}
	if len(src.UpstreamDNS) > 0 && fmt.Sprintf("%v", src.UpstreamDNS) != "[8.8.8.8:53]" {
		dest.UpstreamDNS = src.UpstreamDNS
		dest.sources["upstreamDNS"] = string(SourceFile)
	}
	if src.LogLevel != "" && src.LogLevel != "INFO" {
		dest.LogLevel = src.LogLevel
		dest.sources["logLevel"] = string(SourceFile)
	}
	if src.InterfaceName != "" && src.InterfaceName != "olm" {
		dest.InterfaceName = src.InterfaceName
		dest.sources["interface"] = string(SourceFile)
	}
	if src.HTTPAddr != "" && src.HTTPAddr != ":9452" {
		dest.HTTPAddr = src.HTTPAddr
		dest.sources["httpAddr"] = string(SourceFile)
	}
	if src.SocketPath != "" {
		// Check if it's not the default for any OS
		isDefault := src.SocketPath == "/var/run/olm.sock" || src.SocketPath == "olm"
		if !isDefault {
			dest.SocketPath = src.SocketPath
			dest.sources["socketPath"] = string(SourceFile)
		}
	}
	if src.PingInterval != "" && src.PingInterval != "3s" {
		dest.PingInterval = src.PingInterval
		dest.sources["pingInterval"] = string(SourceFile)
	}
	if src.PingTimeout != "" && src.PingTimeout != "5s" {
		dest.PingTimeout = src.PingTimeout
		dest.sources["pingTimeout"] = string(SourceFile)
	}
	if src.TlsClientCert != "" {
		dest.TlsClientCert = src.TlsClientCert
		dest.sources["tlsClientCert"] = string(SourceFile)
	}
	// For booleans, we always take the source value if explicitly set
	if src.EnableAPI {
		dest.EnableAPI = src.EnableAPI
		dest.sources["enableApi"] = string(SourceFile)
	}
	if src.Holepunch {
		dest.Holepunch = src.Holepunch
		dest.sources["holepunch"] = string(SourceFile)
	}
	if src.OverrideDNS {
		dest.OverrideDNS = src.OverrideDNS
		dest.sources["overrideDNS"] = string(SourceFile)
	}
	if src.DisableRelay {
		dest.DisableRelay = src.DisableRelay
		dest.sources["disableRelay"] = string(SourceFile)
	}
	// if src.DoNotCreateNewClient {
	// 	dest.DoNotCreateNewClient = src.DoNotCreateNewClient
	// 	dest.sources["doNotCreateNewClient"] = string(SourceFile)
	// }
}

// SaveConfig saves the current configuration to the config file
func SaveConfig(config *OlmConfig) error {
	configPath := getOlmConfigPath()
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}
	return os.WriteFile(configPath, data, 0644)
}

// ShowConfig prints the configuration and the source of each value
func (c *OlmConfig) ShowConfig() {
	configPath := getOlmConfigPath()

	fmt.Print("\n=== Olm Configuration ===\n\n")
	fmt.Printf("Config File: %s\n", configPath)

	// Check if config file exists
	if _, err := os.Stat(configPath); err == nil {
		fmt.Printf("Config File Status: ✓ exists\n")
	} else {
		fmt.Printf("Config File Status: ✗ not found\n")
	}

	fmt.Println("\n--- Configuration Values ---")
	fmt.Print("(Format: Setting = Value [source])\n\n")

	// Helper to get source or default
	getSource := func(key string) string {
		if source, ok := c.sources[key]; ok {
			return source
		}
		return string(SourceDefault)
	}

	// Helper to format value (mask secrets)
	formatValue := func(key, value string) string {
		if key == "secret" && value != "" {
			if len(value) > 8 {
				return value[:4] + "****" + value[len(value)-4:]
			}
			return "****"
		}
		if value == "" {
			return "(not set)"
		}
		return value
	}

	// Connection settings
	fmt.Println("Connection:")
	fmt.Printf("  endpoint     = %s [%s]\n", formatValue("endpoint", c.Endpoint), getSource("endpoint"))
	fmt.Printf("  id           = %s [%s]\n", formatValue("id", c.ID), getSource("id"))
	fmt.Printf("  secret       = %s [%s]\n", formatValue("secret", c.Secret), getSource("secret"))
	fmt.Printf("  org          = %s [%s]\n", formatValue("org", c.OrgID), getSource("org"))
	fmt.Printf("  user-token   = %s [%s]\n", formatValue("userToken", c.UserToken), getSource("userToken"))

	// Network settings
	fmt.Println("\nNetwork:")
	fmt.Printf("  mtu          = %d [%s]\n", c.MTU, getSource("mtu"))
	fmt.Printf("  dns          = %s [%s]\n", c.DNS, getSource("dns"))
	fmt.Printf("  upstream-dns = %v [%s]\n", c.UpstreamDNS, getSource("upstreamDNS"))
	fmt.Printf("  interface    = %s [%s]\n", c.InterfaceName, getSource("interface"))

	// Logging
	fmt.Println("\nLogging:")
	fmt.Printf("  log-level    = %s [%s]\n", c.LogLevel, getSource("logLevel"))

	// API server
	fmt.Println("\nAPI Server:")
	fmt.Printf("  enable-api   = %v [%s]\n", c.EnableAPI, getSource("enableApi"))
	fmt.Printf("  http-addr    = %s [%s]\n", c.HTTPAddr, getSource("httpAddr"))
	fmt.Printf("  socket-path  = %s [%s]\n", c.SocketPath, getSource("socketPath"))

	// Timing
	fmt.Println("\nTiming:")
	fmt.Printf("  ping-interval = %s [%s]\n", c.PingInterval, getSource("pingInterval"))
	fmt.Printf("  ping-timeout  = %s [%s]\n", c.PingTimeout, getSource("pingTimeout"))

	// Advanced
	fmt.Println("\nAdvanced:")
	fmt.Printf("  holepunch             = %v [%s]\n", c.Holepunch, getSource("holepunch"))
	fmt.Printf("  override-dns          = %v [%s]\n", c.OverrideDNS, getSource("overrideDNS"))
	fmt.Printf("  disable-relay         = %v [%s]\n", c.DisableRelay, getSource("disableRelay"))
	// fmt.Printf("  do-not-create-new-client = %v [%s]\n", c.DoNotCreateNewClient, getSource("doNotCreateNewClient"))
	if c.TlsClientCert != "" {
		fmt.Printf("  tls-cert              = %s [%s]\n", c.TlsClientCert, getSource("tlsClientCert"))
	}

	// Source legend
	fmt.Println("\n--- Source Legend ---")
	fmt.Println("  default     = Built-in default value")
	fmt.Println("  file        = Loaded from config file")
	fmt.Println("  environment = Set via environment variable")
	fmt.Println("  cli         = Provided as command-line argument")
	fmt.Println("\nPriority: cli > environment > file > default")
	fmt.Println()
}

// splitComma splits a comma-separated string into a slice of trimmed strings
func splitComma(s string) []string {
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}
