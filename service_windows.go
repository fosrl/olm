//go:build windows

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/fosrl/newt/logger"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/debug"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	serviceName        = "OlmWireguardService"
	serviceDisplayName = "Olm WireGuard VPN Service"
	serviceDescription = "Olm WireGuard VPN client service for secure network connectivity"
)

// Global variable to store service arguments
var serviceArgs []string

// getServiceArgsPath returns the path where service arguments are stored
func getServiceArgsPath() string {
	logDir := filepath.Join(os.Getenv("PROGRAMDATA"), "olm")
	return filepath.Join(logDir, "service_args.json")
}

// saveServiceArgs saves the service arguments to a file
func saveServiceArgs(args []string) error {
	logDir := filepath.Join(os.Getenv("PROGRAMDATA"), "olm")
	err := os.MkdirAll(logDir, 0755)
	if err != nil {
		return fmt.Errorf("failed to create config directory: %v", err)
	}

	argsPath := getServiceArgsPath()
	data, err := json.Marshal(args)
	if err != nil {
		return fmt.Errorf("failed to marshal service args: %v", err)
	}

	err = os.WriteFile(argsPath, data, 0644)
	if err != nil {
		return fmt.Errorf("failed to write service args: %v", err)
	}

	return nil
}

// loadServiceArgs loads the service arguments from a file
func loadServiceArgs() ([]string, error) {
	argsPath := getServiceArgsPath()
	data, err := os.ReadFile(argsPath)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil // Return empty args if file doesn't exist
		}
		return nil, fmt.Errorf("failed to read service args: %v", err)
	}

	// delete the file after reading
	err = os.Remove(argsPath)
	if err != nil {
		return nil, fmt.Errorf("failed to delete service args file: %v", err)
	}

	var args []string
	err = json.Unmarshal(data, &args)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal service args: %v", err)
	}

	return args, nil
}

type olmService struct {
	elog debug.Log
	ctx  context.Context
	stop context.CancelFunc
	args []string
}

func (s *olmService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown
	changes <- svc.Status{State: svc.StartPending}

	s.elog.Info(1, fmt.Sprintf("Service Execute called with args: %v", args))

	// Load saved service arguments
	savedArgs, err := loadServiceArgs()
	if err != nil {
		s.elog.Error(1, fmt.Sprintf("Failed to load service args: %v", err))
		// Continue with empty args if loading fails
		savedArgs = []string{}
	}

	// Combine service start args with saved args, giving priority to service start args
	finalArgs := []string{}
	if len(args) > 0 {
		// Skip the first arg which is typically the service name
		if len(args) > 1 {
			finalArgs = append(finalArgs, args[1:]...)
		}
		s.elog.Info(1, fmt.Sprintf("Using service start parameters: %v", finalArgs))
	}

	// If no service start parameters, use saved args
	if len(finalArgs) == 0 && len(savedArgs) > 0 {
		finalArgs = savedArgs
		s.elog.Info(1, fmt.Sprintf("Using saved service args: %v", finalArgs))
	}

	s.args = finalArgs

	// Start the main olm functionality
	olmDone := make(chan struct{})
	go func() {
		s.runOlm()
		close(olmDone)
	}()

	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}
	s.elog.Info(1, "Service status set to Running")

	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				changes <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				s.elog.Info(1, "Service stopping")
				changes <- svc.Status{State: svc.StopPending}
				if s.stop != nil {
					s.stop()
				}
				// Wait for main logic to finish or timeout
				select {
				case <-olmDone:
					s.elog.Info(1, "Main logic finished gracefully")
				case <-time.After(10 * time.Second):
					s.elog.Info(1, "Timeout waiting for main logic to finish")
				}
				return false, 0
			default:
				s.elog.Error(1, fmt.Sprintf("Unexpected control request #%d", c))
			}
		case <-olmDone:
			s.elog.Info(1, "Main olm logic completed, stopping service")
			changes <- svc.Status{State: svc.StopPending}
			return false, 0
		}
	}
}

func (s *olmService) runOlm() {
	// Create a context that can be cancelled when the service stops
	s.ctx, s.stop = context.WithCancel(context.Background())

	// Setup logging for service mode
	s.elog.Info(1, "Starting Olm main logic")

	// Run the main olm logic and wait for it to complete
	done := make(chan struct{})
	go func() {
		defer func() {
			if r := recover(); r != nil {
				s.elog.Error(1, fmt.Sprintf("Olm panic: %v", r))
			}
			close(done)
		}()

		// Call the main olm function with stored arguments
		runOlmMainWithArgs(s.ctx, s.args)
	}()

	// Wait for either context cancellation or main logic completion
	select {
	case <-s.ctx.Done():
		s.elog.Info(1, "Olm service context cancelled")
	case <-done:
		s.elog.Info(1, "Olm main logic completed")
	}
}

func runService(name string, isDebug bool, args []string) {
	var err error
	var elog debug.Log

	if isDebug {
		elog = debug.New(name)
		fmt.Printf("Starting %s service in debug mode\n", name)
	} else {
		elog, err = eventlog.Open(name)
		if err != nil {
			fmt.Printf("Failed to open event log: %v\n", err)
			return
		}
	}
	defer elog.Close()

	elog.Info(1, fmt.Sprintf("Starting %s service", name))
	run := svc.Run
	if isDebug {
		run = debug.Run
	}

	service := &olmService{elog: elog, args: args}
	err = run(name, service)
	if err != nil {
		elog.Error(1, fmt.Sprintf("%s service failed: %v", name, err))
		if isDebug {
			fmt.Printf("Service failed: %v\n", err)
		}
		return
	}
	elog.Info(1, fmt.Sprintf("%s service stopped", name))
	if isDebug {
		fmt.Printf("%s service stopped\n", name)
	}
}

func installService() error {
	exepath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %v", err)
	}

	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to service manager: %v", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err == nil {
		s.Close()
		return fmt.Errorf("service %s already exists", serviceName)
	}

	config := mgr.Config{
		ServiceType:    0x10, // SERVICE_WIN32_OWN_PROCESS
		StartType:      mgr.StartManual,
		ErrorControl:   mgr.ErrorNormal,
		DisplayName:    serviceDisplayName,
		Description:    serviceDescription,
		BinaryPathName: exepath,
	}

	s, err = m.CreateService(serviceName, exepath, config)
	if err != nil {
		return fmt.Errorf("failed to create service: %v", err)
	}
	defer s.Close()

	err = eventlog.InstallAsEventCreate(serviceName, eventlog.Error|eventlog.Warning|eventlog.Info)
	if err != nil {
		s.Delete()
		return fmt.Errorf("failed to install event log: %v", err)
	}

	return nil
}

func removeService() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to service manager: %v", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("service %s is not installed", serviceName)
	}
	defer s.Close()

	// Stop the service if it's running
	status, err := s.Query()
	if err != nil {
		return fmt.Errorf("failed to query service status: %v", err)
	}

	if status.State != svc.Stopped {
		_, err = s.Control(svc.Stop)
		if err != nil {
			return fmt.Errorf("failed to stop service: %v", err)
		}

		// Wait for service to stop
		timeout := time.Now().Add(30 * time.Second)
		for status.State != svc.Stopped {
			if timeout.Before(time.Now()) {
				return fmt.Errorf("timeout waiting for service to stop")
			}
			time.Sleep(300 * time.Millisecond)
			status, err = s.Query()
			if err != nil {
				return fmt.Errorf("failed to query service status: %v", err)
			}
		}
	}

	err = s.Delete()
	if err != nil {
		return fmt.Errorf("failed to delete service: %v", err)
	}

	err = eventlog.Remove(serviceName)
	if err != nil {
		return fmt.Errorf("failed to remove event log: %v", err)
	}

	return nil
}

func startService(args []string) error {
	// Save the service arguments as backup
	if len(args) > 0 {
		err := saveServiceArgs(args)
		if err != nil {
			return fmt.Errorf("failed to save service args: %v", err)
		}
	}

	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to service manager: %v", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("service %s is not installed", serviceName)
	}
	defer s.Close()

	// Pass arguments directly to the service start call
	err = s.Start(args...)
	if err != nil {
		return fmt.Errorf("failed to start service: %v", err)
	}

	return nil
}

func stopService() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to service manager: %v", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("service %s is not installed", serviceName)
	}
	defer s.Close()

	status, err := s.Control(svc.Stop)
	if err != nil {
		return fmt.Errorf("failed to stop service: %v", err)
	}

	timeout := time.Now().Add(30 * time.Second)
	for status.State != svc.Stopped {
		if timeout.Before(time.Now()) {
			return fmt.Errorf("timeout waiting for service to stop")
		}
		time.Sleep(300 * time.Millisecond)
		status, err = s.Query()
		if err != nil {
			return fmt.Errorf("failed to query service status: %v", err)
		}
	}

	return nil
}

func debugService(args []string) error {
	// Save the service arguments before starting
	if len(args) > 0 {
		err := saveServiceArgs(args)
		if err != nil {
			return fmt.Errorf("failed to save service args: %v", err)
		}
	}

	// Start the service with the provided arguments
	err := startService(args)
	if err != nil {
		return fmt.Errorf("failed to start service: %v", err)
	}

	// Watch the log file
	return watchLogFile(true)
}

func watchLogFile(end bool) error {
	logDir := filepath.Join(os.Getenv("PROGRAMDATA"), "olm", "logs")
	logPath := filepath.Join(logDir, "olm.log")

	// Ensure the log directory exists
	err := os.MkdirAll(logDir, 0755)
	if err != nil {
		return fmt.Errorf("failed to create log directory: %v", err)
	}

	// Wait for the log file to be created if it doesn't exist
	var file *os.File
	for i := 0; i < 30; i++ { // Wait up to 15 seconds
		file, err = os.Open(logPath)
		if err == nil {
			break
		}
		if i == 0 {
			fmt.Printf("Waiting for log file to be created...\n")
		}
		time.Sleep(500 * time.Millisecond)
	}

	if err != nil {
		return fmt.Errorf("failed to open log file after waiting: %v", err)
	}
	defer file.Close()

	// Seek to the end of the file to only show new logs
	_, err = file.Seek(0, 2)
	if err != nil {
		return fmt.Errorf("failed to seek to end of file: %v", err)
	}

	// Set up signal handling for graceful exit
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	// Create a ticker to check for new content
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	buffer := make([]byte, 4096)

	for {
		select {
		case <-sigCh:
			fmt.Printf("\n\nStopping log watch...\n")
			// stop the service if needed
			if end {
				if err := stopService(); err != nil {
					fmt.Printf("Failed to stop service: %v\n", err)
				}
			}
			fmt.Printf("Log watch stopped.\n")
			return nil
		case <-ticker.C:
			// Read new content
			n, err := file.Read(buffer)
			if err != nil && err != io.EOF {
				// Try to reopen the file in case it was recreated
				file.Close()
				file, err = os.Open(logPath)
				if err != nil {
					return fmt.Errorf("error reopening log file: %v", err)
				}
				continue
			}

			if n > 0 {
				// Print the new content
				fmt.Print(string(buffer[:n]))
			}
		}
	}
}

func getServiceStatus() (string, error) {
	m, err := mgr.Connect()
	if err != nil {
		return "", fmt.Errorf("failed to connect to service manager: %v", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		return "Not Installed", nil
	}
	defer s.Close()

	status, err := s.Query()
	if err != nil {
		return "", fmt.Errorf("failed to query service status: %v", err)
	}

	switch status.State {
	case svc.Stopped:
		return "Stopped", nil
	case svc.StartPending:
		return "Starting", nil
	case svc.StopPending:
		return "Stopping", nil
	case svc.Running:
		return "Running", nil
	case svc.ContinuePending:
		return "Continue Pending", nil
	case svc.PausePending:
		return "Pause Pending", nil
	case svc.Paused:
		return "Paused", nil
	default:
		return "Unknown", nil
	}
}

// showServiceConfig displays current saved service configuration
func showServiceConfig() {
	configPath := getServiceArgsPath()
	fmt.Printf("Service configuration file: %s\n", configPath)

	args, err := loadServiceArgs()
	if err != nil {
		fmt.Printf("No saved configuration found or error loading: %v\n", err)
		return
	}

	if len(args) == 0 {
		fmt.Println("No saved service arguments found")
	} else {
		fmt.Printf("Saved service arguments: %v\n", args)
	}
}

func isWindowsService() bool {
	isWindowsService, err := svc.IsWindowsService()
	return err == nil && isWindowsService
}

// rotateLogFile handles daily log rotation
func rotateLogFile(logDir string, logFile string) error {
	// Get current log file info
	info, err := os.Stat(logFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // No current log file to rotate
		}
		return fmt.Errorf("failed to stat log file: %v", err)
	}

	// Check if log file is from today
	now := time.Now()
	fileTime := info.ModTime()

	// If the log file is from today, no rotation needed
	if now.Year() == fileTime.Year() && now.YearDay() == fileTime.YearDay() {
		return nil
	}

	// Create rotated filename with date
	rotatedName := fmt.Sprintf("olm-%s.log", fileTime.Format("2006-01-02"))
	rotatedPath := filepath.Join(logDir, rotatedName)

	// Rename current log file to dated filename
	err = os.Rename(logFile, rotatedPath)
	if err != nil {
		return fmt.Errorf("failed to rotate log file: %v", err)
	}

	// Clean up old log files (keep last 30 days)
	cleanupOldLogFiles(logDir, 30)

	return nil
}

// cleanupOldLogFiles removes log files older than specified days
func cleanupOldLogFiles(logDir string, daysToKeep int) {
	cutoff := time.Now().AddDate(0, 0, -daysToKeep)

	files, err := os.ReadDir(logDir)
	if err != nil {
		return
	}

	for _, file := range files {
		if !file.IsDir() && strings.HasPrefix(file.Name(), "olm-") && strings.HasSuffix(file.Name(), ".log") {
			filePath := filepath.Join(logDir, file.Name())
			info, err := file.Info()
			if err != nil {
				continue
			}

			if info.ModTime().Before(cutoff) {
				os.Remove(filePath)
			}
		}
	}
}

func setupWindowsEventLog() {
	// Create log directory if it doesn't exist
	logDir := filepath.Join(os.Getenv("PROGRAMDATA"), "olm", "logs")
	err := os.MkdirAll(logDir, 0755)
	if err != nil {
		fmt.Printf("Failed to create log directory: %v\n", err)
		return
	}

	logFile := filepath.Join(logDir, "olm.log")

	// Rotate log file if needed
	err = rotateLogFile(logDir, logFile)
	if err != nil {
		fmt.Printf("Failed to rotate log file: %v\n", err)
		// Continue anyway to create new log file
	}

	file, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		fmt.Printf("Failed to open log file: %v\n", err)
		return
	}

	// Set the custom logger output
	logger.GetLogger().SetOutput(file)

	log.Printf("Olm service logging initialized - log file: %s", logFile)
}
