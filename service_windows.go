//go:build windows

package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

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

type olmService struct {
	elog debug.Log
	ctx  context.Context
	stop context.CancelFunc
}

func (s *olmService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown
	changes <- svc.Status{State: svc.StartPending}

	s.elog.Info(1, "Service Execute called, starting main logic")

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
	setupWindowsEventLog()
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

		// Call the main olm function
		runOlmMain(s.ctx)
	}()

	// Wait for either context cancellation or main logic completion
	select {
	case <-s.ctx.Done():
		s.elog.Info(1, "Olm service context cancelled")
	case <-done:
		s.elog.Info(1, "Olm main logic completed")
	}
}

func runService(name string, isDebug bool) {
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

	service := &olmService{elog: elog}
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
		StartType:      mgr.StartAutomatic,
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

func startService() error {
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

	err = s.Start()
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

func isWindowsService() bool {
	isWindowsService, err := svc.IsWindowsService()
	return err == nil && isWindowsService
}

func setupWindowsEventLog() {
	// Create log directory if it doesn't exist
	logDir := filepath.Join(os.Getenv("PROGRAMDATA"), "Olm", "logs")
	err := os.MkdirAll(logDir, 0755)
	if err != nil {
		fmt.Printf("Failed to create log directory: %v\n", err)
		return
	}

	logFile := filepath.Join(logDir, "olm.log")
	file, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		fmt.Printf("Failed to open log file: %v\n", err)
		return
	}
	log.SetOutput(file)
	log.Printf("Olm service logging initialized - log file: %s", logFile)
}
