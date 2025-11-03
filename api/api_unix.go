//go:build !windows
// +build !windows

package api

import (
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/fosrl/newt/logger"
)

// createSocketListener creates a Unix domain socket listener
func createSocketListener(socketPath string) (net.Listener, error) {
	// Ensure the directory exists
	dir := filepath.Dir(socketPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create socket directory: %w", err)
	}

	// Remove existing socket file if it exists
	if err := os.RemoveAll(socketPath); err != nil {
		return nil, fmt.Errorf("failed to remove existing socket: %w", err)
	}

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on Unix socket: %w", err)
	}

	// Set socket permissions to allow access
	if err := os.Chmod(socketPath, 0666); err != nil {
		listener.Close()
		return nil, fmt.Errorf("failed to set socket permissions: %w", err)
	}

	logger.Debug("Created Unix socket at %s", socketPath)
	return listener, nil
}

// cleanupSocket removes the Unix socket file
func cleanupSocket(socketPath string) {
	if err := os.Remove(socketPath); err != nil && !os.IsNotExist(err) {
		logger.Error("Failed to remove socket file %s: %v", socketPath, err)
	} else {
		logger.Debug("Removed Unix socket at %s", socketPath)
	}
}
