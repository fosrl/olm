//go:build windows
// +build windows

package api

import (
	"fmt"
	"net"

	"github.com/Microsoft/go-winio"
	"github.com/fosrl/newt/logger"
)

// createSocketListener creates a Windows named pipe listener
func createSocketListener(pipePath string) (net.Listener, error) {
	// Ensure the pipe path has the correct format
	if pipePath[0] != '\\' {
		pipePath = `\\.\pipe\` + pipePath
	}

	// Create a pipe configuration that allows everyone to write
	config := &winio.PipeConfig{
		// Set security descriptor to allow everyone full access
		// This SDDL string grants full access to Everyone (WD) and to the current owner (OW)
		SecurityDescriptor: "D:(A;;GA;;;WD)(A;;GA;;;OW)",
	}

	// Create a named pipe listener using go-winio with the configuration
	listener, err := winio.ListenPipe(pipePath, config)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on named pipe: %w", err)
	}

	logger.Debug("Created named pipe at %s with write access for everyone", pipePath)
	return listener, nil
}

// cleanupSocket is a no-op on Windows as named pipes are automatically cleaned up
func cleanupSocket(pipePath string) {
	logger.Debug("Named pipe %s will be automatically cleaned up", pipePath)
}
