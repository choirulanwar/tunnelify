package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	// Parse command line flags
	configPath := flag.String("config", "", "Path to custom config file")
	flag.Parse()

	// Load configuration first
	config, err := LoadConfig(*configPath)
	if err != nil {
		fmt.Printf("Failed to load config: %v\n", err)
		os.Exit(1)
	}

	// Initialize logger with debug from config
	logger := NewLogger(config.Debug)

	// Create SSH client
	sshReady := make(chan bool, 1)
	client := NewSSHClient(
		config.SSH.Host,
		config.SSH.Port,
		config.Port,
		config.SSH.Username,
		config.SSH.Password,
		config,
		sshReady,
		logger,
	)

	// Handle shutdown gracefully
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		logger.Info("Shutting down...")
		if client != nil {
			if client.client != nil {
				client.client.Close()
			}
		}
		os.Exit(0)
	}()

	// Start SSH client
	if err := client.Start(); err != nil {
		logger.Error("Failed to start: %v", err)
		os.Exit(1)
	}
}
