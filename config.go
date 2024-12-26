package main

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Mode    ModeConfig    `yaml:"mode"`
	SSH     SSHConfig     `yaml:"ssh"`
	Payload PayloadConfig `yaml:"payload"`
	SNI     SNIConfig     `yaml:"sni"`
	Monitor MonitorConfig `yaml:"monitor"`
	Port    int           `yaml:"port"`
	Debug   bool          `yaml:"debug"`
}

type ModeConfig struct {
	ConnectionMode int  `yaml:"connection_mode"`
	AutoReplace    bool `yaml:"auto_replace"`
}

type SSHConfig struct {
	Host              string `yaml:"host"`
	Port              int    `yaml:"port"`
	Username          string `yaml:"username"`
	Password          string `yaml:"password"`
	EnableCompression bool   `yaml:"enable_compression"`
	AuthMethod        string `yaml:"auth_method"`
}

type PayloadConfig struct {
	Payload   string `yaml:"payload"`
	ProxyIP   string `yaml:"proxyip"`
	ProxyPort int    `yaml:"proxyport"`
}

type SNIConfig struct {
	ServerName string `yaml:"server_name"`
}

type MonitorConfig struct {
	PingURL              string `yaml:"ping_url"`
	MaxReconnectAttempts int    `yaml:"max_reconnect_attempts"`
	ReconnectDelay       int    `yaml:"reconnect_delay"`
	EnableAutoPing       bool   `yaml:"enable_auto_ping"`
	PingInterval         int    `yaml:"ping_interval"`
	MaxPingFailures      int    `yaml:"max_ping_failures"`
}

var defaultConfig = Config{
	Port:  1080,
	Debug: false,
	Mode: ModeConfig{
		ConnectionMode: 1,
		AutoReplace:    true,
	},
	Payload: PayloadConfig{
		Payload:   "GET / HTTP/1.1[crlf]Host: [host_port][crlf]Connection: Websocket[crlf]User-Agent: [ua][crlf]Upgrade: websocket[crlf][crlf]",
		ProxyIP:   "example.com",
		ProxyPort: 80,
	},
	SSH: SSHConfig{
		Host:              "example.com",
		Port:              80,
		Username:          "username",
		Password:          "password",
		EnableCompression: true,
		AuthMethod:        "password",
	},
	SNI: SNIConfig{
		ServerName: "example.com",
	},
	Monitor: MonitorConfig{
		EnableAutoPing:       true,
		PingURL:              "https://dns.google",
		PingInterval:         5,
		MaxPingFailures:      3,
		ReconnectDelay:       5,
		MaxReconnectAttempts: 10,
	},
}

func getConfigDir() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(homeDir, ".tunnelify"), nil
}

func ensureConfigDir() error {
	configDir, err := getConfigDir()
	if err != nil {
		return err
	}

	// Create directory if it doesn't exist
	if _, err := os.Stat(configDir); os.IsNotExist(err) {
		if err := os.MkdirAll(configDir, 0755); err != nil {
			return err
		}

		// Create default config file
		configPath := filepath.Join(configDir, "config.yaml")
		data, err := yaml.Marshal(defaultConfig)
		if err != nil {
			return err
		}

		if err := os.WriteFile(configPath, data, 0644); err != nil {
			return err
		}
	}
	return nil
}

func LoadConfig(customPath string) (*Config, error) {
	var configPath string

	if customPath != "" {
		// If custom path is relative, make it relative to current directory
		if !filepath.IsAbs(customPath) {
			pwd, err := os.Getwd()
			if err != nil {
				return nil, err
			}
			configPath = filepath.Join(pwd, customPath)
		} else {
			configPath = customPath
		}
	} else {
		// Use default config path
		configDir, err := getConfigDir()
		if err != nil {
			return nil, err
		}
		configPath = filepath.Join(configDir, "config.yaml")
	}

	// Ensure config directory and default config exist
	if err := ensureConfigDir(); err != nil {
		return nil, fmt.Errorf("failed to setup config directory: %v", err)
	}

	// Read and parse config file
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	return &config, nil
}
