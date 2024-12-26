package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
)

type SSHClient struct {
	config         *ssh.ClientConfig
	host           string
	port           int
	injectPort     int
	username       string
	password       string
	enableCompress bool
	settings       *Config
	client         *ssh.Client
	readyChan      chan bool
	logger         *Logger
	listener       net.Listener
	connMutex      sync.Mutex
}

const (
	// Optimized buffer sizes
	sendBufferSize    = 16 * 1024 // 16KB for send
	receiveBufferSize = 32 * 1024 // 32KB for receive
)

func NewSSHClient(host string, port, injectPort int, user, password string, settings *Config, readyChan chan bool, logger *Logger) *SSHClient {
	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         time.Second * 10,
	}

	return &SSHClient{
		config:         config,
		host:           host,
		port:           port,
		injectPort:     injectPort,
		username:       user,
		password:       password,
		enableCompress: settings.SSH.EnableCompression,
		settings:       settings,
		readyChan:      readyChan,
		logger:         logger,
	}
}

func (s *SSHClient) simplifyError(err error) string {
	msg := err.Error()

	// Simplify SSH authentication errors
	if strings.Contains(msg, "ssh: unable to authenticate") {
		return "SSH authentication failed: invalid credentials"
	}

	if strings.Contains(msg, "ssh: handshake failed") ||
		strings.Contains(msg, "ssh: overflow reading") ||
		strings.Contains(msg, "ssh: no common algorithm") {
		return "SSH authentication failed: connection error"
	}

	// Simplify connection errors
	if strings.Contains(msg, "connection refused") ||
		strings.Contains(msg, "no route to host") ||
		strings.Contains(msg, "network is unreachable") {
		return "Connection failed"
	}

	// Simplify timeout errors
	if strings.Contains(msg, "timeout") ||
		strings.Contains(msg, "deadline exceeded") {
		return "Connection timeout"
	}

	return msg
}

func (s *SSHClient) copyData(dst io.Writer, src io.Reader) (int64, error) {
	// Use different buffer sizes for send and receive
	var buf []byte
	if _, ok := dst.(*net.TCPConn); ok {
		// If writing to TCP connection (sending), use send buffer
		buf = make([]byte, sendBufferSize)
	} else {
		// If reading from TCP connection (receiving), use receive buffer
		buf = make([]byte, receiveBufferSize)
	}

	// Use io.CopyBuffer with error handling
	var written int64
	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[0:nr])
			if nw < 0 || nr < nw {
				nw = 0
				if ew == nil {
					ew = fmt.Errorf("invalid write")
				}
			}
			written += int64(nw)
			if ew != nil {
				return written, ew
			}
			if nr != nw {
				return written, io.ErrShortWrite
			}
		}
		if er != nil {
			if er != io.EOF {
				return written, er
			}
			break
		}
	}
	return written, nil
}

func (s *SSHClient) handleConnection(local net.Conn) {
	defer local.Close()

	s.connMutex.Lock()
	client := s.client
	s.connMutex.Unlock()

	// Check if SSH client is still valid
	if client == nil {
		s.logger.Debug("SSH client is not connected")
		return
	}

	s.logger.Debug("New SOCKS5 connection from %s", local.RemoteAddr())

	// SOCKS5 handshake
	buffer := make([]byte, 2)
	if _, err := io.ReadFull(local, buffer); err != nil {
		s.logger.Error("Error reading SOCKS version: %v", err)
		return
	}

	// Check SOCKS version
	if buffer[0] != 0x05 {
		s.logger.Error("Unsupported SOCKS version: %d", buffer[0])
		return
	}

	s.logger.Debug("SOCKS5 version check passed")
	nmethods := int(buffer[1])
	methods := make([]byte, nmethods)
	if _, err := io.ReadFull(local, methods); err != nil {
		s.logger.Error("Error reading auth methods: %v", err)
		return
	}

	// Send auth method
	if _, err := local.Write([]byte{0x05, 0x00}); err != nil {
		s.logger.Error("Error sending auth response: %v", err)
		return
	}
	s.logger.Debug("SOCKS5 auth method sent")

	// Read connect request
	header := make([]byte, 4)
	if _, err := io.ReadFull(local, header); err != nil {
		s.logger.Error("Error reading request header: %v", err)
		return
	}

	if header[1] != 0x01 {
		s.logger.Error("Unsupported SOCKS5 command: %d", header[1])
		local.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // Command not supported
		return
	}

	// Get target address
	var targetAddr string
	switch header[3] {
	case 0x01: // IPv4
		ipv4 := make([]byte, 4)
		if _, err := io.ReadFull(local, ipv4); err != nil {
			s.logger.Error("Error reading IPv4: %v", err)
			return
		}
		targetAddr = net.IP(ipv4).String()
		s.logger.Debug("Target IPv4: %s", targetAddr)
	case 0x03: // Domain name
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(local, lenBuf); err != nil {
			s.logger.Error("Error reading domain length: %v", err)
			return
		}
		length := int(lenBuf[0])
		domain := make([]byte, length)
		if _, err := io.ReadFull(local, domain); err != nil {
			s.logger.Error("Error reading domain: %v", err)
			return
		}
		targetAddr = string(domain)
		s.logger.Debug("Target domain: %s", targetAddr)
	case 0x04: // IPv6
		ipv6 := make([]byte, 16)
		if _, err := io.ReadFull(local, ipv6); err != nil {
			s.logger.Error("Error reading IPv6: %v", err)
			return
		}
		targetAddr = net.IP(ipv6).String()
		s.logger.Debug("Target IPv6: %s", targetAddr)
	}

	// Read port
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(local, portBuf); err != nil {
		s.logger.Error("Error reading port: %v", err)
		return
	}
	targetPort := int(portBuf[0])<<8 | int(portBuf[1])
	s.logger.Debug("Target port: %d", targetPort)

	// Create remote connection through SSH tunnel
	remoteAddr := fmt.Sprintf("%s:%d", targetAddr, targetPort)
	s.logger.Debug("Connecting to %s", remoteAddr)

	// Set timeout for connection
	done := make(chan bool, 1)
	var remote net.Conn
	var dialErr error

	go func() {
		// Double check client before dialing
		if s.client != nil {
			remote, dialErr = s.client.Dial("tcp", remoteAddr)
		} else {
			dialErr = fmt.Errorf("SSH client disconnected")
		}
		done <- true
	}()

	select {
	case <-done:
		if dialErr != nil {
			s.logger.Debug("Error connecting to remote: %v", dialErr)
			local.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
			return
		}
	case <-time.After(10 * time.Second):
		s.logger.Debug("Connection timeout after 10 seconds")
		local.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	if remote == nil {
		s.logger.Debug("Remote connection is nil")
		local.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	defer remote.Close()
	s.logger.Debug("Remote connection established")

	// Send success response
	if _, err := local.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		s.logger.Error("Error sending success response: %v", err)
		return
	}
	s.logger.Debug("SOCKS5 connection established")

	// Forward data dengan WaitGroup
	var wg sync.WaitGroup
	wg.Add(2)

	// Set TCP options for better performance on the local connection
	if tcpConn, ok := local.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)
		tcpConn.SetWriteBuffer(1024 * 1024) // 1MB write buffer
		tcpConn.SetReadBuffer(1024 * 1024)  // 1MB read buffer
	}

	uploadChan := make(chan struct{})
	downloadChan := make(chan struct{})

	go func() {
		defer wg.Done()
		defer close(uploadChan)
		n, err := s.copyData(remote, local)
		if err != nil {
			s.logger.Debug("Error copying to remote: %v", err)
		}
		s.logger.Debug("Uploaded %d bytes", n)
		// Safely close write end if supported
		if closer, ok := remote.(interface{ CloseWrite() error }); ok {
			closer.CloseWrite()
		}
	}()

	go func() {
		defer wg.Done()
		defer close(downloadChan)
		n, err := s.copyData(local, remote)
		if err != nil {
			s.logger.Debug("Error copying to local: %v", err)
		}
		s.logger.Debug("Downloaded %d bytes", n)
		// Safely close write end if supported
		if closer, ok := local.(interface{ CloseWrite() error }); ok {
			closer.CloseWrite()
		}
	}()

	// Wait for both upload and download to complete
	<-uploadChan
	<-downloadChan

	s.logger.Debug("Connection closed")
}

func (s *SSHClient) startHealthCheck(reconnectChan chan<- bool) {
	if !s.settings.Monitor.EnableAutoPing {
		return
	}

	interval := 30
	if s.settings.Monitor.PingInterval > 0 {
		interval = s.settings.Monitor.PingInterval
	}

	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	defer ticker.Stop()

	s.logger.Info("Auto ping started (interval: %ds)", interval)

	failureCount := 0
	for range ticker.C {
		// Check if client is still valid
		if s.client == nil {
			s.logger.Error("SSH client disconnected, triggering reconnect...")
			reconnectChan <- true
			return
		}

		start := time.Now()
		resp, err := s.checkConnection()
		duration := time.Since(start)

		if err != nil {
			failureCount++
			// Simplify error message
			errMsg := "timeout"
			if !strings.Contains(err.Error(), "timeout") {
				errMsg = "network error"
			}
			s.logger.Error("HTTP Ping %s (%d/%d)",
				errMsg,
				failureCount,
				s.settings.Monitor.MaxPingFailures)

			if failureCount >= s.settings.Monitor.MaxPingFailures {
				s.logger.Error("Max failures reached, reconnecting...")
				if s.client != nil {
					s.client.Close()
					s.client = nil
				}
				reconnectChan <- true
				return
			}
			continue
		}

		// Reset failure count on successful ping
		if failureCount > 0 {
			failureCount = 0
		}
		s.logger.Info("HTTP Ping %d OK (%dms)",
			resp.StatusCode,
			duration.Milliseconds())
	}
}

func (s *SSHClient) Start() error {
	reconnectChan := make(chan bool, 1)
	reconnectAttempts := 0

	for {
		err := s.Connect()
		if err != nil {
			errMsg := err.Error()

			// Only exit on invalid credentials
			if strings.Contains(errMsg, "SSH authentication failed: invalid credentials") {
				return fmt.Errorf("SSH authentication failed: invalid credentials")
			}

			reconnectAttempts++
			if s.settings.Monitor.MaxReconnectAttempts > 0 && reconnectAttempts >= s.settings.Monitor.MaxReconnectAttempts {
				return fmt.Errorf("max reconnect attempts reached (%d)", reconnectAttempts)
			}

			s.logger.Error("Connection lost: %s", errMsg)
			s.logger.Info("Reconnecting in %d seconds (attempt %d/%d)...",
				s.settings.Monitor.ReconnectDelay,
				reconnectAttempts,
				s.settings.Monitor.MaxReconnectAttempts)
			time.Sleep(time.Duration(s.settings.Monitor.ReconnectDelay) * time.Second)
			continue
		}

		// Reset reconnect attempts on successful connection
		reconnectAttempts = 0

		// Start health check with reconnect channel
		go s.startHealthCheck(reconnectChan)

		// Wait for reconnect signal or connection error
		select {
		case <-reconnectChan:
			s.logger.Info("Reconnecting due to health check failure...")
			time.Sleep(time.Duration(s.settings.Monitor.ReconnectDelay) * time.Second)
			continue
		}
	}
}

func (s *SSHClient) checkConnection() (*http.Response, error) {
	// Parse ping URL
	u, err := url.Parse(s.settings.Monitor.PingURL)
	if err != nil {
		return nil, err
	}

	// Get port from URL scheme
	port := 80
	if u.Scheme == "https" {
		port = 443
	}

	// Create direct connection through SSH tunnel
	conn, err := s.client.Dial("tcp", fmt.Sprintf("%s:%d", u.Host, port))
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// For HTTP connections
	if port == 80 {
		// Send simple HTTP request
		httpReq := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n",
			u.Path, u.Host)
		if _, err := conn.Write([]byte(httpReq)); err != nil {
			return nil, err
		}
	} else {
		// For HTTPS, create TLS connection
		tlsConn := tls.Client(conn, &tls.Config{
			ServerName:         u.Host,
			InsecureSkipVerify: true,
		})
		defer tlsConn.Close()

		if err := tlsConn.Handshake(); err != nil {
			return nil, err
		}

		// Send HTTPS request
		httpReq := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n",
			u.Path, u.Host)
		if _, err := tlsConn.Write([]byte(httpReq)); err != nil {
			return nil, err
		}
	}

	// Create a fake response to maintain compatibility
	return &http.Response{
		Status:     "200 OK",
		StatusCode: 200,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
	}, nil
}

func (s *SSHClient) Connect() error {
	s.connMutex.Lock()
	defer s.connMutex.Unlock()

	// Cleanup any existing connections first
	if s.client != nil {
		s.client.Close()
		s.client = nil
	}

	// Close existing listener if any
	if s.listener != nil {
		s.listener.Close()
		s.listener = nil
	}

	// Initialize connection to proxy server
	s.logger.Info("Connecting to proxy %s port %d", s.settings.Payload.ProxyIP, s.settings.Payload.ProxyPort)

	// Set TCP options for better performance
	dialer := &net.Dialer{
		Timeout: 10 * time.Second,
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				// Enable TCP keepalive
				syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_KEEPALIVE, 1)

				// Set TCP buffer sizes
				syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, 1024*1024) // 1MB receive buffer
				syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF, 1024*1024) // 1MB send buffer

				// Enable TCP_NODELAY (disable Nagle's algorithm)
				syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_NODELAY, 1)
			})
		},
	}

	conn, err := dialer.Dial("tcp", fmt.Sprintf("%s:%d", s.settings.Payload.ProxyIP, s.settings.Payload.ProxyPort))
	if err != nil {
		return fmt.Errorf("%s", s.simplifyError(err))
	}

	// Send HTTP payload
	rawPayload := s.settings.Payload.Payload
	payload := formatPayload(rawPayload, s.host, s.port)
	s.logger.Info("Payload: %s", strings.ReplaceAll(payload, "\r\n", "[crlf]"))
	if _, err := conn.Write([]byte(payload)); err != nil {
		return fmt.Errorf("%s", s.simplifyError(err))
	}

	// Read server response
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		return fmt.Errorf("%s", s.simplifyError(err))
	}
	response := string(buffer[:n])
	statusLine := strings.Split(response, "\r\n")[0]
	s.logger.Info("Response: %s", statusLine)

	// Initialize SSH connection
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, fmt.Sprintf("%s:%d", s.host, s.port), s.config)
	if err != nil {
		return fmt.Errorf("%s", s.simplifyError(err))
	}
	s.logger.Info("SSH-%s %s", sshConn.ServerVersion(), sshConn.ClientVersion())

	s.client = ssh.NewClient(sshConn, chans, reqs)

	// Setup port forwarding with socket reuse
	config := &net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
				syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEPORT, 1)
			})
		},
	}

	listener, err := config.Listen(context.Background(), "tcp", fmt.Sprintf("0.0.0.0:%d", s.injectPort))
	if err != nil {
		return fmt.Errorf("failed to start listener: %v", err)
	}

	s.listener = listener
	localAddr := listener.Addr().(*net.TCPAddr)
	s.logger.Info("LAN address: %s", localAddr.String())
	s.logger.Info("Connected")

	// Start handling connections
	go s.handleConnections(listener)

	return nil
}

func (s *SSHClient) handleConnections(listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			if strings.Contains(err.Error(), "use of closed network connection") {
				return
			}
			s.logger.Debug("Error accepting connection: %v", err)
			continue
		}

		go s.handleConnection(conn)
	}
}
