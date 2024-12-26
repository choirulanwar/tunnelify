# Tunnelify

SSH tunneling tool with SOCKS5 proxy and custom payload injection support.

## Features

- 🔒 SSH tunneling with custom payload
- 🌐 SOCKS5 proxy
- 🔄 Auto reconnect
- 📊 Connection monitoring
- 🔍 Health check

## Quick Start

Build:
```bash
go build -o tunnelify
```

Run:
```bash
./tunnelify
```

Or with custom config:
```bash
./tunnelify -config /path/to/config.yaml
```

The SOCKS5 proxy will be available at `127.0.0.1:1080`

## Default Config

Config file location: `~/.tunnelify/config.yaml`

```yaml
mode:
  connection_mode: 1
  auto_replace: true

ssh:
  host: "example.com"
  port: 80
  username: "username"
  password: "password"
  enable_compression: true
  auth_method: "password"

payload:
  payload: "GET / HTTP/1.1[crlf]Host: [host_port][crlf]Connection: Websocket[crlf]User-Agent: [ua][crlf]Upgrade: websocket[crlf][crlf]"
  proxyip: "example.com"
  proxyport: 80

sni:
  server_name: "example.com"

monitor:
  ping_url: "https://dns.google"
  max_reconnect_attempts: 10
  reconnect_delay: 5
  enable_auto_ping: true
  ping_interval: 5
  max_ping_failures: 3

port: 1080
debug: false
```
