package main

import (
	"fmt"
	"strings"
)

// formatPayload replaces placeholders in payload template
func formatPayload(payload string, host string, port int) string {
	replacer := strings.NewReplacer(
		"[host]", host,
		"[port]", fmt.Sprintf("%d", port),
		"[host_port]", fmt.Sprintf("%s:%d", host, port),
		"[crlf]", "\r\n",
		"[ua]", "Mozilla/5.0",
	)
	return replacer.Replace(payload)
}
