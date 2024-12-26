package main

import (
	"fmt"
	"time"
)

type Logger struct {
	debug bool
}

func NewLogger(debug bool) *Logger {
	return &Logger{debug: debug}
}

func (l *Logger) Info(format string, args ...interface{}) {
	timestamp := time.Now().Format("15:04:05")
	fmt.Printf("[%s] %s\n", timestamp, fmt.Sprintf(format, args...))
}

func (l *Logger) Debug(format string, args ...interface{}) {
	if l.debug {
		timestamp := time.Now().Format("15:04:05")
		fmt.Printf("[%s] DEBUG: %s\n", timestamp, fmt.Sprintf(format, args...))
	}
}

func (l *Logger) Error(format string, args ...interface{}) {
	timestamp := time.Now().Format("15:04:05")
	fmt.Printf("[%s] ERROR: %s\n", timestamp, fmt.Sprintf(format, args...))
}
