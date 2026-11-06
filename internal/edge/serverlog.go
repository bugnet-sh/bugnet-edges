package edge

import (
	"context"
	stdlog "log"
	"log/slog"
	"strings"
)

// strangerNoise starts each net/http message that any stranger's connection can cause
var strangerNoise = []string{
	"http: TLS handshake error",
	"http2: server: error reading preface",
	"timeout waiting for SETTINGS frames",
	"http2: server connection error",
	"http2: received GOAWAY",
}

// serverLog is a net/http ErrorLog writing each message to log at its serverLogLevel
func serverLog(log *slog.Logger) *stdlog.Logger {
	return stdlog.New(serverLogWriter{log: log}, "", 0)
}

type serverLogWriter struct {
	log *slog.Logger
}

func (w serverLogWriter) Write(p []byte) (int, error) {
	msg := strings.TrimSuffix(string(p), "\n")
	w.log.Log(context.Background(), serverLogLevel(msg), msg)
	return len(p), nil
}

// serverLogLevel is debug for stranger noise, error for a handler's panic, warn for the rest
func serverLogLevel(msg string) slog.Level {
	for _, prefix := range strangerNoise {
		if strings.HasPrefix(msg, prefix) {
			return slog.LevelDebug
		}
	}
	if strings.HasPrefix(msg, "http: panic serving") ||
		strings.HasPrefix(msg, "http2: panic serving") {
		return slog.LevelError
	}
	return slog.LevelWarn
}
