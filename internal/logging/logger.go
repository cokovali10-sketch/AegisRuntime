package logging

import (
	"log/slog"
	"os"
	"path/filepath"
)

var Logger *slog.Logger

func Init(level string, logFile string) {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{
		Level: lvl,
	}

	var handler slog.Handler
	if logFile != "" {
		if err := os.MkdirAll(filepath.Dir(logFile), 0o755); err == nil {
			f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
			if err == nil {
				handler = slog.NewJSONHandler(f, opts)
			}
		}
	}

	if handler == nil {
		handler = slog.NewJSONHandler(os.Stderr, opts)
	}

	Logger = slog.New(handler)
	slog.SetDefault(Logger)
}

func WithContainer(id string) *slog.Logger {
	if Logger == nil {
		Init("info", "")
	}
	return Logger.With("container_id", id)
}

func WithAgent(id string) *slog.Logger {
	if Logger == nil {
		Init("info", "")
	}
	return Logger.With("agent_id", id)
}
