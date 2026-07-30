package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/laflabs-inc/lafsecrets/internal/config"
	"github.com/laflabs-inc/lafsecrets/internal/health"
	"github.com/laflabs-inc/lafsecrets/internal/httpserver"
)

const shutdownTimeout = 10 * time.Second

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	cfg, err := config.Parse(os.Environ())
	if err != nil {
		logger.Error("startup configuration rejected", "error", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stop()

	if err := serve(ctx, cfg, logger); err != nil {
		logger.Error("service stopped", "error", err)
		os.Exit(1)
	}
}

func serve(ctx context.Context, cfg config.Config, logger *slog.Logger) error {
	readiness := &health.Gate{}
	server := httpserver.New(cfg.HTTPAddress, readiness)

	listener, err := net.Listen("tcp", cfg.HTTPAddress)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}

	serveErr := make(chan error, 1)
	go func() {
		serveErr <- server.Serve(listener)
	}()

	readiness.MarkReady()
	logger.Info("service ready", "runtime_mode", cfg.RuntimeMode)

	select {
	case err := <-serveErr:
		readiness.MarkNotReady()
		if err == nil || errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("serve: %w", err)
	case <-ctx.Done():
		readiness.MarkNotReady()

		shutdownCtx, cancel := context.WithTimeout(
			context.Background(),
			shutdownTimeout,
		)
		defer cancel()

		if err := server.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shutdown: %w", err)
		}

		err := <-serveErr
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("serve after shutdown: %w", err)
		}
		return nil
	}
}
