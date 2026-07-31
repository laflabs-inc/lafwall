//go:build integration

package httpserver

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/laflabs-inc/lafsecrets/internal/health"
)

func TestIntegrationOperationalProbeLifecycle(t *testing.T) {
	t.Parallel()

	readiness := &health.Gate{}
	server := New("127.0.0.1:0", readiness)
	listener, err := net.Listen("tcp", server.Addr)
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}

	serveErr := make(chan error, 1)
	go func() {
		serveErr <- server.Serve(listener)
	}()

	t.Cleanup(func() {
		readiness.MarkNotReady()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		if err := server.Shutdown(ctx); err != nil {
			t.Errorf("server.Shutdown() error = %v", err)
		}
		if err := <-serveErr; err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("server.Serve() error = %v", err)
		}
	})

	client := &http.Client{Timeout: 2 * time.Second}
	baseURL := "http://" + listener.Addr().String()

	assertHTTPStatus(t, client, baseURL+"/livez", http.StatusNoContent)
	assertHTTPStatus(t, client, baseURL+"/readyz", http.StatusServiceUnavailable)

	readiness.MarkReady()
	assertHTTPStatus(t, client, baseURL+"/readyz", http.StatusNoContent)

	readiness.MarkNotReady()
	assertHTTPStatus(t, client, baseURL+"/readyz", http.StatusServiceUnavailable)
}

func assertHTTPStatus(
	t *testing.T,
	client *http.Client,
	url string,
	wantStatus int,
) {
	t.Helper()

	response, err := client.Get(url)
	if err != nil {
		t.Fatalf("GET %s error = %v", url, err)
	}
	defer response.Body.Close()

	if response.StatusCode != wantStatus {
		t.Fatalf("GET %s status = %d, want %d", url, response.StatusCode, wantStatus)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read GET %s response body: %v", url, err)
	}
	if len(body) != 0 {
		t.Fatalf("GET %s response body length = %d, want 0", url, len(body))
	}
}
