package httpserver

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/laflabs-inc/lafsecrets/internal/health"
)

func TestOperationalProbesExposeOnlyStatus(t *testing.T) {
	t.Parallel()

	readiness := &health.Gate{}
	handler := NewHandler(readiness)

	assertProbe(t, handler, http.MethodGet, "/livez", http.StatusNoContent)
	assertProbe(t, handler, http.MethodGet, "/readyz", http.StatusServiceUnavailable)

	readiness.MarkReady()
	assertProbe(t, handler, http.MethodHead, "/readyz", http.StatusNoContent)

	readiness.MarkNotReady()
	assertProbe(t, handler, http.MethodGet, "/readyz", http.StatusServiceUnavailable)
}

func TestReadinessFailsClosedWithoutProvider(t *testing.T) {
	t.Parallel()

	handler := NewHandler(nil)
	assertProbe(t, handler, http.MethodGet, "/readyz", http.StatusServiceUnavailable)
}

func TestOperationalProbesRejectUnsupportedMethods(t *testing.T) {
	t.Parallel()

	handler := NewHandler(&health.Gate{})
	request := httptest.NewRequest(http.MethodPost, "/livez", nil)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusMethodNotAllowed)
	}
	if response.Header().Get("Allow") != "GET, HEAD" {
		t.Fatalf("Allow = %q, want %q", response.Header().Get("Allow"), "GET, HEAD")
	}
	if response.Body.Len() != 0 {
		t.Fatalf("response body length = %d, want 0", response.Body.Len())
	}
}

func TestServerUsesBoundedHTTPSettings(t *testing.T) {
	t.Parallel()

	server := New("127.0.0.1:8080", &health.Gate{})
	if server.ReadHeaderTimeout <= 0 {
		t.Fatal("ReadHeaderTimeout is not bounded")
	}
	if server.ReadTimeout <= 0 {
		t.Fatal("ReadTimeout is not bounded")
	}
	if server.WriteTimeout <= 0 {
		t.Fatal("WriteTimeout is not bounded")
	}
	if server.IdleTimeout <= 0 {
		t.Fatal("IdleTimeout is not bounded")
	}
	if server.MaxHeaderBytes <= 0 {
		t.Fatal("MaxHeaderBytes is not bounded")
	}
}

func assertProbe(
	t *testing.T,
	handler http.Handler,
	method string,
	path string,
	wantStatus int,
) {
	t.Helper()

	request := httptest.NewRequest(method, path, nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != wantStatus {
		t.Fatalf("%s %s status = %d, want %d", method, path, response.Code, wantStatus)
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf(
			"%s %s Cache-Control = %q, want %q",
			method,
			path,
			response.Header().Get("Cache-Control"),
			"no-store",
		)
	}
	if response.Body.Len() != 0 {
		t.Fatalf(
			"%s %s response body length = %d, want 0",
			method,
			path,
			response.Body.Len(),
		)
	}
}
