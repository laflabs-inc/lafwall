package httpserver

import (
	"net/http"
	"time"
)

const (
	maxHeaderBytes    = 16 << 10
	readHeaderTimeout = 5 * time.Second
	readTimeout       = 10 * time.Second
	writeTimeout      = 10 * time.Second
	idleTimeout       = 60 * time.Second
)

type Readiness interface {
	Ready() bool
}

func New(address string, readiness Readiness) *http.Server {
	return &http.Server{
		Addr:              address,
		Handler:           NewHandler(readiness),
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
	}
}

func NewHandler(readiness Readiness) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/livez", operationalProbe(func() bool {
		return true
	}))
	mux.Handle("/readyz", operationalProbe(func() bool {
		return readiness != nil && readiness.Ready()
	}))
	return mux
}

func operationalProbe(healthy func() bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")

		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		if !healthy() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	})
}
