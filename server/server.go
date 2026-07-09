package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

// Config configures the reference HAX server.
type Config struct {
	// Addr is the listen address (default ":0" for random port).
	Addr string
	// APIKey, if set, is accepted for Bearer auth.
	APIKey string
	// WebhookSecret, if set, signs outgoing webhooks (HMAC-SHA256).
	WebhookSecret string
	// AutoAcceptKnocks controls whether DID knocks are auto-accepted.
	AutoAcceptKnocks *bool
	// BaseURL is the external URL for generating request URLs.
	// If empty, derived from the incoming request Host.
	BaseURL string
	// RateLimit, if > 0, limits requests per IP per minute.
	RateLimit int
}

// Server is the reference HAX API server.
type Server struct {
	config   Config
	store    *store
	mux      *http.ServeMux
	httpSrv  *http.Server
	listener net.Listener
	limiter  *rateLimiter
}

// NewServer creates a reference HAX server.
func NewServer(config Config) *Server {
	autoAccept := true
	if config.AutoAcceptKnocks != nil {
		autoAccept = *config.AutoAcceptKnocks
	}
	config.AutoAcceptKnocks = &autoAccept

	s := &Server{
		config: config,
		store:  newStore(),
	}
	if config.RateLimit > 0 {
		s.limiter = newRateLimiter(config.RateLimit, time.Minute)
	}
	s.mux = http.NewServeMux()
	s.registerRoutes()
	return s
}

const apiPrefix = "/api/v1"

func (s *Server) registerRoutes() {
	mux := s.mux

	// Request endpoints.
	mux.HandleFunc("POST "+apiPrefix+"/requests", s.rateLimit(s.auth(s.handleCreateRequest)))
	mux.HandleFunc("GET "+apiPrefix+"/requests", s.rateLimit(s.auth(s.handleListRequests)))
	mux.HandleFunc("GET "+apiPrefix+"/requests/{id}", s.rateLimit(s.auth(s.handleGetRequest)))
	mux.HandleFunc("PATCH "+apiPrefix+"/requests/{id}", s.rateLimit(s.auth(s.handleUpdateRequest)))
	mux.HandleFunc("POST "+apiPrefix+"/requests/{id}/response", s.rateLimit(s.auth(s.handleSubmitResponse)))

	// Types.
	mux.HandleFunc("GET "+apiPrefix+"/types", s.rateLimit(s.auth(s.handleListTypes)))

	// Knock.
	mux.HandleFunc("GET "+apiPrefix+"/knock/status", s.rateLimit(s.auth(s.handleKnockStatus)))

	// Workspace settings.
	mux.HandleFunc("GET "+apiPrefix+"/workspaces/settings", s.rateLimit(s.auth(s.handleGetWorkspaceSettings)))
	mux.HandleFunc("PATCH "+apiPrefix+"/workspaces/settings", s.rateLimit(s.auth(s.handleWorkspaceSettings)))

	// Admin endpoints (not part of the client SDK, useful for testing).
	mux.HandleFunc("POST "+apiPrefix+"/admin/knock", s.handleAdminKnock)
	mux.HandleFunc("POST "+apiPrefix+"/admin/respond", s.handleAdminRespond)

	// Health check (no auth).
	mux.HandleFunc("GET /healthz", s.handleHealth)

	// Human-facing UI (no auth required).
	s.registerUIRoutes()
}

// auth wraps a handler with authentication.
func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		info, _, err := s.verifyAuth(r)
		if err != nil {
			writeError(w, http.StatusUnauthorized, err.Error())
			return
		}
		ctx := context.WithValue(r.Context(), authContextKey{}, info)
		next(w, r.WithContext(ctx))
	}
}

// Handler returns the HTTP handler for use with httptest or custom servers.
func (s *Server) Handler() http.Handler {
	return s.corsMiddleware(s.mux)
}

// corsMiddleware adds CORS headers for browser-based clients.
func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-HAX-DID, X-HAX-Signature")
		w.Header().Set("Access-Control-Max-Age", "3600")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ListenAndServe starts the server. It blocks until the server is stopped.
func (s *Server) ListenAndServe() error {
	addr := s.config.Addr
	if addr == "" {
		addr = ":0"
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	s.listener = ln
	s.httpSrv = &http.Server{Handler: s.Handler()}
	log.Printf("hax-server: listening on %s", ln.Addr())
	return s.httpSrv.Serve(ln)
}

// BaseURL returns the base URL for API requests (e.g. "http://localhost:PORT/api/v1").
func (s *Server) BaseURL() string {
	host := "localhost:8080"
	if s.listener != nil {
		host = s.listener.Addr().String()
	}
	return "http://" + host + apiPrefix
}

// Shutdown gracefully stops the server.
func (s *Server) Shutdown() error {
	if s.httpSrv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return s.httpSrv.Shutdown(ctx)
	}
	return nil
}

// NewTestServer starts a server on a random port and returns the base URL
// and a cleanup function.
func NewTestServer(config Config) (*Server, string, func()) {
	if config.Addr == "" {
		config.Addr = ":0"
	}
	s := NewServer(config)
	ln, err := net.Listen("tcp", config.Addr)
	if err != nil {
		panic(err)
	}
	s.listener = ln
	s.httpSrv = &http.Server{Handler: s.Handler()}
	go func() {
		_ = s.httpSrv.Serve(ln)
	}()
	baseURL := "http://" + ln.Addr().String() + apiPrefix
	cleanup := func() {
		_ = s.Shutdown()
	}
	return s, baseURL, cleanup
}

// --- JSON helpers ---

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]any{
		"error":  message,
		"status": status,
	})
}

func writeErrorWithDetails(w http.ResponseWriter, status int, message string, details map[string]any) {
	body := map[string]any{
		"error":   message,
		"status":  status,
		"details": details,
	}
	writeJSON(w, status, body)
}

func readJSON(r *http.Request) (map[string]any, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read body: %w", err)
	}
	if len(body) == 0 {
		return map[string]any{}, nil
	}
	var result map[string]any
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}
	return result, nil
}

// requestURL generates the human-facing URL for a request.
func (s *Server) requestURL(id string) string {
	base := s.config.BaseURL
	if base == "" {
		base = s.BaseURL()
	}
	base = strings.TrimRight(base, "/")
	base = strings.TrimSuffix(base, apiPrefix)
	return base + "/hub/r/" + id
}
