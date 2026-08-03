package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/rektone666/browsersec/internal/core"
	webassets "github.com/rektone666/browsersec/web"
)

type LocalServer struct {
	listener   net.Listener
	httpServer *http.Server
	token      string
	resultCh   chan core.ScanPayload
	resultOnce sync.Once
	logger     *log.Logger
}

func New(logger *log.Logger) (*LocalServer, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("listen on loopback: %w", err)
	}

	tokenBytes := make([]byte, 24)
	if _, err := rand.Read(tokenBytes); err != nil {
		listener.Close()
		return nil, fmt.Errorf("create scan token: %w", err)
	}

	s := &LocalServer{
		listener: listener,
		token:    hex.EncodeToString(tokenBytes),
		resultCh: make(chan core.ScanPayload, 1),
		logger:   logger,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/assets/app.js", s.handleAsset("app.js", "application/javascript; charset=utf-8"))
	mux.HandleFunc("/assets/styles.css", s.handleAsset("styles.css", "text/css; charset=utf-8"))
	mux.HandleFunc("/sw.js", s.handleAsset("sw.js", "application/javascript; charset=utf-8"))
	mux.HandleFunc("/third-party.html", s.handleThirdParty)
	mux.HandleFunc("/api/headers", s.handleHeaders)
	mux.HandleFunc("/api/results", s.handleResults)
	mux.HandleFunc("/api/health", s.handleHealth)

	s.httpServer = &http.Server{
		Handler:           s.securityHeaders(mux),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	return s, nil
}

func (s *LocalServer) URL() string {
	return fmt.Sprintf("http://127.0.0.1:%d/?token=%s", s.Port(), s.token)
}

func (s *LocalServer) Port() int {
	return s.listener.Addr().(*net.TCPAddr).Port
}

func (s *LocalServer) Results() <-chan core.ScanPayload { return s.resultCh }

func (s *LocalServer) Start() {
	go func() {
		if err := s.httpServer.Serve(s.listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.logger.Printf("local server error: %v", err)
		}
	}()
}

func (s *LocalServer) Stop(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}

func (s *LocalServer) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store, max-age=0")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		w.Header().Set("Cross-Origin-Embedder-Policy", "require-corp")
		w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
		w.Header().Set("Accept-CH", "Sec-CH-UA-Arch, Sec-CH-UA-Bitness, Sec-CH-UA-Full-Version-List, Sec-CH-UA-Model, Sec-CH-UA-Platform-Version, Sec-CH-UA-WoW64, Sec-CH-UA-Form-Factors")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-src http://localhost:* http://127.0.0.1:*; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; require-trusted-types-for 'script'; trusted-types browsersec")
		next.ServeHTTP(w, r)
	})
}

func (s *LocalServer) handleAsset(name, contentType string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		data, err := webassets.Assets.ReadFile(name)
		if err != nil {
			http.Error(w, "asset unavailable", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", contentType)
		_, _ = w.Write(data)
	}
}

func (s *LocalServer) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.URL.Query().Get("token") != s.token {
		http.Error(w, "invalid or expired scan link", http.StatusForbidden)
		return
	}
	data, err := webassets.Assets.ReadFile("index.html")
	if err != nil {
		http.Error(w, "scanner interface unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(data)
}

func (s *LocalServer) handleThirdParty(w http.ResponseWriter, r *http.Request) {
	// This endpoint is deliberately accessible as localhost while the top-level
	// scanner uses 127.0.0.1, creating a best-effort cross-site loopback test.
	w.Header().Set("Cross-Origin-Resource-Policy", "cross-origin")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; connect-src 'none'; style-src 'none'; img-src 'none'; frame-ancestors http://127.0.0.1:*")
	w.Header().Add("Set-Cookie", "browsersec_third_party=1; Path=/; SameSite=None; Secure")
	data, err := webassets.Assets.ReadFile("third-party.html")
	if err != nil {
		http.Error(w, "third-party test unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(data)
}

func (s *LocalServer) handleHeaders(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.URL.Query().Get("token") != s.token {
		http.Error(w, "invalid token", http.StatusForbidden)
		return
	}

	headers := make(map[string]string, len(r.Header))
	for name, values := range r.Header {
		lower := strings.ToLower(name)
		if lower == "cookie" || lower == "authorization" || lower == "proxy-authorization" {
			continue
		}
		headers[name] = strings.Join(values, ", ")
	}
	response := map[string]any{
		"headers": headers,
		"method":  r.Method,
		"proto":   r.Proto,
		"host":    r.Host,
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *LocalServer) handleResults(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.URL.Query().Get("token") != s.token {
		http.Error(w, "invalid token", http.StatusForbidden)
		return
	}

	body := http.MaxBytesReader(w, r.Body, 4<<20)
	defer body.Close()
	decoder := json.NewDecoder(body)
	decoder.UseNumber()
	var payload core.ScanPayload
	if err := decoder.Decode(&payload); err != nil {
		http.Error(w, "invalid scan result", http.StatusBadRequest)
		return
	}
	if payload.Meta.Version == "" || len(payload.Findings) == 0 || len(payload.Findings) > 200 {
		http.Error(w, "incomplete scan result", http.StatusBadRequest)
		return
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		http.Error(w, "invalid trailing data", http.StatusBadRequest)
		return
	}

	accepted := false
	s.resultOnce.Do(func() {
		s.resultCh <- payload
		accepted = true
	})
	if !accepted {
		writeJSON(w, http.StatusConflict, map[string]any{"accepted": false, "message": "scan already submitted"})
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"accepted": true})
}

func (s *LocalServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "version": core.Version})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
