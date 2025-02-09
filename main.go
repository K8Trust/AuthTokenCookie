package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"time"
)

// Config holds the plugin configuration.
type Config struct {
	AuthEndpoint string        `json:"authEndpoint,omitempty"`
	Timeout      time.Duration `json:"timeout,omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		AuthEndpoint: "http://localhost:9000/test/auth/api-key",
		Timeout:      Timeout,
	}
}

type AuthResponse struct {
	AccessToken string `json:"accessToken"`
}

type AuthPlugin struct {
	next         http.Handler
	authEndpoint string
	name         string
	logger       *log.Logger
}

const Timeout = 30 * time.Second

// New creates a new instance of the plugin.
func New(_ context.Context, next http.Handler, cfg *Config, name string) (http.Handler, error) {
	if cfg.AuthEndpoint == "" {
		return nil, fmt.Errorf("missing auth endpoint")
	}

	logger := log.New(os.Stdout, "[AuthPlugin] ", log.LstdFlags)
	logger.Printf("Initializing plugin with endpoint: %s, timeout: %v", cfg.AuthEndpoint, Timeout)

	return &AuthPlugin{
		next:         next,
		authEndpoint: cfg.AuthEndpoint,
		logger:       logger,
		name:         name,
	}, nil
}

// maskSensitive masks sensitive data in logs
func maskSensitive(s string) string {
	if len(s) <= 4 {
		return "****"
	}
	return s[:4] + "****"
}

// sameSiteToString converts SameSite value to human-readable string
func sameSiteToString(s http.SameSite) string {
	switch s {
	case http.SameSiteLaxMode:
		return "Lax"
	case http.SameSiteStrictMode:
		return "Strict"
	case http.SameSiteNoneMode:
		return "None"
	default:
		return "DefaultMode"
	}
}

func (a *AuthPlugin) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	apiKey := req.Header.Get("x-api-key")
	tenant := req.Header.Get("x-account")

	a.logger.Printf("Received request from %s with headers: x-api-key: %s, x-account: %s",
		req.RemoteAddr,
		maskSensitive(apiKey),
		tenant)

	if apiKey == "" || tenant == "" {
		a.logger.Printf("Missing required headers from %s", req.RemoteAddr)
		http.Error(rw, `{"error": "Unauthorized"}`, http.StatusUnauthorized)
		return
	}

	authReq, err := http.NewRequest(http.MethodGet, a.authEndpoint, nil)
	if err != nil {
		a.logger.Printf("Failed to create auth request: %v", err)
		http.Error(rw, `{"error": "Internal error"}`, http.StatusInternalServerError)
		return
	}
	authReq.Header.Set("x-api-key", apiKey)
	authReq.Header.Set("x-account", tenant)

	client := &http.Client{Timeout: Timeout}
	resp, err := client.Do(authReq)
	if err != nil {
		if err, ok := err.(net.Error); ok && err.Timeout() {
			a.logger.Printf("Auth request timed out after %v: %v", Timeout, err)
			http.Error(rw, `{"error": "Auth service timeout"}`, http.StatusGatewayTimeout)
			return
		}
		a.logger.Printf("Auth request failed: %v", err)
		http.Error(rw, `{"error": "Internal error"}`, http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		a.logger.Printf("Failed to read auth response: %v", err)
		http.Error(rw, `{"error": "Internal error"}`, http.StatusInternalServerError)
		return
	}

	a.logger.Printf("Auth server response status: %d for account: %s", resp.StatusCode, tenant)

	if resp.StatusCode != http.StatusOK {
		a.logger.Printf("Auth server returned non-200 status: %d, body: %s", resp.StatusCode, string(body))
		rw.WriteHeader(resp.StatusCode)
		_, _ = rw.Write(body)
		return
	}

	var authResp AuthResponse
	if err := json.Unmarshal(body, &authResp); err != nil {
		a.logger.Printf("Failed to parse auth response: %v", err)
		http.Error(rw, `{"error": "Internal error"}`, http.StatusInternalServerError)
		return
	}

	cookie := &http.Cookie{
		Name:     "token",
		Value:    authResp.AccessToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	}
	http.SetCookie(rw, cookie)

	a.logger.Printf("Setting cookie: %s=%s, HttpOnly: %v, Secure: %v, SameSite: %s",
		cookie.Name,
		maskSensitive(cookie.Value),
		cookie.HttpOnly,
		cookie.Secure,
		sameSiteToString(cookie.SameSite))

	a.logger.Printf("Auth successful for account: %s, passing request to next handler", tenant)
	a.next.ServeHTTP(rw, req)
}

func main() {
	logger := log.New(os.Stdout, "[AuthPlugin] ", log.LstdFlags)

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("OK"))
	})

	cfg := CreateConfig()

	handler, err := New(context.Background(), nextHandler, cfg, "auth-cookie")
	if err != nil {
		logger.Fatalf("Failed to create handler: %v", err)
	}

	addr := ":8080"
	logger.Printf("Starting server on %s", addr)
	if err := http.ListenAndServe(addr, handler); err != nil {
		logger.Fatalf("Server failed to start: %v", err)
	}
}
