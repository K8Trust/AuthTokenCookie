// main.go
//
// Package main implements an HTTP middleware plugin that performs an authentication
// check by calling an internal auth server. It then sets a cookie in the response
// containing the access token with HttpOnly and Secure flags enabled.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// Config holds the plugin configuration.
type Config struct {
	// Conf should be a full URL (e.g., "http://auth-service/verify")
	// This will be provided through Traefik's plugin configuration
	Conf    string        `json:"conf,omitempty"`
	Timeout time.Duration `json:"timeout,omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		Timeout: 30 * time.Second,
	}
}

// authResponse represents the expected structure of the auth server response.
type authResponse struct {
	AccessToken string `json:"accessToken"`
}

// AuthPlugin holds the necessary components for the plugin.
type AuthPlugin struct {
	next         http.Handler
	endpointHost string
	endpointPath string
	timeout      time.Duration
	name         string
}

// New creates a new instance of the plugin.
func New(_ context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if config.Conf == "" {
		return nil, fmt.Errorf("conf cannot be empty")
	}

	parsedURL, err := url.Parse(config.Conf)
	if err != nil {
		return nil, fmt.Errorf("invalid auth endpoint URL: %v", err)
	}

	timeout := config.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	return &AuthPlugin{
		next:         next,
		endpointHost: parsedURL.Host,
		endpointPath: parsedURL.Path,
		timeout:      timeout,
		name:         name,
	}, nil
}

// ServeHTTP implements the middleware logic.
func (a *AuthPlugin) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	// Extract required headers.
	apiKey := req.Header.Get("x-api-key")
	tenant := req.Header.Get("x-account")
	if apiKey == "" || tenant == "" {
		http.Error(rw, `{"error": "Unauthorized"}`, http.StatusUnauthorized)
		return
	}

	// Build the auth server URL using plain HTTP.
	authURL := fmt.Sprintf("http://%s%s", a.endpointHost, a.endpointPath)
	fmt.Println("Auth URL:", authURL)
	// Create an HTTP request to the auth server.
	authReq, err := http.NewRequest(http.MethodGet, authURL, nil)
	if err != nil {
		http.Error(rw, `{"error": "Internal error"}`, http.StatusInternalServerError)
		return
	}

	// Pass along the necessary headers.
	authReq.Header.Set("x-api-key", apiKey)
	authReq.Header.Set("x-account", tenant)

	// Perform the auth request.
	client := &http.Client{
		Timeout: a.timeout,
	}
	resp, err := client.Do(authReq)
	if err != nil {
		http.Error(rw, `{"error": "Internal error"}`, http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	// Read the response body.
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(rw, `{"error": "Internal error"}`, http.StatusInternalServerError)
		return
	}

	// Propagate non-200 responses from the auth server.
	if resp.StatusCode != http.StatusOK {
		rw.WriteHeader(resp.StatusCode)
		_, _ = rw.Write(body)
		return
	}

	// Parse the JSON response.
	var authResp authResponse
	if err := json.Unmarshal(body, &authResp); err != nil {
		http.Error(rw, `{"error": "Internal error"}`, http.StatusInternalServerError)
		return
	}

	// Set a cookie in the response with the access token.
	cookie := &http.Cookie{
		Name:     "token",
		Value:    authResp.AccessToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		// Optionally, add SameSite, Expires, etc.
	}
	http.SetCookie(rw, cookie)

	// Continue with the next handler.
	a.next.ServeHTTP(rw, req)
}

// main() is provided for local testing purposes. In a production Traefik deployment,
// Traefik would load the plugin using the New() factory.
func main() {
	// A simple downstream handler that echoes "OK".
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("OK"))
	})

	// Configure the plugin with default values
	cfg := &Config{
		// Conf will be provided through the plugin configuration
		Timeout: 30 * time.Second,
	}

	// Create the plugin middleware.
	handler, err := New(context.Background(), nextHandler, cfg, "auth_cookie")
	if err != nil {
		panic(err)
	}

	// Start a local server on port 8080.
	fmt.Println("Starting server on :8080")
	if err := http.ListenAndServe(":8080", handler); err != nil {
		panic(err)
	}
}
