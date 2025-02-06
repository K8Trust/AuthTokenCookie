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
	if timeout <= 0 {
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
	apiKey := req.Header.Get("x-api-key")
	tenant := req.Header.Get("x-account")

	fmt.Println("Received request with headers:")
	fmt.Println("x-api-key:", apiKey)
	fmt.Println("x-account:", tenant)

	if apiKey == "" || tenant == "" {
		fmt.Println("Missing required headers, returning 401")
		http.Error(rw, `{"error": "Unauthorized"}`, http.StatusUnauthorized)
		return
	}

	authURL := fmt.Sprintf("http://%s%s", a.endpointHost, a.endpointPath)
	fmt.Println("Auth URL:", authURL)

	authReq, err := http.NewRequest(http.MethodGet, authURL, nil)
	if err != nil {
		fmt.Println("Failed to create auth request:", err)
		http.Error(rw, `{"error": "Internal error"}`, http.StatusInternalServerError)
		return
	}
	authReq.Header.Set("x-api-key", apiKey)
	authReq.Header.Set("x-account", tenant)

	client := &http.Client{Timeout: a.timeout}
	resp, err := client.Do(authReq)
	if err != nil {
		fmt.Println("Auth request failed:", err)
		http.Error(rw, `{"error": "Internal error"}`, http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Failed to read auth response:", err)
		http.Error(rw, `{"error": "Internal error"}`, http.StatusInternalServerError)
		return
	}

	fmt.Println("Auth server response:", string(body))

	if resp.StatusCode != http.StatusOK {
		fmt.Println("Auth server returned non-200:", resp.StatusCode)
		rw.WriteHeader(resp.StatusCode)
		_, _ = rw.Write(body)
		return
	}

	var authResp authResponse
	if err := json.Unmarshal(body, &authResp); err != nil {
		fmt.Println("Failed to parse auth response JSON:", err)
		http.Error(rw, `{"error": "Internal error"}`, http.StatusInternalServerError)
		return
	}

	cookie := &http.Cookie{
		Name:     "token",
		Value:    authResp.AccessToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
	}
	http.SetCookie(rw, cookie)
	fmt.Println("Auth successful, cookie set, passing request to next handler")
	a.next.ServeHTTP(rw, req)
}

func main() {
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("OK"))
	})

	cfg := &Config{
		Conf:    "http://localhost:9000/test/auth/api-key", // Change to actual auth server URL
		Timeout: 30 * time.Second,
	}

	handler, err := New(context.Background(), nextHandler, cfg, "auth_cookie")
	if err != nil {
		panic(err)
	}

	fmt.Println("Starting server on :8080")
	if err := http.ListenAndServe(":8080", handler); err != nil {
		panic(err)
	}
}