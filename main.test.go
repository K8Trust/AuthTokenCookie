// main_test.go
package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// fakeAuthServer creates a test HTTP server simulating the auth server.
func fakeAuthServer(t *testing.T, status int, token string) *httptest.Server {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Add cookie before writing status
		cookie := &http.Cookie{
			Name:  "token",
			Value: token,
		}
		http.SetCookie(w, cookie)
		w.WriteHeader(status)
		resp := authResponse{AccessToken: token}
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Fatalf("could not encode response: %v", err)
		}
	})
	return httptest.NewServer(handler)
}

func TestAuthPluginSuccess(t *testing.T) {
	// Create a fake auth server that returns HTTP 200 with a token.
	fakeServer := fakeAuthServer(t, http.StatusOK, "test-token")
	defer fakeServer.Close()
	// fakeServer.URL, // Full URL; our plugin will parse this.
	// Create a config using the fake auth server's URL.

	// Create a simple next handler.
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("OK"))
	})

	cfg := &Config{
		AuthEndpoint: fakeServer.URL,
		Timeout:      Timeout,
	}

	// Create the plugin.
	plugin, err := New(context.Background(), nextHandler, cfg, "auth_cookie")
	if err != nil {
		t.Fatalf("failed to create plugin: %v", err)
	}

	// Create a test request with required headers.
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Header.Set("x-api-key", "dummy")
	req.Header.Set("x-account", "dummy")

	// Record the response.
	rec := httptest.NewRecorder()
	plugin.ServeHTTP(rec, req)
	res := rec.Result()
	defer res.Body.Close()

	// Verify that a cookie named "token" with the correct value is set.
	cookies := res.Cookies()
	if len(cookies) == 0 {
		t.Fatal("expected a cookie to be set in the response")
	}

	found := false
	for _, cookie := range cookies {
		if cookie.Name == "token" && cookie.Value == "test-token" {
			found = true
			if !cookie.HttpOnly {
				t.Error("expected cookie to be HttpOnly")
			}
			if !cookie.Secure {
				t.Error("expected cookie to be Secure")
			}
		}
	}
	if !found {
		t.Errorf("expected cookie with token 'test-token' not found")
	}
}

func TestAuthPluginUnauthorized(t *testing.T) {

	// Next handler that should not be called.
	nextHandler := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Fatal("next handler should not be called for unauthorized requests")
	})

	cfg := CreateConfig()

	// Create the plugin.
	plugin, err := New(context.Background(), nextHandler, cfg, "auth_cookie")
	if err != nil {
		t.Fatalf("failed to create plugin: %v", err)
	}

	// Create a test request without required headers.
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	rec := httptest.NewRecorder()
	plugin.ServeHTTP(rec, req)

	if rec.Result().StatusCode != http.StatusUnauthorized {
		t.Errorf("expected status %d for unauthorized request, got %d", http.StatusUnauthorized, rec.Result().StatusCode)
	}
}
