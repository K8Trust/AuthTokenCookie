package main

import (
    "context"
    "encoding/json"
    "fmt"
    "io"
    "log"
    "net"
    "net/http"
    "net/url"
    "os"
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
        Timeout: 5 * time.Second,
    }
}

type authResponse struct {
    AccessToken string `json:"accessToken"`
}

type AuthPlugin struct {
    next         http.Handler
    endpointHost string
    endpointPath string
    timeout      time.Duration
    name         string
    logger       *log.Logger
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

    if config.Timeout > 10*time.Second {
        return nil, fmt.Errorf("timeout cannot exceed 10 seconds")
    }

    timeout := config.Timeout
    if timeout <= 0 {
        timeout = 5 * time.Second
    }

    logger := log.New(os.Stdout, "[AuthPlugin] ", log.LstdFlags)
    logger.Printf("Initializing plugin with endpoint: %s, timeout: %v", config.Conf, timeout)

    // Instead of failing on health check, just log the warning
    client := &http.Client{Timeout: 2 * time.Second}
    req, err := http.NewRequest(http.MethodHead, config.Conf, nil)
    if err != nil {
        logger.Printf("[Warning] Failed to create health check request: %v", err)
    } else {
        resp, err := client.Do(req)
        if err != nil {
            logger.Printf("[Warning] Auth endpoint not reachable during initialization: %v", err)
        } else {
            defer resp.Body.Close()
            if resp.StatusCode >= 500 {
                logger.Printf("[Warning] Auth endpoint returned status %d during initialization", resp.StatusCode)
            } else {
                logger.Printf("[Health Check] Endpoint is reachable at %s", config.Conf)
            }
        }
    }

    return &AuthPlugin{
        next:         next,
        endpointHost: parsedURL.Host,
        endpointPath: parsedURL.Path,
        timeout:      timeout,
        name:         name,
        logger:       logger,
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

    authURL := fmt.Sprintf("http://%s%s", a.endpointHost, a.endpointPath)
    a.logger.Printf("Making auth request to: %s for account: %s", authURL, tenant)

    authReq, err := http.NewRequest(http.MethodGet, authURL, nil)
    if err != nil {
        a.logger.Printf("Failed to create auth request: %v", err)
        http.Error(rw, `{"error": "Internal error"}`, http.StatusInternalServerError)
        return
    }
    authReq.Header.Set("x-api-key", apiKey)
    authReq.Header.Set("x-account", tenant)

    client := &http.Client{Timeout: a.timeout}
    resp, err := client.Do(authReq)
    if err != nil {
        if err, ok := err.(net.Error); ok && err.Timeout() {
            a.logger.Printf("Auth request timed out after %v: %v", a.timeout, err)
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

    var authResp authResponse
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

    cfg := &Config{
        Conf:    "http://localhost:9000/test/auth/api-key",
        Timeout: 5 * time.Second,
    }

    handler, err := New(context.Background(), nextHandler, cfg, "auth_cookie")
    if err != nil {
        logger.Fatalf("Failed to create handler: %v", err)
    }

    addr := ":8080"
    logger.Printf("Starting server on %s", addr)
    if err := http.ListenAndServe(addr, handler); err != nil {
        logger.Fatalf("Server failed to start: %v", err)
    }
}