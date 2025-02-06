package main

import (
    "encoding/json"
    "log"
    "net/http"
    "os"
)

type authResponse struct {
    AccessToken string `json:"accessToken"`
}

// maskSensitive masks sensitive data in logs
func maskSensitive(s string) string {
    if len(s) <= 4 {
        return "****"
    }
    return s[:4] + "****"
}

func main() {
    logger := log.New(os.Stdout, "[AuthServer] ", log.LstdFlags)

    http.HandleFunc("/test/auth/api-key", func(w http.ResponseWriter, r *http.Request) {
        // Add method to the log
        logger.Printf("Received %s request from %s with headers: x-api-key: %s, x-account: %s",
            r.Method,
            r.RemoteAddr, 
            maskSensitive(r.Header.Get("x-api-key")),
            r.Header.Get("x-account"))

        // For health checks, just return 200 without processing
        if r.Method == http.MethodHead {
            logger.Printf("[Health Check] Request successful from %s", r.RemoteAddr)
            return
        }

        w.Header().Set("Content-Type", "application/json")
        response := authResponse{AccessToken: "mocked-token"}
        
        if err := json.NewEncoder(w).Encode(response); err != nil {
            logger.Printf("Error encoding response: %v", err)
            http.Error(w, "Internal Server Error", http.StatusInternalServerError)
            return
        }
        
        logger.Printf("Auth request successful, issued token: %s for account: %s", 
            maskSensitive(response.AccessToken),
            r.Header.Get("x-account"))
    })

    addr := ":9000"
    logger.Printf("Mock auth server running on %s", addr)
    if err := http.ListenAndServe(addr, nil); err != nil {
        logger.Fatalf("Server failed to start: %v", err)
    }
}