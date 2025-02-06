package main

import (
    "encoding/json"
    "fmt"
    "net/http"
)

type authResponse struct {
    AccessToken string `json:"accessToken"`
}

func authHandler(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    response := authResponse{AccessToken: "mocked-token"}
    json.NewEncoder(w).Encode(response)
}

func main() {
    http.HandleFunc("/test/auth/api-key", authHandler)
    fmt.Println("Mock auth server running on :9000")
    http.ListenAndServe(":9000", nil)
}
