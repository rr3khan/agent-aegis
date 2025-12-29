// Package main provides a CLI tool to generate JWT tokens for testing.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/rr3khan/agent-aegis/internal/auth"
)

func main() {
	subject := flag.String("sub", "test-user@example.com", "Token subject (user identifier)")
	scopesStr := flag.String("scopes", "tools:demo:read", "Comma-separated list of scopes")
	duration := flag.Duration("duration", time.Hour, "Token validity duration")
	secret := flag.String("secret", "aegis-dev-secret-do-not-use-in-prod", "JWT signing secret")
	decode := flag.String("decode", "", "Decode and display a token instead of generating")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "JWT Token Generator for Agent Aegis\n\n")
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  Generate token:  %s -sub user@example.com -scopes tools:read,tools:write\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  Decode token:    %s -decode <token>\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	if *decode != "" {
		decodeToken(*decode, *secret)
		return
	}

	scopes := parseScopes(*scopesStr)

	token, err := auth.GenerateDevToken(*secret, *subject, scopes, *duration)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating token: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Generated JWT Token:")
	fmt.Println("=====================")
	fmt.Println(token)
	fmt.Println()
	fmt.Println("Token Details:")
	fmt.Printf("  Subject:  %s\n", *subject)
	fmt.Printf("  Scopes:   %v\n", scopes)
	fmt.Printf("  Expires:  %s\n", time.Now().Add(*duration).Format(time.RFC3339))
	fmt.Println()
	fmt.Println("Usage with curl:")
	fmt.Printf("  curl -X POST http://localhost:8081/execute \\\n")
	fmt.Printf("    -H 'Authorization: Bearer %s' \\\n", token)
	fmt.Printf("    -H 'Content-Type: application/json' \\\n")
	fmt.Printf("    -d '{\"tool\": \"get_weather\", \"args\": {\"location\": \"London\"}}'\n")
}

func parseScopes(scopesStr string) []string {
	if scopesStr == "" {
		return nil
	}
	parts := strings.Split(scopesStr, ",")
	scopes := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			scopes = append(scopes, p)
		}
	}
	return scopes
}

func decodeToken(token, secret string) {
	verifier := auth.NewDevVerifier(secret)
	claims, err := verifier.VerifyToken(token)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error decoding token: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Token Claims:")
	fmt.Println("=============")
	fmt.Printf("  Subject:    %s\n", claims.Subject)
	fmt.Printf("  Issuer:     %s\n", claims.Issuer)
	fmt.Printf("  Audience:   %v\n", claims.Audience)
	fmt.Printf("  Scopes:     %v\n", claims.Scopes)
	fmt.Printf("  Issued At:  %s\n", time.Unix(claims.IssuedAt, 0).Format(time.RFC3339))
	fmt.Printf("  Expires At: %s\n", time.Unix(claims.ExpiresAt, 0).Format(time.RFC3339))
	fmt.Printf("  JWT ID:     %s\n", claims.JTI)

	if time.Now().Unix() > claims.ExpiresAt {
		fmt.Println("\n⚠️  Warning: This token has expired!")
	}
}
