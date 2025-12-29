// Package auth provides JWT authentication and verification for Agent Aegis.
package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	ErrMissingToken       = errors.New("missing authorization token")
	ErrInvalidToken       = errors.New("invalid token format")
	ErrTokenExpired       = errors.New("token has expired")
	ErrInvalidSignature   = errors.New("invalid token signature")
	ErrMissingClaims      = errors.New("missing required claims")
	ErrInvalidIssuer      = errors.New("invalid token issuer")
	ErrInvalidAudience    = errors.New("invalid token audience")
)

// Claims represents the JWT claims extracted from a token.
type Claims struct {
	Subject   string   `json:"sub"`
	Issuer    string   `json:"iss"`
	Audience  []string `json:"aud"`
	Scopes    []string `json:"scope"`
	ExpiresAt int64    `json:"exp"`
	IssuedAt  int64    `json:"iat"`
	JTI       string   `json:"jti"` // JWT ID for audit correlation
}

// JWTVerifier handles JWT token verification.
type JWTVerifier struct {
	// DevSecret is used for development/testing (HS256).
	// In production, use JWKS instead.
	DevSecret []byte

	// AllowedIssuers restricts which issuers are trusted.
	// Empty means all issuers are allowed (not recommended for prod).
	AllowedIssuers []string

	// AllowedAudiences restricts which audiences are accepted.
	AllowedAudiences []string

	// ClockSkew allows for clock differences between systems.
	ClockSkew time.Duration
}

// NewDevVerifier creates a verifier for development with a shared secret.
func NewDevVerifier(secret string) *JWTVerifier {
	return &JWTVerifier{
		DevSecret: []byte(secret),
		ClockSkew: 30 * time.Second,
	}
}

// NewVerifier creates a verifier with production settings.
func NewVerifier(allowedIssuers, allowedAudiences []string) *JWTVerifier {
	return &JWTVerifier{
		AllowedIssuers:   allowedIssuers,
		AllowedAudiences: allowedAudiences,
		ClockSkew:        30 * time.Second,
	}
}

// VerifyToken validates a JWT token and extracts claims.
func (v *JWTVerifier) VerifyToken(tokenString string) (*Claims, error) {
	if tokenString == "" {
		return nil, ErrMissingToken
	}

	// Remove "Bearer " prefix if present
	tokenString = strings.TrimPrefix(tokenString, "Bearer ")
	tokenString = strings.TrimSpace(tokenString)

	if tokenString == "" {
		return nil, ErrMissingToken
	}

	// Parse and validate the token
	token, err := jwt.Parse(tokenString, v.keyFunc, 
		jwt.WithLeeway(v.ClockSkew),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrTokenExpired
		}
		if errors.Is(err, jwt.ErrSignatureInvalid) {
			return nil, ErrInvalidSignature
		}
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	if !token.Valid {
		return nil, ErrInvalidToken
	}

	// Extract claims
	claims, err := v.extractClaims(token)
	if err != nil {
		return nil, err
	}

	// Validate issuer if configured
	if len(v.AllowedIssuers) > 0 && !contains(v.AllowedIssuers, claims.Issuer) {
		return nil, ErrInvalidIssuer
	}

	// Validate audience if configured
	if len(v.AllowedAudiences) > 0 && !containsAny(v.AllowedAudiences, claims.Audience) {
		return nil, ErrInvalidAudience
	}

	return claims, nil
}

// keyFunc returns the key for verifying the token signature.
func (v *JWTVerifier) keyFunc(token *jwt.Token) (interface{}, error) {
	// For development, we use HS256 with a shared secret
	if _, ok := token.Method.(*jwt.SigningMethodHMAC); ok {
		if len(v.DevSecret) == 0 {
			return nil, errors.New("no secret configured for HMAC verification")
		}
		return v.DevSecret, nil
	}

	// TODO: Add JWKS support for production RS256/ES256 tokens
	return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
}

// extractClaims extracts our Claims struct from the JWT token.
func (v *JWTVerifier) extractClaims(token *jwt.Token) (*Claims, error) {
	mapClaims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, ErrMissingClaims
	}

	claims := &Claims{}

	// Subject (required)
	if sub, ok := mapClaims["sub"].(string); ok {
		claims.Subject = sub
	} else {
		return nil, fmt.Errorf("%w: sub", ErrMissingClaims)
	}

	// Issuer (optional but recommended)
	if iss, ok := mapClaims["iss"].(string); ok {
		claims.Issuer = iss
	}

	// Audience (can be string or array)
	switch aud := mapClaims["aud"].(type) {
	case string:
		claims.Audience = []string{aud}
	case []interface{}:
		for _, a := range aud {
			if s, ok := a.(string); ok {
				claims.Audience = append(claims.Audience, s)
			}
		}
	}

	// Scopes (space-separated string or array)
	claims.Scopes = parseScopes(mapClaims["scope"])

	// Expiration
	if exp, ok := mapClaims["exp"].(float64); ok {
		claims.ExpiresAt = int64(exp)
	}

	// Issued At
	if iat, ok := mapClaims["iat"].(float64); ok {
		claims.IssuedAt = int64(iat)
	}

	// JWT ID
	if jti, ok := mapClaims["jti"].(string); ok {
		claims.JTI = jti
	}

	return claims, nil
}

// parseScopes handles both space-separated string scopes and array scopes.
func parseScopes(scopeClaim interface{}) []string {
	switch s := scopeClaim.(type) {
	case string:
		// Space-separated scopes (OAuth2 style)
		return strings.Fields(s)
	case []interface{}:
		scopes := make([]string, 0, len(s))
		for _, item := range s {
			if str, ok := item.(string); ok {
				scopes = append(scopes, str)
			}
		}
		return scopes
	case []string:
		return s
	default:
		return nil
	}
}

// HasScope checks if the claims include a specific scope.
func (c *Claims) HasScope(scope string) bool {
	return contains(c.Scopes, scope)
}

// HasAnyScope checks if the claims include any of the given scopes.
func (c *Claims) HasAnyScope(scopes ...string) bool {
	for _, s := range scopes {
		if c.HasScope(s) {
			return true
		}
	}
	return false
}

// contains checks if a string slice contains a value.
func contains(slice []string, val string) bool {
	for _, item := range slice {
		if item == val {
			return true
		}
	}
	return false
}

// containsAny checks if any value from needles is in haystack.
func containsAny(haystack, needles []string) bool {
	for _, needle := range needles {
		if contains(haystack, needle) {
			return true
		}
	}
	return false
}

// GenerateDevToken creates a JWT token for development/testing.
// WARNING: Only use this for development. Never in production.
func GenerateDevToken(secret string, subject string, scopes []string, duration time.Duration) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"sub":   subject,
		"iss":   "agent-aegis-dev",
		"aud":   "agent-aegis",
		"scope": strings.Join(scopes, " "),
		"iat":   now.Unix(),
		"exp":   now.Add(duration).Unix(),
		"jti":   generateJTI(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

// generateJTI creates a simple JWT ID for correlation.
func generateJTI() string {
	h := hmac.New(sha256.New, []byte(fmt.Sprintf("%d", time.Now().UnixNano())))
	h.Write([]byte("aegis"))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))[:16]
}

// IdentitySummary returns a safe-to-log summary of the identity.
func (c *Claims) IdentitySummary() map[string]interface{} {
	return map[string]interface{}{
		"subject": c.Subject,
		"issuer":  c.Issuer,
		"scopes":  c.Scopes,
		"jti":     c.JTI,
	}
}

// MarshalJSON implements custom JSON marshaling for claims.
func (c *Claims) MarshalJSON() ([]byte, error) {
	type Alias Claims
	return json.Marshal(&struct {
		*Alias
	}{
		Alias: (*Alias)(c),
	})
}

