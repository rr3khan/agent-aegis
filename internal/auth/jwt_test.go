package auth

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateDevToken(t *testing.T) {
	secret := "test-secret"
	subject := "test-user@example.com"
	scopes := []string{"tools:read", "tools:write"}
	duration := time.Hour

	token, err := GenerateDevToken(secret, subject, scopes, duration)
	require.NoError(t, err)
	assert.NotEmpty(t, token)

	// Verify the token can be parsed
	verifier := NewDevVerifier(secret)
	claims, err := verifier.VerifyToken(token)
	require.NoError(t, err)
	assert.Equal(t, subject, claims.Subject)
	assert.Equal(t, "agent-aegis-dev", claims.Issuer)
	assert.Contains(t, claims.Scopes, "tools:read")
	assert.Contains(t, claims.Scopes, "tools:write")
}

func TestVerifyToken_Valid(t *testing.T) {
	secret := "test-secret"
	verifier := NewDevVerifier(secret)

	token, err := GenerateDevToken(secret, "user@example.com", []string{"tools:status:read"}, time.Hour)
	require.NoError(t, err)

	claims, err := verifier.VerifyToken(token)
	require.NoError(t, err)
	assert.Equal(t, "user@example.com", claims.Subject)
	assert.True(t, claims.HasScope("tools:status:read"))
}

func TestVerifyToken_WithBearerPrefix(t *testing.T) {
	secret := "test-secret"
	verifier := NewDevVerifier(secret)

	token, err := GenerateDevToken(secret, "user@example.com", []string{"tools:read"}, time.Hour)
	require.NoError(t, err)

	claims, err := verifier.VerifyToken("Bearer " + token)
	require.NoError(t, err)
	assert.Equal(t, "user@example.com", claims.Subject)
}

func TestVerifyToken_MissingToken(t *testing.T) {
	verifier := NewDevVerifier("secret")

	_, err := verifier.VerifyToken("")
	assert.ErrorIs(t, err, ErrMissingToken)

	_, err = verifier.VerifyToken("Bearer ")
	assert.ErrorIs(t, err, ErrMissingToken)
}

func TestVerifyToken_InvalidSignature(t *testing.T) {
	token, err := GenerateDevToken("secret1", "user@example.com", []string{"read"}, time.Hour)
	require.NoError(t, err)

	verifier := NewDevVerifier("secret2") // Different secret
	_, err = verifier.VerifyToken(token)
	assert.Error(t, err)
}

func TestVerifyToken_Expired(t *testing.T) {
	secret := "test-secret"

	// Generate a token that expired 1 hour ago
	token, err := GenerateDevToken(secret, "user@example.com", []string{"read"}, -time.Hour)
	require.NoError(t, err)

	verifier := NewDevVerifier(secret)
	_, err = verifier.VerifyToken(token)
	assert.ErrorIs(t, err, ErrTokenExpired)
}

func TestVerifyToken_InvalidFormat(t *testing.T) {
	verifier := NewDevVerifier("secret")

	_, err := verifier.VerifyToken("not.a.valid.token")
	assert.Error(t, err)

	_, err = verifier.VerifyToken("just-random-text")
	assert.Error(t, err)
}

func TestClaims_HasScope(t *testing.T) {
	claims := &Claims{
		Scopes: []string{"tools:read", "tools:write", "admin"},
	}

	assert.True(t, claims.HasScope("tools:read"))
	assert.True(t, claims.HasScope("tools:write"))
	assert.True(t, claims.HasScope("admin"))
	assert.False(t, claims.HasScope("tools:delete"))
	assert.False(t, claims.HasScope(""))
}

func TestClaims_HasAnyScope(t *testing.T) {
	claims := &Claims{
		Scopes: []string{"tools:read", "tools:write"},
	}

	assert.True(t, claims.HasAnyScope("tools:read", "tools:admin"))
	assert.True(t, claims.HasAnyScope("other", "tools:write"))
	assert.False(t, claims.HasAnyScope("admin", "superuser"))
}

func TestParseScopes_SpaceSeparated(t *testing.T) {
	scopes := parseScopes("tools:read tools:write admin")
	assert.Equal(t, []string{"tools:read", "tools:write", "admin"}, scopes)
}

func TestParseScopes_Array(t *testing.T) {
	scopes := parseScopes([]interface{}{"tools:read", "tools:write"})
	assert.Equal(t, []string{"tools:read", "tools:write"}, scopes)
}

func TestParseScopes_StringArray(t *testing.T) {
	scopes := parseScopes([]string{"tools:read", "tools:write"})
	assert.Equal(t, []string{"tools:read", "tools:write"}, scopes)
}

func TestParseScopes_Empty(t *testing.T) {
	assert.Nil(t, parseScopes(nil))
	assert.Empty(t, parseScopes(""))
	assert.Empty(t, parseScopes([]interface{}{}))
}

func TestClaims_IdentitySummary(t *testing.T) {
	claims := &Claims{
		Subject: "user@example.com",
		Issuer:  "test-issuer",
		Scopes:  []string{"tools:read"},
		JTI:     "abc123",
	}

	summary := claims.IdentitySummary()
	assert.Equal(t, "user@example.com", summary["subject"])
	assert.Equal(t, "test-issuer", summary["issuer"])
	assert.Equal(t, []string{"tools:read"}, summary["scopes"])
	assert.Equal(t, "abc123", summary["jti"])
}

func TestVerifier_AllowedIssuers(t *testing.T) {
	secret := "test-secret"

	token, err := GenerateDevToken(secret, "user@example.com", []string{"read"}, time.Hour)
	require.NoError(t, err)

	// Verifier that only allows specific issuers
	verifier := &JWTVerifier{
		DevSecret:      []byte(secret),
		AllowedIssuers: []string{"other-issuer"}, // Not "agent-aegis-dev"
		ClockSkew:      30 * time.Second,
	}

	_, err = verifier.VerifyToken(token)
	assert.ErrorIs(t, err, ErrInvalidIssuer)

	// Now allow the correct issuer
	verifier.AllowedIssuers = []string{"agent-aegis-dev"}
	claims, err := verifier.VerifyToken(token)
	require.NoError(t, err)
	assert.Equal(t, "user@example.com", claims.Subject)
}
