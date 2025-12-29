//go:build integration
// +build integration

package integration

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/riyadkhan/agent-aegis/internal/audit"
	"github.com/riyadkhan/agent-aegis/internal/auth"
	"github.com/riyadkhan/agent-aegis/internal/executor"
	"github.com/riyadkhan/agent-aegis/internal/handler"
	"github.com/riyadkhan/agent-aegis/internal/policy"
	"github.com/riyadkhan/agent-aegis/internal/validation"
)

const testSecret = "integration-test-secret"

// TestIntegration_FullAllowedFlow tests the complete flow for an allowed request.
func TestIntegration_FullAllowedFlow(t *testing.T) {
	// Set up mock tool executor
	mockExecServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Tool string                 `json:"tool"`
			Args map[string]interface{} `json:"args"`
		}
		json.NewDecoder(r.Body).Decode(&req)

		resp := map[string]interface{}{
			"ok": true,
			"result": map[string]interface{}{
				"status":       "green",
				"failed_tests": 0,
				"project":      req.Args["project"],
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer mockExecServer.Close()

	// Create Agent Aegis handler
	pol := &policy.Policy{
		Tools: map[string]policy.ToolPolicy{
			"get_protected_status": {
				RequiredScope: "tools:status:read",
			},
		},
		Defaults: policy.DefaultPolicy{
			DenyUnknownTools: true,
		},
	}

	validator := validation.NewValidator()
	validator.RegisterSchema("get_protected_status", &validation.Schema{
		Type:     "object",
		Required: []string{"project"},
		Properties: map[string]*validation.Schema{
			"project": {Type: "string"},
		},
	})

	auditLogger := audit.NewBufferedLogger()

	h := handler.NewHandler(handler.Config{
		Verifier:    auth.NewDevVerifier(testSecret),
		Policy:      pol,
		Validator:   validator,
		Executor:    executor.NewHTTPExecutor(mockExecServer.URL, 5*time.Second),
		AuditLogger: auditLogger,
	})

	// Create test server for Agent Aegis
	aegisServer := httptest.NewServer(h.Router())
	defer aegisServer.Close()

	// Generate valid token
	token, err := auth.GenerateDevToken(testSecret, "test-agent@example.com",
		[]string{"tools:status:read"}, time.Hour)
	require.NoError(t, err)

	// Make request
	reqBody := `{"tool": "get_protected_status", "args": {"project": "demo"}}`
	req, _ := http.NewRequest("POST", aegisServer.URL+"/execute", bytes.NewBufferString(reqBody))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Verify response
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var result handler.ExecuteResponse
	json.NewDecoder(resp.Body).Decode(&result)
	assert.True(t, result.OK)
	assert.NotEmpty(t, result.RequestID)
	assert.Equal(t, "green", result.Result["status"])

	// Verify audit logs
	events := auditLogger.Events()
	assert.GreaterOrEqual(t, len(events), 3) // request, authorize, execute

	// Find authorization event
	var authEvent *audit.Event
	for _, e := range events {
		if e.EventType == audit.EventTypeAuthorize {
			authEvent = e
			break
		}
	}
	require.NotNil(t, authEvent)
	assert.Equal(t, audit.DecisionAllow, authEvent.Decision)
}

// TestIntegration_DeniedMissingScope tests that requests without proper scope are denied.
func TestIntegration_DeniedMissingScope(t *testing.T) {
	pol := &policy.Policy{
		Tools: map[string]policy.ToolPolicy{
			"admin_action": {
				RequiredScope: "tools:admin:write",
			},
		},
		Defaults: policy.DefaultPolicy{
			DenyUnknownTools: true,
		},
	}

	auditLogger := audit.NewBufferedLogger()

	h := handler.NewHandler(handler.Config{
		Verifier:    auth.NewDevVerifier(testSecret),
		Policy:      pol,
		Executor:    executor.NewNoopExecutor(),
		AuditLogger: auditLogger,
	})

	server := httptest.NewServer(h.Router())
	defer server.Close()

	// Generate token with wrong scope
	token, _ := auth.GenerateDevToken(testSecret, "user@example.com",
		[]string{"tools:read:only"}, time.Hour)

	reqBody := `{"tool": "admin_action", "args": {}}`
	req, _ := http.NewRequest("POST", server.URL+"/execute", bytes.NewBufferString(reqBody))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Verify denied
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)

	var result handler.ExecuteResponse
	json.NewDecoder(resp.Body).Decode(&result)
	assert.False(t, result.OK)
	assert.Contains(t, result.Error, "missing scope")

	// Verify audit logs show denial
	events := auditLogger.Events()
	var authEvent *audit.Event
	for _, e := range events {
		if e.EventType == audit.EventTypeAuthorize {
			authEvent = e
			break
		}
	}
	require.NotNil(t, authEvent)
	assert.Equal(t, audit.DecisionDeny, authEvent.Decision)
}

// TestIntegration_DeniedUnknownTool tests that unknown tools are denied.
func TestIntegration_DeniedUnknownTool(t *testing.T) {
	pol := &policy.Policy{
		Tools: map[string]policy.ToolPolicy{
			"allowed_tool": {RequiredScope: "tools:read"},
		},
		Defaults: policy.DefaultPolicy{
			DenyUnknownTools: true,
		},
	}

	h := handler.NewHandler(handler.Config{
		Verifier: auth.NewDevVerifier(testSecret),
		Policy:   pol,
		Executor: executor.NewNoopExecutor(),
	})

	server := httptest.NewServer(h.Router())
	defer server.Close()

	token, _ := auth.GenerateDevToken(testSecret, "user@example.com",
		[]string{"tools:read", "tools:admin"}, time.Hour)

	reqBody := `{"tool": "unknown_dangerous_tool", "args": {}}`
	req, _ := http.NewRequest("POST", server.URL+"/execute", bytes.NewBufferString(reqBody))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusForbidden, resp.StatusCode)

	var result handler.ExecuteResponse
	json.NewDecoder(resp.Body).Decode(&result)
	assert.False(t, result.OK)
	assert.Contains(t, result.Error, "unknown tool")
}

// TestIntegration_InvalidToken tests authentication failure.
func TestIntegration_InvalidToken(t *testing.T) {
	pol := &policy.Policy{
		Tools: map[string]policy.ToolPolicy{
			"any_tool": {RequiredScope: "tools:read"},
		},
	}

	h := handler.NewHandler(handler.Config{
		Verifier: auth.NewDevVerifier(testSecret),
		Policy:   pol,
		Executor: executor.NewNoopExecutor(),
	})

	server := httptest.NewServer(h.Router())
	defer server.Close()

	reqBody := `{"tool": "any_tool", "args": {}}`
	req, _ := http.NewRequest("POST", server.URL+"/execute", bytes.NewBufferString(reqBody))
	req.Header.Set("Authorization", "Bearer invalid-token-here")
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// TestIntegration_ExpiredToken tests that expired tokens are rejected.
func TestIntegration_ExpiredToken(t *testing.T) {
	pol := &policy.Policy{
		Tools: map[string]policy.ToolPolicy{
			"any_tool": {RequiredScope: "tools:read"},
		},
	}

	h := handler.NewHandler(handler.Config{
		Verifier: auth.NewDevVerifier(testSecret),
		Policy:   pol,
		Executor: executor.NewNoopExecutor(),
	})

	server := httptest.NewServer(h.Router())
	defer server.Close()

	// Generate expired token
	token, _ := auth.GenerateDevToken(testSecret, "user@example.com",
		[]string{"tools:read"}, -time.Hour)

	reqBody := `{"tool": "any_tool", "args": {}}`
	req, _ := http.NewRequest("POST", server.URL+"/execute", bytes.NewBufferString(reqBody))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	var result handler.ExecuteResponse
	json.NewDecoder(resp.Body).Decode(&result)
	assert.Contains(t, result.Error, "expired")
}

// TestIntegration_SchemaValidation tests argument validation.
func TestIntegration_SchemaValidation(t *testing.T) {
	pol := &policy.Policy{
		Tools: map[string]policy.ToolPolicy{
			"create_item": {RequiredScope: "tools:write"},
		},
	}

	validator := validation.NewValidator()
	min := 1
	validator.RegisterSchema("create_item", &validation.Schema{
		Type:     "object",
		Required: []string{"name", "count"},
		Properties: map[string]*validation.Schema{
			"name":  {Type: "string", MinLength: &min},
			"count": {Type: "integer", Minimum: func() *float64 { f := 1.0; return &f }()},
		},
	})

	h := handler.NewHandler(handler.Config{
		Verifier:  auth.NewDevVerifier(testSecret),
		Policy:    pol,
		Validator: validator,
		Executor:  executor.NewNoopExecutor(),
	})

	server := httptest.NewServer(h.Router())
	defer server.Close()

	token, _ := auth.GenerateDevToken(testSecret, "user@example.com",
		[]string{"tools:write"}, time.Hour)

	tests := []struct {
		name     string
		args     string
		wantCode int
	}{
		{
			name:     "valid args",
			args:     `{"name": "test", "count": 5}`,
			wantCode: http.StatusOK,
		},
		{
			name:     "missing required field",
			args:     `{"name": "test"}`,
			wantCode: http.StatusBadRequest,
		},
		{
			name:     "wrong type",
			args:     `{"name": "test", "count": "five"}`,
			wantCode: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reqBody := `{"tool": "create_item", "args": ` + tt.args + `}`
			req, _ := http.NewRequest("POST", server.URL+"/execute", bytes.NewBufferString(reqBody))
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("Content-Type", "application/json")

			resp, err := http.DefaultClient.Do(req)
			require.NoError(t, err)
			resp.Body.Close()

			assert.Equal(t, tt.wantCode, resp.StatusCode)
		})
	}
}
