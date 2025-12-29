package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rr3khan/agent-aegis/internal/audit"
	"github.com/rr3khan/agent-aegis/internal/auth"
	"github.com/rr3khan/agent-aegis/internal/executor"
	"github.com/rr3khan/agent-aegis/internal/policy"
	"github.com/rr3khan/agent-aegis/internal/validation"
)

const testSecret = "test-secret"

func setupTestHandler() (*Handler, *executor.MockExecutor, *audit.BufferedLogger) {
	mockExec := executor.NewMockExecutor()
	auditLogger := audit.NewBufferedLogger()

	pol := &policy.Policy{
		Tools: map[string]policy.ToolPolicy{
			"get_status":  {RequiredScope: "tools:status:read"},
			"create_item": {RequiredScope: "tools:items:write"},
		},
		Defaults: policy.DefaultPolicy{
			DenyUnknownTools: true,
		},
	}

	validator := validation.NewValidator()
	validator.RegisterSchema("get_status", &validation.Schema{
		Type:     "object",
		Required: []string{"project"},
		Properties: map[string]*validation.Schema{
			"project": {Type: "string"},
		},
	})

	h := NewHandler(Config{
		Verifier:    auth.NewDevVerifier(testSecret),
		Policy:      pol,
		Validator:   validator,
		Executor:    mockExec,
		AuditLogger: auditLogger,
	})

	return h, mockExec, auditLogger
}

func generateToken(subject string, scopes []string) string {
	token, _ := auth.GenerateDevToken(testSecret, subject, scopes, time.Hour)
	return token
}

func TestHandler_Health(t *testing.T) {
	h, _, _ := setupTestHandler()

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()

	h.Router().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp HealthResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	assert.Equal(t, "ok", resp.Status)
	assert.NotEmpty(t, resp.Time)
}

func TestHandler_Execute_Success(t *testing.T) {
	h, mockExec, auditLogger := setupTestHandler()

	mockExec.SetResponse("get_status", &executor.Response{
		OK: true,
		Result: map[string]interface{}{
			"status": "green",
		},
	})

	body := `{"tool": "get_status", "args": {"project": "demo"}}`
	req := httptest.NewRequest("POST", "/execute", bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer "+generateToken("user@example.com", []string{"tools:status:read"}))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.Router().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp ExecuteResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	assert.True(t, resp.OK)
	assert.NotEmpty(t, resp.RequestID)
	assert.Equal(t, "green", resp.Result["status"])

	// Check audit logs
	events := auditLogger.Events()
	assert.GreaterOrEqual(t, len(events), 2) // At least request + authorization
}

func TestHandler_Execute_MissingToken(t *testing.T) {
	h, _, _ := setupTestHandler()

	body := `{"tool": "get_status", "args": {"project": "demo"}}`
	req := httptest.NewRequest("POST", "/execute", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.Router().ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)

	var resp ExecuteResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	assert.False(t, resp.OK)
	assert.Contains(t, resp.Error, "missing")
}

func TestHandler_Execute_InvalidToken(t *testing.T) {
	h, _, _ := setupTestHandler()

	body := `{"tool": "get_status", "args": {"project": "demo"}}`
	req := httptest.NewRequest("POST", "/execute", bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer invalid-token")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.Router().ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestHandler_Execute_MissingScope(t *testing.T) {
	h, _, _ := setupTestHandler()

	body := `{"tool": "get_status", "args": {"project": "demo"}}`
	req := httptest.NewRequest("POST", "/execute", bytes.NewBufferString(body))
	// Token has wrong scope
	req.Header.Set("Authorization", "Bearer "+generateToken("user@example.com", []string{"tools:other:read"}))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.Router().ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)

	var resp ExecuteResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	assert.False(t, resp.OK)
	assert.Contains(t, resp.Error, "missing scope")
}

func TestHandler_Execute_UnknownTool(t *testing.T) {
	h, _, _ := setupTestHandler()

	body := `{"tool": "unknown_tool", "args": {}}`
	req := httptest.NewRequest("POST", "/execute", bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer "+generateToken("user@example.com", []string{"tools:status:read"}))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.Router().ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)

	var resp ExecuteResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	assert.Contains(t, resp.Error, "unknown tool")
}

func TestHandler_Execute_InvalidArgs(t *testing.T) {
	h, _, _ := setupTestHandler()

	// Missing required "project" field
	body := `{"tool": "get_status", "args": {}}`
	req := httptest.NewRequest("POST", "/execute", bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer "+generateToken("user@example.com", []string{"tools:status:read"}))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.Router().ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp ExecuteResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	assert.Contains(t, resp.Error, "invalid arguments")
}

func TestHandler_Execute_InvalidBody(t *testing.T) {
	h, _, _ := setupTestHandler()

	body := `not valid json`
	req := httptest.NewRequest("POST", "/execute", bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer "+generateToken("user@example.com", []string{"tools:status:read"}))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.Router().ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandler_Execute_MissingToolName(t *testing.T) {
	h, _, _ := setupTestHandler()

	body := `{"args": {"project": "demo"}}`
	req := httptest.NewRequest("POST", "/execute", bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer "+generateToken("user@example.com", []string{"tools:status:read"}))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.Router().ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp ExecuteResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	assert.Contains(t, resp.Error, "missing tool")
}

func TestHandler_ListTools(t *testing.T) {
	h, _, _ := setupTestHandler()

	req := httptest.NewRequest("GET", "/policy/tools", nil)
	w := httptest.NewRecorder()

	h.Router().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	tools := resp["tools"].([]interface{})
	assert.Len(t, tools, 2)
}

func TestHandler_Execute_ExecutorError(t *testing.T) {
	h, mockExec, _ := setupTestHandler()

	mockExec.SetError("get_status", assert.AnError)

	body := `{"tool": "get_status", "args": {"project": "demo"}}`
	req := httptest.NewRequest("POST", "/execute", bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer "+generateToken("user@example.com", []string{"tools:status:read"}))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.Router().ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadGateway, w.Code)
}

func TestHandler_Execute_AuditLogging(t *testing.T) {
	h, mockExec, auditLogger := setupTestHandler()

	mockExec.SetResponse("get_status", &executor.Response{OK: true})

	body := `{"tool": "get_status", "args": {"project": "demo"}}`
	req := httptest.NewRequest("POST", "/execute", bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer "+generateToken("user@example.com", []string{"tools:status:read"}))
	w := httptest.NewRecorder()

	h.Router().ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	// Check audit log contains expected events
	events := auditLogger.Events()

	eventTypes := make(map[audit.EventType]bool)
	for _, e := range events {
		eventTypes[e.EventType] = true
	}

	assert.True(t, eventTypes[audit.EventTypeRequest], "should log request")
	assert.True(t, eventTypes[audit.EventTypeAuthorize], "should log authorization")
	assert.True(t, eventTypes[audit.EventTypeExecute], "should log execution")
}
