// Package handler provides HTTP handlers for Agent Aegis.
package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/riyadkhan/agent-aegis/internal/audit"
	"github.com/riyadkhan/agent-aegis/internal/auth"
	"github.com/riyadkhan/agent-aegis/internal/executor"
	"github.com/riyadkhan/agent-aegis/internal/policy"
	"github.com/riyadkhan/agent-aegis/internal/validation"
)

// ExecuteRequest is the incoming request format.
type ExecuteRequest struct {
	Tool string                 `json:"tool"`
	Args map[string]interface{} `json:"args"`
}

// ExecuteResponse is the outgoing response format.
type ExecuteResponse struct {
	RequestID string                 `json:"request_id"`
	OK        bool                   `json:"ok"`
	Result    map[string]interface{} `json:"result,omitempty"`
	Error     string                 `json:"error,omitempty"`
}

// HealthResponse is the health check response format.
type HealthResponse struct {
	Status string `json:"status"`
	Time   string `json:"time"`
}

// AuditLogger interface for logging audit events.
type AuditLogger interface {
	LogRequest(requestID, tool string, identity *audit.IdentityInfo)
	LogAuthorization(requestID, tool string, decision audit.Decision, reason string, identity *audit.IdentityInfo)
	LogExecution(requestID, tool string, duration time.Duration, err error)
	LogResponse(requestID string, statusCode int, duration time.Duration)
	LogError(requestID, tool string, err error, identity *audit.IdentityInfo)
}

// Handler is the main HTTP handler for Agent Aegis.
type Handler struct {
	verifier    *auth.JWTVerifier
	policy      *policy.Policy
	validator   *validation.Validator
	executor    executor.Executor
	auditLogger AuditLogger
}

// Config contains configuration for the handler.
type Config struct {
	Verifier    *auth.JWTVerifier
	Policy      *policy.Policy
	Validator   *validation.Validator
	Executor    executor.Executor
	AuditLogger AuditLogger
}

// NewHandler creates a new HTTP handler.
func NewHandler(cfg Config) *Handler {
	h := &Handler{
		verifier:    cfg.Verifier,
		policy:      cfg.Policy,
		validator:   cfg.Validator,
		executor:    cfg.Executor,
		auditLogger: cfg.AuditLogger,
	}

	// Use defaults if not provided
	if h.validator == nil {
		h.validator = validation.NewValidator()
	}

	return h
}

// Router returns an http.Handler with all routes configured.
func (h *Handler) Router() http.Handler {
	mux := http.NewServeMux()

	// Health check endpoint
	mux.HandleFunc("GET /health", h.handleHealth)
	mux.HandleFunc("GET /healthz", h.handleHealth)

	// Main execute endpoint
	mux.HandleFunc("POST /execute", h.handleExecute)

	// Policy info endpoint (for debugging)
	mux.HandleFunc("GET /policy/tools", h.handleListTools)

	return mux
}

// handleHealth returns a health check response.
func (h *Handler) handleHealth(w http.ResponseWriter, r *http.Request) {
	resp := HealthResponse{
		Status: "ok",
		Time:   time.Now().UTC().Format(time.RFC3339),
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleExecute is the main tool execution handler.
func (h *Handler) handleExecute(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	requestID := audit.GenerateRequestID()

	// Parse request body
	var req ExecuteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, requestID, http.StatusBadRequest, "invalid request body")
		return
	}

	// Validate tool name is present
	if req.Tool == "" {
		h.writeError(w, requestID, http.StatusBadRequest, "missing tool name")
		return
	}

	// Extract and verify JWT
	tokenString := r.Header.Get("Authorization")
	claims, err := h.verifier.VerifyToken(tokenString)
	if err != nil {
		h.handleAuthError(w, requestID, req.Tool, err)
		return
	}

	// Create identity info for audit logging
	identity := &audit.IdentityInfo{
		Subject: claims.Subject,
		Issuer:  claims.Issuer,
		Scopes:  claims.Scopes,
		JTI:     claims.JTI,
	}

	// Log incoming request
	if h.auditLogger != nil {
		h.auditLogger.LogRequest(requestID, req.Tool, identity)
	}

	// Check authorization
	authReq := policy.AuthorizationRequest{
		Tool:     req.Tool,
		Scopes:   claims.Scopes,
		Subject:  claims.Subject,
		Issuer:   claims.Issuer,
		Audience: claims.Audience,
	}

	decision := h.policy.Authorize(authReq)

	// Log authorization decision
	if h.auditLogger != nil {
		auditDecision := audit.DecisionAllow
		if !decision.Allowed {
			auditDecision = audit.DecisionDeny
		}
		h.auditLogger.LogAuthorization(requestID, req.Tool, auditDecision, decision.Reason, identity)
	}

	if !decision.Allowed {
		h.writeError(w, requestID, http.StatusForbidden, "forbidden: "+decision.Reason)
		return
	}

	// Validate tool arguments
	validationResult := h.validator.Validate(req.Tool, req.Args)
	if !validationResult.Valid {
		h.writeError(w, requestID, http.StatusBadRequest, "invalid arguments: "+validationResult.Error())
		return
	}

	// Execute the tool
	ctx := context.Background()
	execStart := time.Now()
	execResp, err := h.executor.Execute(ctx, req.Tool, req.Args)
	execDuration := time.Since(execStart)

	// Log execution
	if h.auditLogger != nil {
		h.auditLogger.LogExecution(requestID, req.Tool, execDuration, err)
	}

	if err != nil {
		if h.auditLogger != nil {
			h.auditLogger.LogError(requestID, req.Tool, err, identity)
		}
		h.writeError(w, requestID, http.StatusBadGateway, "execution failed: "+err.Error())
		return
	}

	// Build success response
	resp := ExecuteResponse{
		RequestID: requestID,
		OK:        execResp.OK,
		Result:    execResp.Result,
	}

	if !execResp.OK {
		resp.Error = execResp.Error
	}

	// Log response
	if h.auditLogger != nil {
		h.auditLogger.LogResponse(requestID, http.StatusOK, time.Since(startTime))
	}

	writeJSON(w, http.StatusOK, resp)
}

// handleAuthError maps auth errors to appropriate HTTP responses.
func (h *Handler) handleAuthError(w http.ResponseWriter, requestID, tool string, err error) {
	var statusCode int
	var message string

	switch {
	case errors.Is(err, auth.ErrMissingToken):
		statusCode = http.StatusUnauthorized
		message = "missing authorization token"
	case errors.Is(err, auth.ErrInvalidToken):
		statusCode = http.StatusUnauthorized
		message = "invalid authorization token"
	case errors.Is(err, auth.ErrTokenExpired):
		statusCode = http.StatusUnauthorized
		message = "authorization token has expired"
	case errors.Is(err, auth.ErrInvalidSignature):
		statusCode = http.StatusUnauthorized
		message = "invalid token signature"
	case errors.Is(err, auth.ErrInvalidIssuer):
		statusCode = http.StatusForbidden
		message = "token issuer not allowed"
	case errors.Is(err, auth.ErrInvalidAudience):
		statusCode = http.StatusForbidden
		message = "token audience not allowed"
	default:
		statusCode = http.StatusUnauthorized
		message = "authentication failed"
	}

	// Log auth failures for security monitoring
	if h.auditLogger != nil {
		h.auditLogger.LogAuthorization(requestID, tool, audit.DecisionDeny, message, nil)
	}

	h.writeError(w, requestID, statusCode, message)
}

// handleListTools returns the list of configured tools.
func (h *Handler) handleListTools(w http.ResponseWriter, r *http.Request) {
	tools := h.policy.ListTools()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"tools": tools,
	})
}

// writeError writes an error response.
func (h *Handler) writeError(w http.ResponseWriter, requestID string, statusCode int, message string) {
	resp := ExecuteResponse{
		RequestID: requestID,
		OK:        false,
		Error:     message,
	}
	writeJSON(w, statusCode, resp)
}

// writeJSON writes a JSON response.
func writeJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(data)
}
