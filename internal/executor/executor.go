// Package executor handles forwarding tool requests to downstream executors.
package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

var (
	ErrExecutorUnavailable = errors.New("executor unavailable")
	ErrExecutorTimeout     = errors.New("executor request timed out")
	ErrExecutorError       = errors.New("executor returned error")
)

// Request represents a tool execution request.
type Request struct {
	Tool string                 `json:"tool"`
	Args map[string]interface{} `json:"args"`
}

// Response represents a tool execution response.
type Response struct {
	OK     bool                   `json:"ok"`
	Result map[string]interface{} `json:"result,omitempty"`
	Error  string                 `json:"error,omitempty"`
}

// Executor is the interface for tool execution backends.
type Executor interface {
	Execute(ctx context.Context, tool string, args map[string]interface{}) (*Response, error)
}

// HTTPExecutor forwards tool requests to an HTTP endpoint.
type HTTPExecutor struct {
	BaseURL    string
	HTTPClient *http.Client
	Timeout    time.Duration
	Headers    map[string]string
}

// NewHTTPExecutor creates a new HTTP-based executor.
func NewHTTPExecutor(baseURL string, timeout time.Duration) *HTTPExecutor {
	return &HTTPExecutor{
		BaseURL: baseURL,
		HTTPClient: &http.Client{
			Timeout: timeout,
		},
		Timeout: timeout,
		Headers: make(map[string]string),
	}
}

// Execute forwards a tool request to the downstream executor.
func (e *HTTPExecutor) Execute(ctx context.Context, tool string, args map[string]interface{}) (*Response, error) {
	// Create request body
	reqBody := Request{
		Tool: tool,
		Args: args,
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Create HTTP request
	url := e.BaseURL + "/execute"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	// Add custom headers
	for k, v := range e.Headers {
		req.Header.Set(k, v)
	}

	// Execute request
	resp, err := e.HTTPClient.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ErrExecutorTimeout
		}
		return nil, fmt.Errorf("%w: %v", ErrExecutorUnavailable, err)
	}
	defer resp.Body.Close()

	// Read response body
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Handle non-2xx status codes
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("%w: status %d - %s", ErrExecutorError, resp.StatusCode, string(respBody))
	}

	// Parse response
	var response Response
	if err := json.Unmarshal(respBody, &response); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &response, nil
}

// SetHeader sets a custom header for executor requests.
func (e *HTTPExecutor) SetHeader(key, value string) {
	e.Headers[key] = value
}

// MockExecutor is a test executor that returns predefined responses.
type MockExecutor struct {
	Responses map[string]*Response
	Errors    map[string]error
	Calls     []MockCall
}

// MockCall records a call to the mock executor.
type MockCall struct {
	Tool string
	Args map[string]interface{}
	Time time.Time
}

// NewMockExecutor creates a new mock executor for testing.
func NewMockExecutor() *MockExecutor {
	return &MockExecutor{
		Responses: make(map[string]*Response),
		Errors:    make(map[string]error),
		Calls:     make([]MockCall, 0),
	}
}

// SetResponse sets the response for a tool.
func (m *MockExecutor) SetResponse(tool string, response *Response) {
	m.Responses[tool] = response
}

// SetError sets an error for a tool.
func (m *MockExecutor) SetError(tool string, err error) {
	m.Errors[tool] = err
}

// Execute returns the predefined response for a tool.
func (m *MockExecutor) Execute(ctx context.Context, tool string, args map[string]interface{}) (*Response, error) {
	m.Calls = append(m.Calls, MockCall{
		Tool: tool,
		Args: args,
		Time: time.Now(),
	})

	if err, exists := m.Errors[tool]; exists {
		return nil, err
	}

	if resp, exists := m.Responses[tool]; exists {
		return resp, nil
	}

	// Default response
	return &Response{
		OK: true,
		Result: map[string]interface{}{
			"message": fmt.Sprintf("executed %s", tool),
		},
	}, nil
}

// GetCalls returns all recorded calls.
func (m *MockExecutor) GetCalls() []MockCall {
	return m.Calls
}

// Reset clears all recorded calls.
func (m *MockExecutor) Reset() {
	m.Calls = m.Calls[:0]
}

// NoopExecutor is an executor that does nothing (for testing denied paths).
type NoopExecutor struct{}

// NewNoopExecutor creates a no-op executor.
func NewNoopExecutor() *NoopExecutor {
	return &NoopExecutor{}
}

// Execute returns a success response without doing anything.
func (n *NoopExecutor) Execute(ctx context.Context, tool string, args map[string]interface{}) (*Response, error) {
	return &Response{
		OK: true,
		Result: map[string]interface{}{
			"noop": true,
		},
	}, nil
}

