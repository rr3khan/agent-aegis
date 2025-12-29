package executor

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHTTPExecutor_Execute_Success(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/execute", r.URL.Path)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		var req Request
		json.NewDecoder(r.Body).Decode(&req)
		assert.Equal(t, "get_status", req.Tool)
		assert.Equal(t, "demo", req.Args["project"])

		resp := Response{
			OK: true,
			Result: map[string]interface{}{
				"status": "green",
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	exec := NewHTTPExecutor(server.URL, 5*time.Second)
	resp, err := exec.Execute(context.Background(), "get_status", map[string]interface{}{
		"project": "demo",
	})

	require.NoError(t, err)
	assert.True(t, resp.OK)
	assert.Equal(t, "green", resp.Result["status"])
}

func TestHTTPExecutor_Execute_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal server error"))
	}))
	defer server.Close()

	exec := NewHTTPExecutor(server.URL, 5*time.Second)
	_, err := exec.Execute(context.Background(), "get_status", nil)

	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrExecutorError)
}

func TestHTTPExecutor_Execute_Unavailable(t *testing.T) {
	exec := NewHTTPExecutor("http://localhost:99999", 1*time.Second)
	_, err := exec.Execute(context.Background(), "get_status", nil)

	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrExecutorUnavailable)
}

func TestHTTPExecutor_Execute_Timeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
	}))
	defer server.Close()

	exec := NewHTTPExecutor(server.URL, 100*time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err := exec.Execute(ctx, "get_status", nil)
	assert.Error(t, err)
}

func TestHTTPExecutor_CustomHeaders(t *testing.T) {
	var receivedHeaders http.Header

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header
		json.NewEncoder(w).Encode(Response{OK: true})
	}))
	defer server.Close()

	exec := NewHTTPExecutor(server.URL, 5*time.Second)
	exec.SetHeader("X-Custom-Header", "custom-value")
	exec.SetHeader("X-Request-ID", "req-123")

	_, err := exec.Execute(context.Background(), "test", nil)
	require.NoError(t, err)

	assert.Equal(t, "custom-value", receivedHeaders.Get("X-Custom-Header"))
	assert.Equal(t, "req-123", receivedHeaders.Get("X-Request-ID"))
}

func TestMockExecutor_Execute(t *testing.T) {
	mock := NewMockExecutor()
	mock.SetResponse("get_status", &Response{
		OK: true,
		Result: map[string]interface{}{
			"status": "healthy",
		},
	})

	resp, err := mock.Execute(context.Background(), "get_status", map[string]interface{}{
		"project": "demo",
	})

	require.NoError(t, err)
	assert.True(t, resp.OK)
	assert.Equal(t, "healthy", resp.Result["status"])

	// Check recorded calls
	calls := mock.GetCalls()
	assert.Len(t, calls, 1)
	assert.Equal(t, "get_status", calls[0].Tool)
	assert.Equal(t, "demo", calls[0].Args["project"])
}

func TestMockExecutor_Error(t *testing.T) {
	mock := NewMockExecutor()
	mock.SetError("failing_tool", assert.AnError)

	_, err := mock.Execute(context.Background(), "failing_tool", nil)
	assert.Error(t, err)
}

func TestMockExecutor_DefaultResponse(t *testing.T) {
	mock := NewMockExecutor()

	// Tool without explicit response
	resp, err := mock.Execute(context.Background(), "any_tool", nil)
	require.NoError(t, err)
	assert.True(t, resp.OK)
	assert.Contains(t, resp.Result["message"], "any_tool")
}

func TestMockExecutor_Reset(t *testing.T) {
	mock := NewMockExecutor()

	mock.Execute(context.Background(), "tool1", nil)
	mock.Execute(context.Background(), "tool2", nil)
	assert.Len(t, mock.GetCalls(), 2)

	mock.Reset()
	assert.Empty(t, mock.GetCalls())
}

func TestNoopExecutor(t *testing.T) {
	noop := NewNoopExecutor()

	resp, err := noop.Execute(context.Background(), "any_tool", map[string]interface{}{
		"any": "args",
	})

	require.NoError(t, err)
	assert.True(t, resp.OK)
	assert.True(t, resp.Result["noop"].(bool))
}
