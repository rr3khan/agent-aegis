package audit

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLogger_Log(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(&buf, false)

	event := &Event{
		RequestID: "test-123",
		EventType: EventTypeRequest,
		Tool:      "get_status",
		Identity: &IdentityInfo{
			Subject: "user@example.com",
			Issuer:  "test-issuer",
		},
	}

	err := logger.Log(event)
	require.NoError(t, err)

	// Parse the logged JSON
	var logged Event
	err = json.Unmarshal(buf.Bytes(), &logged)
	require.NoError(t, err)

	assert.Equal(t, "test-123", logged.RequestID)
	assert.Equal(t, EventTypeRequest, logged.EventType)
	assert.Equal(t, "get_status", logged.Tool)
	assert.Equal(t, "user@example.com", logged.Identity.Subject)
	assert.NotZero(t, logged.Timestamp)
}

func TestLogger_LogPretty(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(&buf, true)

	event := &Event{
		RequestID: "test-123",
		EventType: EventTypeRequest,
		Tool:      "get_status",
	}

	err := logger.Log(event)
	require.NoError(t, err)

	// Pretty printed JSON should contain indentation
	assert.Contains(t, buf.String(), "  ")
	assert.Contains(t, buf.String(), "request_id")
}

func TestLogger_LogRequest(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(&buf, false)

	identity := &IdentityInfo{
		Subject: "user@example.com",
		Scopes:  []string{"tools:read"},
	}

	logger.LogRequest("req-123", "get_status", identity)

	var event Event
	err := json.Unmarshal(buf.Bytes(), &event)
	require.NoError(t, err)

	assert.Equal(t, "req-123", event.RequestID)
	assert.Equal(t, EventTypeRequest, event.EventType)
	assert.Equal(t, "get_status", event.Tool)
}

func TestLogger_LogAuthorization(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(&buf, false)

	logger.LogAuthorization("req-123", "get_status", DecisionAllow, "authorized", nil)

	var event Event
	err := json.Unmarshal(buf.Bytes(), &event)
	require.NoError(t, err)

	assert.Equal(t, EventTypeAuthorize, event.EventType)
	assert.Equal(t, DecisionAllow, event.Decision)
	assert.Equal(t, "authorized", event.Reason)
}

func TestLogger_LogExecution(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(&buf, false)

	logger.LogExecution("req-123", "get_status", 100*time.Millisecond, nil)

	var event Event
	err := json.Unmarshal(buf.Bytes(), &event)
	require.NoError(t, err)

	assert.Equal(t, EventTypeExecute, event.EventType)
	assert.Equal(t, "get_status", event.Tool)
	assert.NotZero(t, event.Duration)
}

func TestLogger_LogExecutionWithError(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(&buf, false)

	logger.LogExecution("req-123", "get_status", 100*time.Millisecond,
		assert.AnError)

	var event Event
	err := json.Unmarshal(buf.Bytes(), &event)
	require.NoError(t, err)

	assert.NotEmpty(t, event.Error)
}

func TestLogger_LogResponse(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(&buf, false)

	logger.LogResponse("req-123", 200, 50*time.Millisecond)

	var event Event
	err := json.Unmarshal(buf.Bytes(), &event)
	require.NoError(t, err)

	assert.Equal(t, EventTypeResponse, event.EventType)
	assert.Equal(t, 200, event.StatusCode)
}

func TestBufferedLogger(t *testing.T) {
	logger := NewBufferedLogger()

	// Log some events
	logger.Log(&Event{RequestID: "req-1", EventType: EventTypeRequest})
	logger.Log(&Event{RequestID: "req-1", EventType: EventTypeAuthorize})
	logger.Log(&Event{RequestID: "req-2", EventType: EventTypeRequest})

	// Check all events
	events := logger.Events()
	assert.Len(t, events, 3)

	// Find by request ID
	req1Events := logger.FindByRequestID("req-1")
	assert.Len(t, req1Events, 2)

	// Clear
	logger.Clear()
	assert.Empty(t, logger.Events())
}

func TestGenerateRequestID(t *testing.T) {
	id1 := GenerateRequestID()
	id2 := GenerateRequestID()

	assert.NotEmpty(t, id1)
	assert.NotEmpty(t, id2)
	assert.NotEqual(t, id1, id2)

	// Should be a valid UUID format
	assert.Len(t, id1, 36) // UUID format: 8-4-4-4-12
}

func TestMultiLogger(t *testing.T) {
	var buf1, buf2 bytes.Buffer
	logger1 := NewLogger(&buf1, false)
	logger2 := NewLogger(&buf2, false)

	multi := NewMultiLogger(logger1, logger2)

	multi.LogRequest("req-123", "get_status", nil)

	// Both buffers should have the event
	assert.NotEmpty(t, buf1.String())
	assert.NotEmpty(t, buf2.String())

	// Both should contain the same request ID (don't compare timestamps)
	assert.Contains(t, buf1.String(), "req-123")
	assert.Contains(t, buf2.String(), "req-123")
	assert.Contains(t, buf1.String(), "get_status")
	assert.Contains(t, buf2.String(), "get_status")
}

func TestEvent_Timestamp(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(&buf, false)

	// Log without timestamp
	logger.Log(&Event{RequestID: "test"})

	var event Event
	json.Unmarshal(buf.Bytes(), &event)

	// Timestamp should be set automatically
	assert.False(t, event.Timestamp.IsZero())
	assert.True(t, event.Timestamp.Before(time.Now().Add(time.Second)))
}

func TestEvent_WithMetadata(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(&buf, false)

	logger.Log(&Event{
		RequestID: "test",
		EventType: EventTypeRequest,
		Metadata: map[string]interface{}{
			"custom_field": "custom_value",
			"count":        42,
		},
	})

	var event Event
	json.Unmarshal(buf.Bytes(), &event)

	assert.Equal(t, "custom_value", event.Metadata["custom_field"])
	assert.Equal(t, float64(42), event.Metadata["count"])
}
