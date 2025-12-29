// Package audit provides structured audit logging for Agent Aegis.
package audit

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/google/uuid"
)

// EventType represents the type of audit event.
type EventType string

const (
	EventTypeRequest   EventType = "request"
	EventTypeAuthorize EventType = "authorize"
	EventTypeExecute   EventType = "execute"
	EventTypeResponse  EventType = "response"
	EventTypeError     EventType = "error"
)

// Decision represents an authorization decision.
type Decision string

const (
	DecisionAllow Decision = "allow"
	DecisionDeny  Decision = "deny"
)

// Event represents a structured audit log event.
type Event struct {
	Timestamp  time.Time              `json:"timestamp"`
	RequestID  string                 `json:"request_id"`
	EventType  EventType              `json:"event_type"`
	Tool       string                 `json:"tool,omitempty"`
	Decision   Decision               `json:"decision,omitempty"`
	Reason     string                 `json:"reason,omitempty"`
	Identity   *IdentityInfo          `json:"identity,omitempty"`
	StatusCode int                    `json:"status_code,omitempty"`
	Duration   time.Duration          `json:"duration_ms,omitempty"`
	Error      string                 `json:"error,omitempty"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

// IdentityInfo contains non-sensitive identity information for audit logs.
type IdentityInfo struct {
	Subject string   `json:"subject,omitempty"`
	Issuer  string   `json:"issuer,omitempty"`
	Scopes  []string `json:"scopes,omitempty"`
	JTI     string   `json:"jti,omitempty"`
}

// Logger handles audit event logging.
type Logger struct {
	mu     sync.Mutex
	output io.Writer
	pretty bool
}

// NewLogger creates a new audit logger.
func NewLogger(output io.Writer, pretty bool) *Logger {
	if output == nil {
		output = os.Stdout
	}
	return &Logger{
		output: output,
		pretty: pretty,
	}
}

// NewStdoutLogger creates a logger that writes JSON to stdout.
func NewStdoutLogger() *Logger {
	return NewLogger(os.Stdout, false)
}

// NewFileLogger creates a logger that writes to a file.
func NewFileLogger(path string, pretty bool) (*Logger, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open audit log file: %w", err)
	}
	return NewLogger(f, pretty), nil
}

// Log writes an audit event to the output.
func (l *Logger) Log(event *Event) error {
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	var data []byte
	var err error

	if l.pretty {
		data, err = json.MarshalIndent(event, "", "  ")
	} else {
		data, err = json.Marshal(event)
	}

	if err != nil {
		return fmt.Errorf("failed to marshal audit event: %w", err)
	}

	data = append(data, '\n')
	_, err = l.output.Write(data)
	return err
}

// LogRequest logs an incoming request.
func (l *Logger) LogRequest(requestID, tool string, identity *IdentityInfo) {
	l.Log(&Event{
		RequestID: requestID,
		EventType: EventTypeRequest,
		Tool:      tool,
		Identity:  identity,
	})
}

// LogAuthorization logs an authorization decision.
func (l *Logger) LogAuthorization(requestID, tool string, decision Decision, reason string, identity *IdentityInfo) {
	l.Log(&Event{
		RequestID: requestID,
		EventType: EventTypeAuthorize,
		Tool:      tool,
		Decision:  decision,
		Reason:    reason,
		Identity:  identity,
	})
}

// LogExecution logs a tool execution.
func (l *Logger) LogExecution(requestID, tool string, duration time.Duration, err error) {
	event := &Event{
		RequestID: requestID,
		EventType: EventTypeExecute,
		Tool:      tool,
		Duration:  duration,
	}
	if err != nil {
		event.Error = err.Error()
	}
	l.Log(event)
}

// LogResponse logs the final response.
func (l *Logger) LogResponse(requestID string, statusCode int, duration time.Duration) {
	l.Log(&Event{
		RequestID:  requestID,
		EventType:  EventTypeResponse,
		StatusCode: statusCode,
		Duration:   duration,
	})
}

// LogError logs an error event.
func (l *Logger) LogError(requestID, tool string, err error, identity *IdentityInfo) {
	l.Log(&Event{
		RequestID: requestID,
		EventType: EventTypeError,
		Tool:      tool,
		Error:     err.Error(),
		Identity:  identity,
	})
}

// GenerateRequestID creates a new unique request ID.
func GenerateRequestID() string {
	return uuid.New().String()
}

// MultiLogger writes audit events to multiple loggers.
type MultiLogger struct {
	loggers []*Logger
}

// NewMultiLogger creates a logger that writes to multiple outputs.
func NewMultiLogger(loggers ...*Logger) *MultiLogger {
	return &MultiLogger{loggers: loggers}
}

// Log writes an event to all loggers.
func (m *MultiLogger) Log(event *Event) error {
	var lastErr error
	for _, l := range m.loggers {
		if err := l.Log(event); err != nil {
			lastErr = err
		}
	}
	return lastErr
}

// LogRequest logs a request to all loggers.
func (m *MultiLogger) LogRequest(requestID, tool string, identity *IdentityInfo) {
	for _, l := range m.loggers {
		l.LogRequest(requestID, tool, identity)
	}
}

// LogAuthorization logs an authorization decision to all loggers.
func (m *MultiLogger) LogAuthorization(requestID, tool string, decision Decision, reason string, identity *IdentityInfo) {
	for _, l := range m.loggers {
		l.LogAuthorization(requestID, tool, decision, reason, identity)
	}
}

// BufferedLogger collects events in memory for testing/inspection.
type BufferedLogger struct {
	mu     sync.Mutex
	events []*Event
}

// NewBufferedLogger creates an in-memory logger for testing.
func NewBufferedLogger() *BufferedLogger {
	return &BufferedLogger{
		events: make([]*Event, 0),
	}
}

// Log stores an event in memory.
func (b *BufferedLogger) Log(event *Event) error {
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.events = append(b.events, event)
	return nil
}

// LogRequest logs an incoming request.
func (b *BufferedLogger) LogRequest(requestID, tool string, identity *IdentityInfo) {
	b.Log(&Event{
		RequestID: requestID,
		EventType: EventTypeRequest,
		Tool:      tool,
		Identity:  identity,
	})
}

// LogAuthorization logs an authorization decision.
func (b *BufferedLogger) LogAuthorization(requestID, tool string, decision Decision, reason string, identity *IdentityInfo) {
	b.Log(&Event{
		RequestID: requestID,
		EventType: EventTypeAuthorize,
		Tool:      tool,
		Decision:  decision,
		Reason:    reason,
		Identity:  identity,
	})
}

// LogExecution logs a tool execution.
func (b *BufferedLogger) LogExecution(requestID, tool string, duration time.Duration, err error) {
	event := &Event{
		RequestID: requestID,
		EventType: EventTypeExecute,
		Tool:      tool,
		Duration:  duration,
	}
	if err != nil {
		event.Error = err.Error()
	}
	b.Log(event)
}

// LogResponse logs the final response.
func (b *BufferedLogger) LogResponse(requestID string, statusCode int, duration time.Duration) {
	b.Log(&Event{
		RequestID:  requestID,
		EventType:  EventTypeResponse,
		StatusCode: statusCode,
		Duration:   duration,
	})
}

// LogError logs an error event.
func (b *BufferedLogger) LogError(requestID, tool string, err error, identity *IdentityInfo) {
	b.Log(&Event{
		RequestID: requestID,
		EventType: EventTypeError,
		Tool:      tool,
		Error:     err.Error(),
		Identity:  identity,
	})
}

// Events returns all logged events.
func (b *BufferedLogger) Events() []*Event {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]*Event{}, b.events...)
}

// Clear removes all logged events.
func (b *BufferedLogger) Clear() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.events = b.events[:0]
}

// FindByRequestID finds all events for a request.
func (b *BufferedLogger) FindByRequestID(requestID string) []*Event {
	b.mu.Lock()
	defer b.mu.Unlock()

	var result []*Event
	for _, e := range b.events {
		if e.RequestID == requestID {
			result = append(result, e)
		}
	}
	return result
}
