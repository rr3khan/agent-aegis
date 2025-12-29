// Package main is the entry point for Agent Aegis.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rr3khan/agent-aegis/internal/audit"
	"github.com/rr3khan/agent-aegis/internal/auth"
	"github.com/rr3khan/agent-aegis/internal/executor"
	"github.com/rr3khan/agent-aegis/internal/handler"
	"github.com/rr3khan/agent-aegis/internal/policy"
	"github.com/rr3khan/agent-aegis/internal/validation"
)

// Config holds the application configuration.
type Config struct {
	// Server settings
	Port string
	Host string

	// Policy file path
	PolicyFile string

	// JWT settings
	DevSecret string // For development only

	// Executor settings
	ExecutorURL     string
	ExecutorTimeout time.Duration

	// Logging
	AuditLogFile string
	PrettyLogs   bool
}

func main() {
	cfg := parseFlags()

	// Load policy
	pol, err := policy.LoadPolicy(cfg.PolicyFile)
	if err != nil {
		log.Fatalf("Failed to load policy: %v", err)
	}
	log.Printf("Loaded policy with %d tools", len(pol.Tools))

	// Create validator and register schemas from policy
	validator := validation.NewValidator()
	for toolName, toolPolicy := range pol.Tools {
		if len(toolPolicy.ArgSchema) > 0 {
			if err := validator.RegisterSchemaFromMap(toolName, toolPolicy.ArgSchema); err != nil {
				log.Printf("Warning: failed to register schema for tool '%s': %v", toolName, err)
			}
		}
	}

	// Create JWT verifier
	var verifier *auth.JWTVerifier
	if cfg.DevSecret != "" {
		verifier = auth.NewDevVerifier(cfg.DevSecret)
		log.Println("Using development JWT secret (NOT for production)")
	} else {
		verifier = auth.NewVerifier(pol.Defaults.AllowedIssuers, pol.Defaults.AllowedAudiences)
	}

	// Create executor
	var exec executor.Executor
	if cfg.ExecutorURL != "" {
		exec = executor.NewHTTPExecutor(cfg.ExecutorURL, cfg.ExecutorTimeout)
		log.Printf("Forwarding to executor at: %s", cfg.ExecutorURL)
	} else {
		exec = executor.NewMockExecutor()
		log.Println("Using mock executor (no downstream configured)")
	}

	// Create audit logger
	var auditLogger handler.AuditLogger
	if cfg.AuditLogFile != "" {
		logger, err := audit.NewFileLogger(cfg.AuditLogFile, cfg.PrettyLogs)
		if err != nil {
			log.Fatalf("Failed to create audit logger: %v", err)
		}
		auditLogger = logger
	} else {
		auditLogger = audit.NewStdoutLogger()
	}

	// Create handler
	h := handler.NewHandler(handler.Config{
		Verifier:    verifier,
		Policy:      pol,
		Validator:   validator,
		Executor:    exec,
		AuditLogger: auditLogger,
	})

	// Create server
	addr := fmt.Sprintf("%s:%s", cfg.Host, cfg.Port)
	srv := &http.Server{
		Addr:         addr,
		Handler:      loggingMiddleware(h.Router()),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server in goroutine
	go func() {
		log.Printf("🛡️  Agent Aegis starting on %s", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}()

	// Wait for shutdown signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	log.Println("Server stopped")
}

func parseFlags() *Config {
	cfg := &Config{}

	flag.StringVar(&cfg.Port, "port", getEnvOrDefault("AEGIS_PORT", "8081"), "Server port")
	flag.StringVar(&cfg.Host, "host", getEnvOrDefault("AEGIS_HOST", ""), "Server host")
	flag.StringVar(&cfg.PolicyFile, "config", getEnvOrDefault("AEGIS_POLICY_FILE", "config/policy.yaml"), "Policy file path")
	flag.StringVar(&cfg.DevSecret, "dev-secret", getEnvOrDefault("AEGIS_DEV_SECRET", "aegis-dev-secret-do-not-use-in-prod"), "Development JWT secret")
	flag.StringVar(&cfg.ExecutorURL, "executor-url", getEnvOrDefault("AEGIS_EXECUTOR_URL", ""), "Downstream executor URL")
	flag.DurationVar(&cfg.ExecutorTimeout, "executor-timeout", 30*time.Second, "Executor request timeout")
	flag.StringVar(&cfg.AuditLogFile, "audit-log", getEnvOrDefault("AEGIS_AUDIT_LOG", ""), "Audit log file (empty for stdout)")
	flag.BoolVar(&cfg.PrettyLogs, "pretty", false, "Pretty print JSON logs")

	flag.Parse()

	return cfg
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// loggingMiddleware logs HTTP requests.
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Wrap response writer to capture status code
		wrapped := &statusRecorder{ResponseWriter: w, status: http.StatusOK}

		next.ServeHTTP(wrapped, r)

		log.Printf("%s %s %d %s",
			r.Method,
			r.URL.Path,
			wrapped.status,
			time.Since(start),
		)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (rec *statusRecorder) WriteHeader(code int) {
	rec.status = code
	rec.ResponseWriter.WriteHeader(code)
}
