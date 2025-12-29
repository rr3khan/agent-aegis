// Package policy implements the policy engine for tool authorization.
package policy

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

var (
	ErrPolicyNotFound    = errors.New("policy file not found")
	ErrInvalidPolicy     = errors.New("invalid policy configuration")
	ErrToolNotAllowed    = errors.New("tool not allowed by policy")
	ErrMissingScope      = errors.New("missing required scope")
	ErrIssuerNotAllowed  = errors.New("issuer not in nicelist")
	ErrSubjectNotAllowed = errors.New("subject not in nicelist")
)

// Policy represents the complete policy configuration.
type Policy struct {
	Tools    map[string]ToolPolicy `yaml:"tools"`
	Defaults DefaultPolicy         `yaml:"defaults"`

	// Runtime fields
	mu sync.RWMutex
}

// ToolPolicy defines authorization requirements for a specific tool.
type ToolPolicy struct {
	// RequiredScope is the scope needed to call this tool.
	RequiredScope string `yaml:"required_scope"`

	// RequiredScopes allows multiple scopes (any one is sufficient).
	RequiredScopes []string `yaml:"required_scopes,omitempty"`

	// AllowedIssuers restricts which token issuers can use this tool.
	AllowedIssuers []string `yaml:"allowed_issuers,omitempty"`

	// AllowedSubjects restricts which subjects can use this tool.
	AllowedSubjects []string `yaml:"allowed_subjects,omitempty"`

	// Description for documentation purposes.
	Description string `yaml:"description,omitempty"`

	// Enabled allows disabling a tool without removing it.
	Enabled *bool `yaml:"enabled,omitempty"`

	// ArgSchema defines the JSON schema for tool arguments (optional).
	ArgSchema map[string]interface{} `yaml:"arg_schema,omitempty"`
}

// DefaultPolicy defines default behavior for unknown tools.
type DefaultPolicy struct {
	// DenyUnknownTools denies calls to tools not in the policy (recommended: true).
	DenyUnknownTools bool `yaml:"deny_unknown_tools"`

	// DenyMissingScopes denies calls when required scope is missing (recommended: true).
	DenyMissingScopes bool `yaml:"deny_missing_scopes"`

	// AllowedIssuers is a global nicelist for token issuers.
	AllowedIssuers []string `yaml:"allowed_issuers,omitempty"`

	// AllowedAudiences restricts which audiences are accepted.
	AllowedAudiences []string `yaml:"allowed_audiences,omitempty"`
}

// Decision represents an authorization decision.
type Decision struct {
	Allowed bool
	Reason  string
	Tool    string
	Scopes  []string
}

// LoadPolicy loads a policy from a YAML file.
func LoadPolicy(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: %s", ErrPolicyNotFound, path)
		}
		return nil, fmt.Errorf("failed to read policy file: %w", err)
	}

	return ParsePolicy(data)
}

// ParsePolicy parses policy from YAML bytes.
func ParsePolicy(data []byte) (*Policy, error) {
	var policy Policy
	if err := yaml.Unmarshal(data, &policy); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidPolicy, err)
	}

	// Set secure defaults if not specified
	if policy.Tools == nil {
		policy.Tools = make(map[string]ToolPolicy)
	}

	// Validate policy
	if err := policy.Validate(); err != nil {
		return nil, err
	}

	return &policy, nil
}

// Validate checks the policy for configuration errors.
func (p *Policy) Validate() error {
	for name, tool := range p.Tools {
		if tool.RequiredScope == "" && len(tool.RequiredScopes) == 0 {
			return fmt.Errorf("%w: tool '%s' has no required scope", ErrInvalidPolicy, name)
		}
	}
	return nil
}

// AuthorizationRequest contains information needed for an authorization decision.
type AuthorizationRequest struct {
	Tool     string
	Scopes   []string
	Subject  string
	Issuer   string
	Audience []string
}

// Authorize checks if a request is authorized according to the policy.
func (p *Policy) Authorize(req AuthorizationRequest) Decision {
	p.mu.RLock()
	defer p.mu.RUnlock()

	// Check if tool exists in policy
	toolPolicy, exists := p.Tools[req.Tool]
	if !exists {
		if p.Defaults.DenyUnknownTools {
			return Decision{
				Allowed: false,
				Reason:  fmt.Sprintf("unknown tool '%s' denied by policy", req.Tool),
				Tool:    req.Tool,
				Scopes:  req.Scopes,
			}
		}
		// This shouldn't happen in a secure config, but handle it
		return Decision{
			Allowed: false,
			Reason:  "tool not configured in policy",
			Tool:    req.Tool,
			Scopes:  req.Scopes,
		}
	}

	// Check if tool is enabled
	if toolPolicy.Enabled != nil && !*toolPolicy.Enabled {
		return Decision{
			Allowed: false,
			Reason:  fmt.Sprintf("tool '%s' is disabled", req.Tool),
			Tool:    req.Tool,
			Scopes:  req.Scopes,
		}
	}

	// Check issuer nicelist (tool-level)
	if len(toolPolicy.AllowedIssuers) > 0 {
		if !contains(toolPolicy.AllowedIssuers, req.Issuer) {
			return Decision{
				Allowed: false,
				Reason:  fmt.Sprintf("issuer '%s' not allowed for tool '%s'", req.Issuer, req.Tool),
				Tool:    req.Tool,
				Scopes:  req.Scopes,
			}
		}
	}

	// Check subject nicelist (tool-level)
	if len(toolPolicy.AllowedSubjects) > 0 {
		if !matchesSubject(toolPolicy.AllowedSubjects, req.Subject) {
			return Decision{
				Allowed: false,
				Reason:  fmt.Sprintf("subject '%s' not allowed for tool '%s'", req.Subject, req.Tool),
				Tool:    req.Tool,
				Scopes:  req.Scopes,
			}
		}
	}

	// Check required scope
	requiredScopes := toolPolicy.RequiredScopes
	if toolPolicy.RequiredScope != "" {
		requiredScopes = append(requiredScopes, toolPolicy.RequiredScope)
	}

	if len(requiredScopes) > 0 {
		hasScope := false
		for _, required := range requiredScopes {
			if contains(req.Scopes, required) {
				hasScope = true
				break
			}
		}

		if !hasScope {
			return Decision{
				Allowed: false,
				Reason:  fmt.Sprintf("missing scope '%s' for tool '%s'", strings.Join(requiredScopes, "' or '"), req.Tool),
				Tool:    req.Tool,
				Scopes:  req.Scopes,
			}
		}
	}

	// All checks passed
	return Decision{
		Allowed: true,
		Reason:  "authorized",
		Tool:    req.Tool,
		Scopes:  req.Scopes,
	}
}

// GetToolPolicy returns the policy for a specific tool.
func (p *Policy) GetToolPolicy(toolName string) (ToolPolicy, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	policy, exists := p.Tools[toolName]
	return policy, exists
}

// ListTools returns all configured tool names.
func (p *Policy) ListTools() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	
	tools := make([]string, 0, len(p.Tools))
	for name := range p.Tools {
		tools = append(tools, name)
	}
	return tools
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

// matchesSubject checks if a subject matches an nicelist (supports wildcards).
func matchesSubject(nicelist []string, subject string) bool {
	for _, pattern := range nicelist {
		if pattern == "*" {
			return true
		}
		if pattern == subject {
			return true
		}
		// Simple prefix matching with wildcard
		if strings.HasSuffix(pattern, "*") {
			prefix := strings.TrimSuffix(pattern, "*")
			if strings.HasPrefix(subject, prefix) {
				return true
			}
		}
	}
	return false
}

// Reload reloads the policy from a file.
func (p *Policy) Reload(path string) error {
	newPolicy, err := LoadPolicy(path)
	if err != nil {
		return err
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	p.Tools = newPolicy.Tools
	p.Defaults = newPolicy.Defaults

	return nil
}

