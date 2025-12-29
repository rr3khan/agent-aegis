package policy

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParsePolicy(t *testing.T) {
	yaml := `
tools:
  get_status:
    required_scope: "tools:status:read"
    description: "Get status"
  create_item:
    required_scope: "tools:items:write"
defaults:
  deny_unknown_tools: true
  deny_missing_scopes: true
`
	policy, err := ParsePolicy([]byte(yaml))
	require.NoError(t, err)
	assert.Len(t, policy.Tools, 2)
	assert.True(t, policy.Defaults.DenyUnknownTools)
	assert.True(t, policy.Defaults.DenyMissingScopes)
}

func TestParsePolicy_Invalid(t *testing.T) {
	_, err := ParsePolicy([]byte("not: valid: yaml: here"))
	assert.Error(t, err)
}

func TestParsePolicy_MissingScope(t *testing.T) {
	yaml := `
tools:
  get_status:
    description: "No scope defined"
`
	_, err := ParsePolicy([]byte(yaml))
	assert.ErrorIs(t, err, ErrInvalidPolicy)
}

func TestAuthorize_Allowed(t *testing.T) {
	policy := &Policy{
		Tools: map[string]ToolPolicy{
			"get_status": {RequiredScope: "tools:status:read"},
		},
		Defaults: DefaultPolicy{DenyUnknownTools: true},
	}

	decision := policy.Authorize(AuthorizationRequest{
		Tool:   "get_status",
		Scopes: []string{"tools:status:read", "other:scope"},
	})

	assert.True(t, decision.Allowed)
	assert.Equal(t, "authorized", decision.Reason)
}

func TestAuthorize_MissingScope(t *testing.T) {
	policy := &Policy{
		Tools: map[string]ToolPolicy{
			"get_status": {RequiredScope: "tools:status:read"},
		},
		Defaults: DefaultPolicy{DenyUnknownTools: true},
	}

	decision := policy.Authorize(AuthorizationRequest{
		Tool:   "get_status",
		Scopes: []string{"tools:other:read"},
	})

	assert.False(t, decision.Allowed)
	assert.Contains(t, decision.Reason, "missing scope")
}

func TestAuthorize_UnknownTool(t *testing.T) {
	policy := &Policy{
		Tools: map[string]ToolPolicy{
			"get_status": {RequiredScope: "tools:status:read"},
		},
		Defaults: DefaultPolicy{DenyUnknownTools: true},
	}

	decision := policy.Authorize(AuthorizationRequest{
		Tool:   "unknown_tool",
		Scopes: []string{"tools:status:read"},
	})

	assert.False(t, decision.Allowed)
	assert.Contains(t, decision.Reason, "unknown tool")
}

func TestAuthorize_DisabledTool(t *testing.T) {
	disabled := false
	policy := &Policy{
		Tools: map[string]ToolPolicy{
			"get_status": {
				RequiredScope: "tools:status:read",
				Enabled:       &disabled,
			},
		},
	}

	decision := policy.Authorize(AuthorizationRequest{
		Tool:   "get_status",
		Scopes: []string{"tools:status:read"},
	})

	assert.False(t, decision.Allowed)
	assert.Contains(t, decision.Reason, "disabled")
}

func TestAuthorize_AllowedIssuer(t *testing.T) {
	policy := &Policy{
		Tools: map[string]ToolPolicy{
			"get_status": {
				RequiredScope:  "tools:status:read",
				AllowedIssuers: []string{"trusted-issuer"},
			},
		},
	}

	// Correct issuer
	decision := policy.Authorize(AuthorizationRequest{
		Tool:   "get_status",
		Scopes: []string{"tools:status:read"},
		Issuer: "trusted-issuer",
	})
	assert.True(t, decision.Allowed)

	// Wrong issuer
	decision = policy.Authorize(AuthorizationRequest{
		Tool:   "get_status",
		Scopes: []string{"tools:status:read"},
		Issuer: "untrusted-issuer",
	})
	assert.False(t, decision.Allowed)
	assert.Contains(t, decision.Reason, "issuer")
}

func TestAuthorize_AllowedSubjects(t *testing.T) {
	policy := &Policy{
		Tools: map[string]ToolPolicy{
			"admin_action": {
				RequiredScope:   "tools:admin:write",
				AllowedSubjects: []string{"admin@example.com", "admin-*"},
			},
		},
	}

	// Exact match
	decision := policy.Authorize(AuthorizationRequest{
		Tool:    "admin_action",
		Scopes:  []string{"tools:admin:write"},
		Subject: "admin@example.com",
	})
	assert.True(t, decision.Allowed)

	// Wildcard match
	decision = policy.Authorize(AuthorizationRequest{
		Tool:    "admin_action",
		Scopes:  []string{"tools:admin:write"},
		Subject: "admin-user1",
	})
	assert.True(t, decision.Allowed)

	// No match
	decision = policy.Authorize(AuthorizationRequest{
		Tool:    "admin_action",
		Scopes:  []string{"tools:admin:write"},
		Subject: "user@example.com",
	})
	assert.False(t, decision.Allowed)
	assert.Contains(t, decision.Reason, "subject")
}

func TestAuthorize_MultipleScopes(t *testing.T) {
	policy := &Policy{
		Tools: map[string]ToolPolicy{
			"get_status": {
				RequiredScopes: []string{"tools:status:read", "tools:status:admin"},
			},
		},
	}

	// Has one of the required scopes
	decision := policy.Authorize(AuthorizationRequest{
		Tool:   "get_status",
		Scopes: []string{"tools:status:read"},
	})
	assert.True(t, decision.Allowed)

	// Has the other required scope
	decision = policy.Authorize(AuthorizationRequest{
		Tool:   "get_status",
		Scopes: []string{"tools:status:admin"},
	})
	assert.True(t, decision.Allowed)

	// Has neither
	decision = policy.Authorize(AuthorizationRequest{
		Tool:   "get_status",
		Scopes: []string{"tools:other:read"},
	})
	assert.False(t, decision.Allowed)
}

func TestGetToolPolicy(t *testing.T) {
	policy := &Policy{
		Tools: map[string]ToolPolicy{
			"get_status": {RequiredScope: "tools:status:read"},
		},
	}

	toolPolicy, exists := policy.GetToolPolicy("get_status")
	assert.True(t, exists)
	assert.Equal(t, "tools:status:read", toolPolicy.RequiredScope)

	_, exists = policy.GetToolPolicy("unknown")
	assert.False(t, exists)
}

func TestListTools(t *testing.T) {
	policy := &Policy{
		Tools: map[string]ToolPolicy{
			"tool_a": {RequiredScope: "a"},
			"tool_b": {RequiredScope: "b"},
			"tool_c": {RequiredScope: "c"},
		},
	}

	tools := policy.ListTools()
	assert.Len(t, tools, 3)
	assert.Contains(t, tools, "tool_a")
	assert.Contains(t, tools, "tool_b")
	assert.Contains(t, tools, "tool_c")
}

func TestMatchesSubject(t *testing.T) {
	tests := []struct {
		nicelist []string
		subject   string
		expected  bool
	}{
		{[]string{"admin@example.com"}, "admin@example.com", true},
		{[]string{"admin@example.com"}, "user@example.com", false},
		{[]string{"*"}, "anyone", true},
		{[]string{"admin-*"}, "admin-user1", true},
		{[]string{"admin-*"}, "user-admin", false},
		{[]string{"admin@example.com", "user@example.com"}, "user@example.com", true},
	}

	for _, tt := range tests {
		result := matchesSubject(tt.nicelist, tt.subject)
		assert.Equal(t, tt.expected, result, "nicelist=%v, subject=%s", tt.nicelist, tt.subject)
	}
}

