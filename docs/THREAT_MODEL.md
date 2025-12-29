# Agent Aegis Threat Model

This document outlines the security threats that Agent Aegis is designed to mitigate, along with the controls implemented and residual risks.

## Overview

Agent Aegis is an identity-aware authorization gateway for LLM/agent tool execution. Its primary purpose is to prevent unauthorized tool access when LLM-powered systems interact with protected resources.

## Threat Categories

### 1. Prompt Injection → Tool Escalation

**Threat**: An attacker manipulates LLM input to trick the model into calling tools it shouldn't, potentially accessing sensitive data or performing unauthorized actions.

**Attack Scenarios**:

- Injected prompts in user messages that instruct the LLM to "ignore previous instructions"
- Indirect injection via fetched documents or database content
- Adversarial inputs designed to bypass safety guidelines

**Controls**:

- ✅ **Scope-based authorization**: Tools can only be called if the token includes the required scope
- ✅ **Deny-by-default policy**: Unknown tools are automatically rejected
- ✅ **Separation of concerns**: LLM reasoning is separated from tool execution
- ✅ **Identity binding**: Every request is tied to a verified JWT identity

**Residual Risk**: If an attacker can obtain or forge a valid token with elevated scopes, they can still execute tools. Token protection is the responsibility of the orchestrator.

---

### 2. Confused Deputy Attack

**Threat**: A legitimate service with elevated privileges is tricked into performing actions on behalf of an unauthorized party.

**Attack Scenarios**:

- LLM orchestrator has broad permissions; attacker exploits this via prompt injection
- Cached credentials used for all users regardless of their actual permissions
- Service account with admin access used for all tool calls

**Controls**:

- ✅ **Per-request authorization**: Each request is individually authorized
- ✅ **Token scopes match caller's permissions**: Orchestrator should issue tokens with minimal necessary scopes
- ✅ **Subject tracking**: Audit logs record the identity making each request
- ✅ **Tool-level subject restrictions**: Sensitive tools can require specific subjects

**Mitigation Strategy**: Issue short-lived, minimally-scoped tokens for each user session. Never share tokens across users.

---

### 3. Token Theft / Replay

**Threat**: An attacker steals a valid JWT and replays it to gain unauthorized access.

**Attack Scenarios**:

- Token exposed in logs or error messages
- Man-in-the-middle attack on unencrypted connections
- Token stored insecurely in client applications

**Controls**:

- ✅ **Token expiration**: Tokens have a limited lifetime
- ✅ **JWT signature verification**: Tampered tokens are rejected
- ✅ **Audit logging**: All requests are logged with token identifiers (JTI)

**Recommendations**:

- Always use HTTPS in production
- Set short token expiration times (e.g., 15-60 minutes)
- Implement token rotation for long-running processes
- Monitor audit logs for suspicious patterns

---

### 4. Argument Injection / Validation Bypass

**Threat**: Malicious tool arguments exploit vulnerabilities in downstream systems.

**Attack Scenarios**:

- SQL injection via tool arguments
- Path traversal in file-related tools
- Command injection in system tools

**Controls**:

- ✅ **Schema-based validation**: Tool arguments are validated against strict schemas
- ✅ **Type enforcement**: Arguments must match expected types
- ✅ **Pattern matching**: String arguments can be restricted via regex patterns
- ✅ **Enum constraints**: Arguments can be limited to predefined values

**Recommendations**:

- Define strict schemas for all tools
- Use restrictive patterns (e.g., `^[a-zA-Z0-9-]+$` for IDs)
- Never pass raw arguments to shell commands or SQL queries

---

### 5. Audit Log Tampering / Evasion

**Threat**: An attacker attempts to hide their activities by manipulating or avoiding audit logs.

**Attack Scenarios**:

- Modifying log files to remove evidence
- Overwhelming logs with noise to hide real attacks
- Using tokens without JTI to avoid correlation

**Controls**:

- ✅ **Immutable logging**: Write-only log outputs (when configured)
- ✅ **Request IDs**: Every request gets a unique ID for correlation
- ✅ **Structured logging**: JSON format enables analysis and alerting
- ✅ **Identity capture**: All logs include caller identity information

**Recommendations**:

- Send logs to a centralized, append-only logging system
- Set up alerts for denied requests
- Monitor for unusual patterns (e.g., many 403s from one identity)

---

### 6. Data Leakage via Tool Responses

**Threat**: Sensitive data returned by tools is exposed to unauthorized parties or leaked via LLM outputs.

**Attack Scenarios**:

- Tool returns more data than necessary
- LLM includes sensitive data in its response to user
- Error messages reveal internal system details

**Controls**:

- ✅ **Gateway isolation**: Agent Aegis only returns executor responses, not internal state
- ✅ **Sanitized error messages**: Internal errors are not exposed to clients

**Recommendations**:

- Design tools to return minimal necessary data
- Consider response filtering for sensitive fields
- Train LLMs not to repeat sensitive information verbatim

---

### 7. Denial of Service

**Threat**: An attacker overwhelms the gateway to prevent legitimate requests.

**Attack Scenarios**:

- High volume of requests from compromised clients
- Slow-loris style attacks keeping connections open
- Expensive tool calls that consume resources

**Controls**:

- ✅ **Request timeouts**: All requests have configurable timeouts
- ✅ **Efficient authorization**: Policy checks are fast in-memory operations

**Recommendations** (not yet implemented):

- Add rate limiting per identity
- Implement request queuing for expensive operations
- Use circuit breakers for failing executors

---

## Security Boundaries

```
┌─────────────────────────────────────────────────────────────────┐
│                    Untrusted Zone                               │
│  ┌─────────────────┐                                            │
│  │    LLM/Agent    │  ← May be influenced by prompt injection   │
│  └────────┬────────┘                                            │
│           │ (JWT + tool request)                                │
├───────────┼─────────────────────────────────────────────────────┤
│           ▼                                                     │
│  ┌─────────────────┐                                            │
│  │  Agent Aegis    │  ← Security enforcement point              │
│  │  (Gateway)      │                                            │
│  │  - JWT verify   │                                            │
│  │  - Policy check │                                            │
│  │  - Schema valid │                                            │
│  │  - Audit log    │                                            │
│  └────────┬────────┘                                            │
│           │                                                     │
│                    Trusted Zone                                 │
│           ▼                                                     │
│  ┌─────────────────┐                                            │
│  │ Tool Executor   │  ← Trusted to handle authorized requests   │
│  └────────┬────────┘                                            │
│           ▼                                                     │
│  ┌─────────────────┐                                            │
│  │ Protected APIs  │  ← Protected resources                     │
│  └─────────────────┘                                            │
└─────────────────────────────────────────────────────────────────┘
```

**Key Principle**: Even if the LLM is fully compromised by prompt injection, it cannot execute unauthorized tools because:

1. It cannot forge JWT signatures
2. It cannot add scopes to its token
3. It cannot bypass policy checks

---

## Security Checklist

Before deploying to production:

- [ ] Use HTTPS for all connections
- [ ] Configure proper JWT verification (JWKS, not dev secrets)
- [ ] Set appropriate token expiration times
- [ ] Review and lock down policy file
- [ ] Define schemas for all tools
- [ ] Set up centralized logging
- [ ] Configure rate limiting
- [ ] Implement monitoring and alerting
- [ ] Restrict file system access
- [ ] Run as non-root user
- [ ] Use read-only container images (if containerized)
