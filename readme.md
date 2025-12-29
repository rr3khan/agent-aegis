# Agent Aegis — Identity‑Aware Tool Gateway

**Agent Aegis** is a Go service that enforces **identity- and scope-based authorization** for "agent tools" (actions an LLM-powered workflow wants to perform), using **OIDC/JWT-style access tokens** and **policy-as-code**.

It's designed to sit _in front of_ a tool execution layer, so that:

- the LLM can "request" actions,
- but **only authorized identities** can execute them,
- and execution is always constrained to an explicit nicelist with auditable decisions.

---

## Quick Start

```bash
# Install dependencies
task install-deps

# Run Agent Aegis locally
task dev

# In another terminal, generate a test token
go run ./tools/token-generator -sub user@example.com -scopes tools:demo:read,tools:status:read

# Make a request
curl -X POST http://localhost:8081/execute \
  -H 'Authorization: Bearer <your-token>' \
  -H 'Content-Type: application/json' \
  -d '{"tool": "get_weather", "args": {"location": "London"}}'
```

---

## Why This Is Valuable

When you add tools to an LLM workflow (issue creation, incident lookups, API calls, etc.), the biggest risk is **tool escalation**:

- A prompt injection or confused agent tries to call a tool it shouldn't
- A workflow runs with overly broad privileges
- You can't easily answer: _"Who executed what, and was it allowed?"_

Agent Aegis mitigates those risks by enforcing three core principles:

1. **Least privilege**: tools are allowed only when the token has the right scopes
2. **Separation of concerns**: reasoning (LLM) is separate from execution and authZ enforcement
3. **Auditable control point**: every allow/deny decision is logged with a reason and request ID

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  [ Client / Orchestrator / LLM ]                                │
│           │                                                     │
│           │ (JWT + tool request)                                │
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

**Key security boundary:** Agent Aegis is the authorization "gate."
Even if an LLM is prompt-injected, it can't execute actions unless the request token scopes allow it.

---

## Request Flow

1. A client sends a request to Agent Aegis:

   - `POST /execute`
   - with `Authorization: Bearer <JWT>`
   - including `{ "tool": "...", "args": {...} }`

2. Agent Aegis:

   - Verifies the JWT signature (HMAC for dev, JWKS for production)
   - Extracts identity + scopes (e.g., `sub`, `iss`, `scope`)
   - Checks the **policy file** to determine whether this identity/scope can call the requested tool
   - Validates tool arguments against a strict schema (deny-by-default)

3. If allowed:

   - Agent Aegis forwards the request to a downstream **Tool Executor** (HTTP)
   - Returns the executor's **result** back to the client

4. If denied:
   - Returns a clear error (`401`, `403`, or `400`) and records an audit event

---

## API

### `POST /execute`

Request:

```json
{
  "tool": "get_protected_status",
  "args": { "project": "demo" }
}
```

Response (allowed):

```json
{
  "request_id": "7b0d2d2b-...",
  "ok": true,
  "result": {
    "status": "green",
    "failed_tests": 0
  }
}
```

Response (denied):

```json
{
  "request_id": "7b0d2d2b-...",
  "ok": false,
  "error": "forbidden: missing scope 'tools:status:read'"
}
```

### `GET /health`

Returns `{"status": "ok", "time": "..."}` for health checks.

### `GET /policy/tools`

Returns the list of configured tools (for debugging).

---

## Policy Configuration

Agent Aegis uses a YAML policy file (`config/policy.yaml`) with deny-by-default:

```yaml
defaults:
  deny_unknown_tools: true
  deny_missing_scopes: true

tools:
  get_protected_status:
    description: "Get the status of a protected project"
    required_scope: "tools:status:read"
    arg_schema:
      type: object
      required:
        - project
      properties:
        project:
          type: string
          minLength: 1
          maxLength: 100

  admin_reset_password:
    description: "Reset a user's password (admin only)"
    required_scope: "tools:admin:write"
    allowed_subjects:
      - "admin@example.com"
      - "admin-*"
```

### Tool Policy Options

| Field              | Description                                                        |
| ------------------ | ------------------------------------------------------------------ |
| `required_scope`   | Scope required in the JWT to call this tool                        |
| `required_scopes`  | Alternative: list of scopes (any one is sufficient)                |
| `allowed_issuers`  | Restrict which token issuers can use this tool                     |
| `allowed_subjects` | Restrict which subjects can use this tool (supports `*` wildcards) |
| `enabled`          | Set to `false` to disable a tool without removing it               |
| `arg_schema`       | JSON Schema-like validation for tool arguments                     |

---

## Taskfile Commands

| Command                 | Description                  |
| ----------------------- | ---------------------------- |
| `task dev`              | Run Agent Aegis locally      |
| `task build`            | Build the binary             |
| `task test`             | Run all unit tests           |
| `task test:unit`        | Run unit tests with coverage |
| `task test:integration` | Run integration tests        |
| `task ci`               | Run full CI pipeline         |
| `task lint`             | Run linter                   |
| `task fmt`              | Format Go code               |
| `task demo:executor`    | Run the mock tool executor   |
| `task demo:ollama`      | Run the Ollama E2E demo      |
| `task generate:token`   | Generate a test JWT token    |
| `task clean`            | Clean build artifacts        |

---

## Configuration Options

### Environment Variables

| Variable             | Default                 | Description                          |
| -------------------- | ----------------------- | ------------------------------------ |
| `AEGIS_PORT`         | `8081`                  | Server port                          |
| `AEGIS_HOST`         | ``                      | Server host (empty = all interfaces) |
| `AEGIS_POLICY_FILE`  | `config/policy.yaml`    | Policy file path                     |
| `AEGIS_DEV_SECRET`   | `aegis-dev-secret...`   | Development JWT secret ⚠️            |
| `AEGIS_EXECUTOR_URL` | `` (uses mock executor) | Downstream executor URL              |
| `AEGIS_AUDIT_LOG`    | ``                      | Audit log file (empty = stdout)      |

> ⚠️ **Security Warning:** The default `AEGIS_DEV_SECRET` is for local development only. In production, use OIDC/JWKS with proper key management. Never use the default secret in production environments.

### Command Line Flags

```bash
./bin/aegis \
  --port 8081 \
  --config config/policy.yaml \
  --executor-url http://localhost:8081 \
  --dev-secret my-secret \
  --pretty
```

---

## E2E Demo with Ollama

To run a full end-to-end demo with a local LLM, you'll need Ollama installed.

### Prerequisites

1. **Install Ollama** from [ollama.com](https://ollama.com)
2. **Pull a model** (the demo uses `llama3.1:8b` by default):
   ```bash
   ollama pull llama3.1:8b
   ```
3. **Start Ollama** (if not already running):
   ```bash
   ollama serve
   ```

### Running the Demo

```bash
# Terminal 1: Start the mock tool executor
task demo:executor

# Terminal 2: Start Agent Aegis
task dev

# Terminal 3: Run the Ollama demo
task demo:ollama
```

The demo shows:

1. An LLM (via Ollama) receiving a user query
2. The LLM deciding to call a tool
3. The tool request going through Agent Aegis
4. Authorization being enforced based on JWT scopes
5. Audit logs capturing the decision

---

## Project Structure

```
agent-aegis/
├── cmd/aegis/              # Main entry point
├── internal/
│   ├── auth/               # JWT verification
│   ├── policy/             # Policy engine
│   ├── validation/         # Schema validation
│   ├── executor/           # Tool execution forwarding
│   ├── audit/              # Audit logging
│   └── handler/            # HTTP handlers
├── config/
│   └── policy.yaml         # Default policy configuration
├── examples/
│   ├── mock-executor/      # Mock tool executor for testing
│   └── ollama-demo/        # E2E demo with Ollama
├── tools/
│   └── token-generator/    # CLI tool to generate test tokens
├── tests/
│   └── integration/        # Integration tests
├── docs/
│   └── THREAT_MODEL.md     # Security threat model
├── Taskfile.yaml           # Task runner configuration
└── go.mod
```

---

## Security

### What Agent Aegis Does ✅

- Enforces tool execution authorization using JWT scopes
- Validates tool inputs (schema-based, strict)
- Deny-by-default policy enforcement
- Generates structured audit logs (allow/deny, reason, request_id)
- Forwards allowed tool calls to a downstream executor

### What Agent Aegis Does NOT Do ❌

- Run an LLM (that stays in your orchestrator / Ollama)
- Store secrets (that stays in your secret manager)
- Provide a full IAM system (this is scoped to tool authorization)

### Threat Model

See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for detailed security analysis including:

- Prompt injection → tool escalation mitigation
- Confused deputy attack prevention
- Token theft / replay protection
- Argument injection defense
- Audit log integrity

---

## Adding a New Tool

1. Add the tool to `config/policy.yaml`:

```yaml
tools:
  my_new_tool:
    description: "Description of what this tool does"
    required_scope: "tools:myapp:read"
    arg_schema:
      type: object
      required:
        - param1
      properties:
        param1:
          type: string
```

2. Ensure your downstream executor handles the tool
3. Issue tokens with the appropriate scope to callers

---

## Development

```bash
# Install Go dependencies
go mod download

# Run tests with coverage
task test:unit

# Run linter
task lint

# Build binary
task build
```

---

## Roadmap

Future enhancements may include:

- [ ] OIDC/JWKS integration for production deployments
- [ ] Per-tool rate limits and quotas
- [ ] Response schema validation
- [ ] Multi-tenant policy support
- [ ] OpenTelemetry audit sink integration
- [ ] Admin API for policy hot-reload

---
