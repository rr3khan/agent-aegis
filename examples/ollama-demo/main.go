// Package main provides an E2E demo using Ollama with Agent Aegis.
// This demonstrates how an LLM can request tool execution through the identity gateway.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/riyadkhan/agent-aegis/internal/auth"
)

const (
	defaultAegisURL  = "http://localhost:8080"
	defaultOllamaURL = "http://localhost:11434"
	defaultModel     = "llama3.1:8b"
	jwtSecret        = "aegis-dev-secret-do-not-use-in-prod"
)

// Tool represents a tool that the LLM can request
type Tool struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Parameters  string `json:"parameters"`
}

var availableTools = []Tool{
	{
		Name:        "get_protected_status",
		Description: "Get the build/test status of a project",
		Parameters:  `{"project": "string (required)"}`,
	},
	{
		Name:        "get_weather",
		Description: "Get current weather for a location",
		Parameters:  `{"location": "string (required)"}`,
	},
	{
		Name:        "calculate",
		Description: "Perform a mathematical calculation",
		Parameters:  `{"expression": "string (required, e.g., '5 + 3')"}`,
	},
	{
		Name:        "list_issues",
		Description: "List issues for a project",
		Parameters:  `{"project": "string (required)", "status": "string (open/closed/all)", "limit": "integer"}`,
	},
}

func main() {
	aegisURL := getEnv("AEGIS_URL", defaultAegisURL)
	ollamaURL := getEnv("OLLAMA_URL", defaultOllamaURL)
	model := getEnv("OLLAMA_MODEL", defaultModel)

	fmt.Println("🛡️  Agent Aegis + Ollama E2E Demo")
	fmt.Println("================================")
	fmt.Printf("Aegis Gateway: %s\n", aegisURL)
	fmt.Printf("Ollama URL: %s\n", ollamaURL)
	fmt.Printf("Model: %s\n\n", model)

	// Check Ollama is running
	if !checkOllama(ollamaURL) {
		log.Fatal("❌ Ollama is not running. Please start Ollama first: ollama serve")
	}
	fmt.Println("✅ Ollama is running")

	// Check Agent Aegis is running
	if !checkAegis(aegisURL) {
		log.Fatal("❌ Agent Aegis is not running. Please start it first: task dev")
	}
	fmt.Println("✅ Agent Aegis is running")

	// Generate tokens with different scopes for demo
	fmt.Println("\n📋 Demo Scenarios:")
	fmt.Println("------------------")

	// Scenario 1: User with read permissions
	fmt.Println("\n🔹 Scenario 1: User with read permissions")
	runScenario(aegisURL, ollamaURL, model,
		"demo-agent@example.com",
		[]string{"tools:status:read", "tools:demo:read"},
		"What is the current status of the 'agent-aegis' project?")

	// Scenario 2: User trying to access without proper scope
	fmt.Println("\n🔹 Scenario 2: User trying to list issues without permission")
	runScenario(aegisURL, ollamaURL, model,
		"limited-user@example.com",
		[]string{"tools:demo:read"}, // Missing tools:issues:read
		"List all open issues for the 'backend' project")

	// Scenario 3: Weather and calculation demo
	fmt.Println("\n🔹 Scenario 3: Using allowed demo tools")
	runScenario(aegisURL, ollamaURL, model,
		"demo-user@example.com",
		[]string{"tools:demo:read"},
		"What's the weather in San Francisco? Also, what is 42 * 3?")

	fmt.Println("\n✨ Demo complete!")
}

func runScenario(aegisURL, ollamaURL, model, subject string, scopes []string, userQuery string) {
	fmt.Printf("   User: %s\n", subject)
	fmt.Printf("   Scopes: %v\n", scopes)
	fmt.Printf("   Query: %s\n\n", userQuery)

	// Generate JWT token
	token, err := auth.GenerateDevToken(jwtSecret, subject, scopes, time.Hour)
	if err != nil {
		log.Printf("   ❌ Failed to generate token: %v", err)
		return
	}

	// Build prompt for LLM
	prompt := buildPrompt(userQuery, availableTools)

	// Get LLM response
	fmt.Println("   🤖 Asking LLM...")
	llmResponse, err := queryOllama(ollamaURL, model, prompt)
	if err != nil {
		log.Printf("   ❌ LLM error: %v", err)
		return
	}

	fmt.Printf("   📝 LLM Response:\n%s\n", indent(llmResponse, "      "))

	// Parse tool calls from LLM response
	toolCalls := parseToolCalls(llmResponse)
	if len(toolCalls) == 0 {
		fmt.Println("   ℹ️  LLM did not request any tool calls")
		return
	}

	fmt.Printf("   🔧 Tool calls detected: %d\n", len(toolCalls))

	// Execute each tool call through Agent Aegis
	for i, tc := range toolCalls {
		fmt.Printf("\n   [%d] Executing: %s\n", i+1, tc.Tool)
		result, err := executeToolViaAegis(aegisURL, token, tc.Tool, tc.Args)
		if err != nil {
			fmt.Printf("   ❌ Error: %v\n", err)
			continue
		}

		if result.OK {
			fmt.Printf("   ✅ Success: %s\n", formatResult(result.Result))
		} else {
			fmt.Printf("   🚫 Denied: %s\n", result.Error)
		}
	}
}

func buildPrompt(userQuery string, tools []Tool) string {
	var sb strings.Builder

	sb.WriteString("You are an AI assistant that can use tools to help users. ")
	sb.WriteString("When you need to use a tool, respond with a JSON tool call in this exact format:\n")
	sb.WriteString("```json\n{\"tool\": \"tool_name\", \"args\": {\"param\": \"value\"}}\n```\n\n")
	sb.WriteString("Available tools:\n")

	for _, t := range tools {
		sb.WriteString(fmt.Sprintf("- %s: %s\n  Parameters: %s\n", t.Name, t.Description, t.Parameters))
	}

	sb.WriteString("\nUser request: ")
	sb.WriteString(userQuery)
	sb.WriteString("\n\nProvide your response. If you need to call a tool, include the JSON tool call.")

	return sb.String()
}

type ToolCall struct {
	Tool string                 `json:"tool"`
	Args map[string]interface{} `json:"args"`
}

func parseToolCalls(response string) []ToolCall {
	var calls []ToolCall

	// Find JSON blocks in the response
	re := regexp.MustCompile("```json\\s*\\n?([\\s\\S]*?)\\n?```")
	matches := re.FindAllStringSubmatch(response, -1)

	for _, match := range matches {
		if len(match) > 1 {
			var tc ToolCall
			if err := json.Unmarshal([]byte(match[1]), &tc); err == nil && tc.Tool != "" {
				calls = append(calls, tc)
			}
		}
	}

	// Also try to find inline JSON
	re2 := regexp.MustCompile(`\{"tool":\s*"[^"]+",\s*"args":\s*\{[^}]*\}\}`)
	inlineMatches := re2.FindAllString(response, -1)

	for _, match := range inlineMatches {
		var tc ToolCall
		if err := json.Unmarshal([]byte(match), &tc); err == nil && tc.Tool != "" {
			// Avoid duplicates
			found := false
			for _, existing := range calls {
				if existing.Tool == tc.Tool {
					found = true
					break
				}
			}
			if !found {
				calls = append(calls, tc)
			}
		}
	}

	return calls
}

type AegisResponse struct {
	RequestID string                 `json:"request_id"`
	OK        bool                   `json:"ok"`
	Result    map[string]interface{} `json:"result,omitempty"`
	Error     string                 `json:"error,omitempty"`
}

func executeToolViaAegis(aegisURL, token, tool string, args map[string]interface{}) (*AegisResponse, error) {
	reqBody, _ := json.Marshal(map[string]interface{}{
		"tool": tool,
		"args": args,
	})

	req, err := http.NewRequest("POST", aegisURL+"/execute", bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	var result AegisResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %s", string(body))
	}

	return &result, nil
}

type OllamaRequest struct {
	Model  string `json:"model"`
	Prompt string `json:"prompt"`
	Stream bool   `json:"stream"`
}

type OllamaResponse struct {
	Response string `json:"response"`
	Done     bool   `json:"done"`
}

func queryOllama(ollamaURL, model, prompt string) (string, error) {
	reqBody, _ := json.Marshal(OllamaRequest{
		Model:  model,
		Prompt: prompt,
		Stream: false,
	})

	resp, err := http.Post(ollamaURL+"/api/generate", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	var result OllamaResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("failed to parse Ollama response: %v", err)
	}

	return result.Response, nil
}

func checkOllama(url string) bool {
	resp, err := http.Get(url + "/api/tags")
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

func checkAegis(url string) bool {
	resp, err := http.Get(url + "/health")
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

func getEnv(key, defaultValue string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultValue
}

func indent(s, prefix string) string {
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		lines[i] = prefix + line
	}
	return strings.Join(lines, "\n")
}

func formatResult(result map[string]interface{}) string {
	data, _ := json.MarshalIndent(result, "", "  ")
	if len(data) > 200 {
		return string(data[:200]) + "..."
	}
	return string(data)
}

