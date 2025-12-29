// Package main provides a mock tool executor for testing Agent Aegis.
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

type Request struct {
	Tool string                 `json:"tool"`
	Args map[string]interface{} `json:"args"`
}

type Response struct {
	OK     bool                   `json:"ok"`
	Result map[string]interface{} `json:"result,omitempty"`
	Error  string                 `json:"error,omitempty"`
}

func main() {
	port := os.Getenv("EXECUTOR_PORT")
	if port == "" {
		port = "8081"
	}

	http.HandleFunc("/execute", handleExecute)
	http.HandleFunc("/health", handleHealth)

	addr := ":" + port
	log.Printf("🔧 Mock Tool Executor starting on %s", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status": "ok",
		"type":   "mock-executor",
	})
}

func handleExecute(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req Request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, "invalid request body")
		return
	}

	log.Printf("Executing tool: %s with args: %v", req.Tool, req.Args)

	// Simulate tool execution
	result, err := executeTool(req.Tool, req.Args)
	if err != nil {
		writeError(w, err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(Response{
		OK:     true,
		Result: result,
	})
}

func executeTool(tool string, args map[string]interface{}) (map[string]interface{}, error) {
	// Simulate processing time
	time.Sleep(time.Duration(50+rand.Intn(100)) * time.Millisecond)

	switch tool {
	case "get_protected_status":
		return handleGetStatus(args)
	case "list_issues":
		return handleListIssues(args)
	case "create_issue":
		return handleCreateIssue(args)
	case "lookup_incident":
		return handleLookupIncident(args)
	case "get_weather":
		return handleGetWeather(args)
	case "calculate":
		return handleCalculate(args)
	default:
		return map[string]interface{}{
			"message": fmt.Sprintf("Tool '%s' executed successfully", tool),
			"args":    args,
		}, nil
	}
}

func handleGetStatus(args map[string]interface{}) (map[string]interface{}, error) {
	project := getStringArg(args, "project", "unknown")

	statuses := []string{"green", "yellow", "red"}
	status := statuses[rand.Intn(len(statuses))]

	return map[string]interface{}{
		"project":      project,
		"status":       status,
		"failed_tests": rand.Intn(10),
		"coverage":     fmt.Sprintf("%.1f%%", 80+rand.Float64()*20),
		"last_updated": time.Now().UTC().Format(time.RFC3339),
	}, nil
}

func handleListIssues(args map[string]interface{}) (map[string]interface{}, error) {
	project := getStringArg(args, "project", "demo")
	status := getStringArg(args, "status", "open")
	limit := getIntArg(args, "limit", 10)

	issues := make([]map[string]interface{}, 0)
	for i := 0; i < min(limit, 5); i++ {
		issues = append(issues, map[string]interface{}{
			"id":       fmt.Sprintf("ISSUE-%d", 1000+i),
			"title":    fmt.Sprintf("Sample issue %d for %s", i+1, project),
			"status":   status,
			"priority": []string{"low", "medium", "high"}[rand.Intn(3)],
		})
	}

	return map[string]interface{}{
		"project": project,
		"status":  status,
		"count":   len(issues),
		"issues":  issues,
	}, nil
}

func handleCreateIssue(args map[string]interface{}) (map[string]interface{}, error) {
	title := getStringArg(args, "title", "Untitled")
	project := getStringArg(args, "project", "demo")
	priority := getStringArg(args, "priority", "medium")

	issueID := fmt.Sprintf("ISSUE-%d", 2000+rand.Intn(1000))

	return map[string]interface{}{
		"id":         issueID,
		"title":      title,
		"project":    project,
		"priority":   priority,
		"status":     "open",
		"created_at": time.Now().UTC().Format(time.RFC3339),
		"url":        fmt.Sprintf("https://issues.example.com/%s/%s", project, issueID),
	}, nil
}

func handleLookupIncident(args map[string]interface{}) (map[string]interface{}, error) {
	incidentID := getStringArg(args, "incident_id", "INC-0000")

	return map[string]interface{}{
		"id":          incidentID,
		"title":       "Security Alert: Unusual login activity detected",
		"severity":    "medium",
		"status":      "investigating",
		"created_at":  time.Now().Add(-2 * time.Hour).UTC().Format(time.RFC3339),
		"assigned_to": "security-team",
		"summary":     "Multiple failed login attempts detected from unusual IP ranges.",
	}, nil
}

func handleGetWeather(args map[string]interface{}) (map[string]interface{}, error) {
	location := getStringArg(args, "location", "Unknown")

	conditions := []string{"sunny", "cloudy", "rainy", "snowy", "partly cloudy"}

	return map[string]interface{}{
		"location":    location,
		"temperature": fmt.Sprintf("%d°C", 10+rand.Intn(20)),
		"condition":   conditions[rand.Intn(len(conditions))],
		"humidity":    fmt.Sprintf("%d%%", 40+rand.Intn(40)),
		"wind":        fmt.Sprintf("%d km/h", rand.Intn(30)),
	}, nil
}

func handleCalculate(args map[string]interface{}) (map[string]interface{}, error) {
	expr := getStringArg(args, "expression", "0")

	// Simple evaluation (just for demo - only handles basic math)
	result := evaluateSimpleExpression(expr)

	return map[string]interface{}{
		"expression": expr,
		"result":     result,
	}, nil
}

func evaluateSimpleExpression(expr string) float64 {
	// Very simple evaluation for demo purposes
	// Only handles single operations like "5 + 3"
	expr = strings.TrimSpace(expr)

	for _, op := range []string{"+", "-", "*", "/"} {
		if strings.Contains(expr, op) {
			parts := strings.Split(expr, op)
			if len(parts) == 2 {
				a, _ := strconv.ParseFloat(strings.TrimSpace(parts[0]), 64)
				b, _ := strconv.ParseFloat(strings.TrimSpace(parts[1]), 64)
				switch op {
				case "+":
					return a + b
				case "-":
					return a - b
				case "*":
					return a * b
				case "/":
					if b != 0 {
						return a / b
					}
				}
			}
		}
	}

	result, _ := strconv.ParseFloat(expr, 64)
	return result
}

func getStringArg(args map[string]interface{}, key, defaultValue string) string {
	if v, ok := args[key].(string); ok {
		return v
	}
	return defaultValue
}

func getIntArg(args map[string]interface{}, key string, defaultValue int) int {
	if v, ok := args[key].(float64); ok {
		return int(v)
	}
	if v, ok := args[key].(int); ok {
		return v
	}
	return defaultValue
}

func writeError(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(Response{
		OK:    false,
		Error: message,
	})
}
