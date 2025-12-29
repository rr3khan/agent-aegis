// Package validation provides schema-based validation for tool arguments.
package validation

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strings"
)

var (
	ErrValidationFailed = errors.New("validation failed")
	ErrInvalidSchema    = errors.New("invalid schema")
	ErrMissingRequired  = errors.New("missing required field")
	ErrInvalidType      = errors.New("invalid type")
	ErrInvalidValue     = errors.New("invalid value")
)

// Schema represents a JSON-schema-like validation schema.
type Schema struct {
	Type        string             `yaml:"type" json:"type"`
	Properties  map[string]*Schema `yaml:"properties,omitempty" json:"properties,omitempty"`
	Required    []string           `yaml:"required,omitempty" json:"required,omitempty"`
	Items       *Schema            `yaml:"items,omitempty" json:"items,omitempty"`
	MinLength   *int               `yaml:"minLength,omitempty" json:"minLength,omitempty"`
	MaxLength   *int               `yaml:"maxLength,omitempty" json:"maxLength,omitempty"`
	Minimum     *float64           `yaml:"minimum,omitempty" json:"minimum,omitempty"`
	Maximum     *float64           `yaml:"maximum,omitempty" json:"maximum,omitempty"`
	Pattern     string             `yaml:"pattern,omitempty" json:"pattern,omitempty"`
	Enum        []interface{}      `yaml:"enum,omitempty" json:"enum,omitempty"`
	Description string             `yaml:"description,omitempty" json:"description,omitempty"`
}

// ValidationError contains details about a validation failure.
type ValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
	Value   string `json:"value,omitempty"`
}

func (e *ValidationError) Error() string {
	if e.Field != "" {
		return fmt.Sprintf("%s: %s", e.Field, e.Message)
	}
	return e.Message
}

// ValidationResult contains the outcome of validation.
type ValidationResult struct {
	Valid  bool               `json:"valid"`
	Errors []*ValidationError `json:"errors,omitempty"`
}

// Error returns a combined error message.
func (r *ValidationResult) Error() string {
	if r.Valid || len(r.Errors) == 0 {
		return ""
	}
	msgs := make([]string, len(r.Errors))
	for i, e := range r.Errors {
		msgs[i] = e.Error()
	}
	return strings.Join(msgs, "; ")
}

// Validator handles schema validation for tool arguments.
type Validator struct {
	schemas map[string]*Schema
}

// NewValidator creates a new Validator.
func NewValidator() *Validator {
	return &Validator{
		schemas: make(map[string]*Schema),
	}
}

// RegisterSchema registers a schema for a tool.
func (v *Validator) RegisterSchema(toolName string, schema *Schema) {
	v.schemas[toolName] = schema
}

// RegisterSchemaFromMap registers a schema from a map (e.g., from YAML).
func (v *Validator) RegisterSchemaFromMap(toolName string, schemaMap map[string]interface{}) error {
	schema, err := SchemaFromMap(schemaMap)
	if err != nil {
		return fmt.Errorf("failed to parse schema for tool '%s': %w", toolName, err)
	}
	v.schemas[toolName] = schema
	return nil
}

// HasSchema checks if a schema is registered for a tool.
func (v *Validator) HasSchema(toolName string) bool {
	_, exists := v.schemas[toolName]
	return exists
}

// Validate validates arguments against the registered schema for a tool.
func (v *Validator) Validate(toolName string, args map[string]interface{}) *ValidationResult {
	schema, exists := v.schemas[toolName]
	if !exists {
		// No schema registered - allow by default (but log warning in practice)
		return &ValidationResult{Valid: true}
	}

	return ValidateAgainstSchema(args, schema, "")
}

// ValidateAgainstSchema validates a value against a schema.
func ValidateAgainstSchema(value interface{}, schema *Schema, path string) *ValidationResult {
	result := &ValidationResult{Valid: true}

	if schema == nil {
		return result
	}

	// Type validation
	if schema.Type != "" {
		if err := validateType(value, schema.Type, path); err != nil {
			result.Valid = false
			result.Errors = append(result.Errors, err)
			return result
		}
	}

	// Object-specific validation
	if schema.Type == "object" {
		objResult := validateObject(value, schema, path)
		if !objResult.Valid {
			result.Valid = false
			result.Errors = append(result.Errors, objResult.Errors...)
		}
	}

	// Array-specific validation
	if schema.Type == "array" {
		arrResult := validateArray(value, schema, path)
		if !arrResult.Valid {
			result.Valid = false
			result.Errors = append(result.Errors, arrResult.Errors...)
		}
	}

	// String-specific validation
	if schema.Type == "string" {
		strResult := validateString(value, schema, path)
		if !strResult.Valid {
			result.Valid = false
			result.Errors = append(result.Errors, strResult.Errors...)
		}
	}

	// Number-specific validation
	if schema.Type == "number" || schema.Type == "integer" {
		numResult := validateNumber(value, schema, path)
		if !numResult.Valid {
			result.Valid = false
			result.Errors = append(result.Errors, numResult.Errors...)
		}
	}

	// Enum validation
	if len(schema.Enum) > 0 {
		if !isInEnum(value, schema.Enum) {
			result.Valid = false
			result.Errors = append(result.Errors, &ValidationError{
				Field:   path,
				Message: fmt.Sprintf("value must be one of: %v", schema.Enum),
				Value:   fmt.Sprintf("%v", value),
			})
		}
	}

	return result
}

func validateType(value interface{}, expectedType string, path string) *ValidationError {
	if value == nil {
		return &ValidationError{
			Field:   path,
			Message: fmt.Sprintf("expected %s, got null", expectedType),
		}
	}

	actualType := getJSONType(value)
	
	// Allow integer where number is expected
	if expectedType == "number" && actualType == "integer" {
		return nil
	}
	
	// Allow number where integer is expected (JSON unmarshals all numbers as float64)
	if expectedType == "integer" && actualType == "number" {
		// Check if it's actually a whole number
		if f, ok := value.(float64); ok && f == float64(int64(f)) {
			return nil
		}
	}

	if actualType != expectedType {
		return &ValidationError{
			Field:   path,
			Message: fmt.Sprintf("expected %s, got %s", expectedType, actualType),
			Value:   fmt.Sprintf("%v", value),
		}
	}

	return nil
}

func validateObject(value interface{}, schema *Schema, path string) *ValidationResult {
	result := &ValidationResult{Valid: true}

	obj, ok := value.(map[string]interface{})
	if !ok {
		return result // Type already validated
	}

	// Check required fields
	for _, field := range schema.Required {
		if _, exists := obj[field]; !exists {
			result.Valid = false
			result.Errors = append(result.Errors, &ValidationError{
				Field:   joinPath(path, field),
				Message: "required field is missing",
			})
		}
	}

	// Validate properties
	for propName, propSchema := range schema.Properties {
		if propValue, exists := obj[propName]; exists {
			propResult := ValidateAgainstSchema(propValue, propSchema, joinPath(path, propName))
			if !propResult.Valid {
				result.Valid = false
				result.Errors = append(result.Errors, propResult.Errors...)
			}
		}
	}

	return result
}

func validateArray(value interface{}, schema *Schema, path string) *ValidationResult {
	result := &ValidationResult{Valid: true}

	arr, ok := value.([]interface{})
	if !ok {
		return result // Type already validated
	}

	if schema.Items != nil {
		for i, item := range arr {
			itemPath := fmt.Sprintf("%s[%d]", path, i)
			itemResult := ValidateAgainstSchema(item, schema.Items, itemPath)
			if !itemResult.Valid {
				result.Valid = false
				result.Errors = append(result.Errors, itemResult.Errors...)
			}
		}
	}

	return result
}

func validateString(value interface{}, schema *Schema, path string) *ValidationResult {
	result := &ValidationResult{Valid: true}

	str, ok := value.(string)
	if !ok {
		return result // Type already validated
	}

	// MinLength
	if schema.MinLength != nil && len(str) < *schema.MinLength {
		result.Valid = false
		result.Errors = append(result.Errors, &ValidationError{
			Field:   path,
			Message: fmt.Sprintf("string length must be at least %d", *schema.MinLength),
			Value:   str,
		})
	}

	// MaxLength
	if schema.MaxLength != nil && len(str) > *schema.MaxLength {
		result.Valid = false
		result.Errors = append(result.Errors, &ValidationError{
			Field:   path,
			Message: fmt.Sprintf("string length must be at most %d", *schema.MaxLength),
			Value:   str,
		})
	}

	// Pattern
	if schema.Pattern != "" {
		matched, err := regexp.MatchString(schema.Pattern, str)
		if err != nil || !matched {
			result.Valid = false
			result.Errors = append(result.Errors, &ValidationError{
				Field:   path,
				Message: fmt.Sprintf("string must match pattern: %s", schema.Pattern),
				Value:   str,
			})
		}
	}

	return result
}

func validateNumber(value interface{}, schema *Schema, path string) *ValidationResult {
	result := &ValidationResult{Valid: true}

	var num float64
	switch v := value.(type) {
	case float64:
		num = v
	case int:
		num = float64(v)
	case int64:
		num = float64(v)
	default:
		return result // Type already validated
	}

	// Minimum
	if schema.Minimum != nil && num < *schema.Minimum {
		result.Valid = false
		result.Errors = append(result.Errors, &ValidationError{
			Field:   path,
			Message: fmt.Sprintf("value must be at least %v", *schema.Minimum),
			Value:   fmt.Sprintf("%v", num),
		})
	}

	// Maximum
	if schema.Maximum != nil && num > *schema.Maximum {
		result.Valid = false
		result.Errors = append(result.Errors, &ValidationError{
			Field:   path,
			Message: fmt.Sprintf("value must be at most %v", *schema.Maximum),
			Value:   fmt.Sprintf("%v", num),
		})
	}

	return result
}

func getJSONType(value interface{}) string {
	if value == nil {
		return "null"
	}

	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Bool:
		return "boolean"
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return "integer"
	case reflect.Float32, reflect.Float64:
		return "number"
	case reflect.String:
		return "string"
	case reflect.Slice, reflect.Array:
		return "array"
	case reflect.Map:
		return "object"
	default:
		return "unknown"
	}
}

func isInEnum(value interface{}, enum []interface{}) bool {
	for _, e := range enum {
		if reflect.DeepEqual(value, e) {
			return true
		}
	}
	return false
}

func joinPath(base, field string) string {
	if base == "" {
		return field
	}
	return base + "." + field
}

// SchemaFromMap converts a map to a Schema struct.
func SchemaFromMap(m map[string]interface{}) (*Schema, error) {
	data, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}

	var schema Schema
	if err := json.Unmarshal(data, &schema); err != nil {
		return nil, err
	}

	return &schema, nil
}

// DefaultToolSchema returns a basic schema for tools without explicit schemas.
func DefaultToolSchema() *Schema {
	return &Schema{
		Type:       "object",
		Properties: make(map[string]*Schema),
	}
}

