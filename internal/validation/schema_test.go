package validation

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateAgainstSchema_Object(t *testing.T) {
	schema := &Schema{
		Type:     "object",
		Required: []string{"name"},
		Properties: map[string]*Schema{
			"name": {Type: "string"},
			"age":  {Type: "integer"},
		},
	}

	// Valid object
	result := ValidateAgainstSchema(map[string]interface{}{
		"name": "John",
		"age":  30,
	}, schema, "")
	assert.True(t, result.Valid)

	// Missing required field
	result = ValidateAgainstSchema(map[string]interface{}{
		"age": 30,
	}, schema, "")
	assert.False(t, result.Valid)
	assert.Len(t, result.Errors, 1)
	assert.Contains(t, result.Errors[0].Message, "required")
}

func TestValidateAgainstSchema_String(t *testing.T) {
	minLen := 3
	maxLen := 10
	schema := &Schema{
		Type:      "string",
		MinLength: &minLen,
		MaxLength: &maxLen,
		Pattern:   "^[a-z]+$",
	}

	// Valid string
	result := ValidateAgainstSchema("hello", schema, "")
	assert.True(t, result.Valid)

	// Too short
	result = ValidateAgainstSchema("ab", schema, "")
	assert.False(t, result.Valid)
	assert.Contains(t, result.Error(), "at least 3")

	// Too long
	result = ValidateAgainstSchema("abcdefghijk", schema, "")
	assert.False(t, result.Valid)
	assert.Contains(t, result.Error(), "at most 10")

	// Wrong pattern
	result = ValidateAgainstSchema("Hello123", schema, "")
	assert.False(t, result.Valid)
	assert.Contains(t, result.Error(), "pattern")
}

func TestValidateAgainstSchema_Number(t *testing.T) {
	min := 0.0
	max := 100.0
	schema := &Schema{
		Type:    "number",
		Minimum: &min,
		Maximum: &max,
	}

	// Valid number
	result := ValidateAgainstSchema(50.5, schema, "")
	assert.True(t, result.Valid)

	// Below minimum
	result = ValidateAgainstSchema(-5.0, schema, "")
	assert.False(t, result.Valid)
	assert.Contains(t, result.Error(), "at least")

	// Above maximum
	result = ValidateAgainstSchema(150.0, schema, "")
	assert.False(t, result.Valid)
	assert.Contains(t, result.Error(), "at most")
}

func TestValidateAgainstSchema_Integer(t *testing.T) {
	min := 1.0
	max := 10.0
	schema := &Schema{
		Type:    "integer",
		Minimum: &min,
		Maximum: &max,
	}

	// Valid integer (passed as int)
	result := ValidateAgainstSchema(5, schema, "")
	assert.True(t, result.Valid)

	// Valid integer (passed as float64 - JSON default)
	result = ValidateAgainstSchema(float64(5), schema, "")
	assert.True(t, result.Valid)
}

func TestValidateAgainstSchema_Array(t *testing.T) {
	schema := &Schema{
		Type: "array",
		Items: &Schema{
			Type: "string",
		},
	}

	// Valid array
	result := ValidateAgainstSchema([]interface{}{"a", "b", "c"}, schema, "")
	assert.True(t, result.Valid)

	// Invalid item type
	result = ValidateAgainstSchema([]interface{}{"a", 123, "c"}, schema, "")
	assert.False(t, result.Valid)
	assert.Contains(t, result.Error(), "[1]")
}

func TestValidateAgainstSchema_Enum(t *testing.T) {
	schema := &Schema{
		Type: "string",
		Enum: []interface{}{"low", "medium", "high"},
	}

	// Valid enum value
	result := ValidateAgainstSchema("medium", schema, "")
	assert.True(t, result.Valid)

	// Invalid enum value
	result = ValidateAgainstSchema("critical", schema, "")
	assert.False(t, result.Valid)
	assert.Contains(t, result.Error(), "must be one of")
}

func TestValidateAgainstSchema_TypeMismatch(t *testing.T) {
	tests := []struct {
		expected string
		value    interface{}
	}{
		{"string", 123},
		{"number", "hello"},
		{"boolean", "true"},
		{"array", "not-array"},
		{"object", []string{"not", "object"}},
	}

	for _, tt := range tests {
		schema := &Schema{Type: tt.expected}
		result := ValidateAgainstSchema(tt.value, schema, "")
		assert.False(t, result.Valid, "expected %s, got %T", tt.expected, tt.value)
	}
}

func TestValidator_Register(t *testing.T) {
	v := NewValidator()

	schema := &Schema{
		Type:     "object",
		Required: []string{"project"},
		Properties: map[string]*Schema{
			"project": {Type: "string"},
		},
	}

	v.RegisterSchema("get_status", schema)
	assert.True(t, v.HasSchema("get_status"))
	assert.False(t, v.HasSchema("unknown_tool"))
}

func TestValidator_Validate(t *testing.T) {
	v := NewValidator()

	schema := &Schema{
		Type:     "object",
		Required: []string{"project"},
		Properties: map[string]*Schema{
			"project": {Type: "string"},
		},
	}
	v.RegisterSchema("get_status", schema)

	// Valid args
	result := v.Validate("get_status", map[string]interface{}{
		"project": "demo",
	})
	assert.True(t, result.Valid)

	// Missing required field
	result = v.Validate("get_status", map[string]interface{}{})
	assert.False(t, result.Valid)
}

func TestValidator_NoSchema(t *testing.T) {
	v := NewValidator()

	// Tools without schemas should pass validation
	result := v.Validate("unknown_tool", map[string]interface{}{
		"anything": "goes",
	})
	assert.True(t, result.Valid)
}

func TestSchemaFromMap(t *testing.T) {
	m := map[string]interface{}{
		"type":     "object",
		"required": []interface{}{"name"},
		"properties": map[string]interface{}{
			"name": map[string]interface{}{
				"type":      "string",
				"minLength": 1,
			},
		},
	}

	schema, err := SchemaFromMap(m)
	require.NoError(t, err)
	assert.Equal(t, "object", schema.Type)
	assert.Contains(t, schema.Required, "name")
	assert.NotNil(t, schema.Properties["name"])
}

func TestGetJSONType(t *testing.T) {
	tests := []struct {
		value    interface{}
		expected string
	}{
		{nil, "null"},
		{true, "boolean"},
		{false, "boolean"},
		{42, "integer"},
		{int64(42), "integer"},
		{3.14, "number"},
		{"hello", "string"},
		{[]interface{}{}, "array"},
		{map[string]interface{}{}, "object"},
	}

	for _, tt := range tests {
		assert.Equal(t, tt.expected, getJSONType(tt.value), "value: %v", tt.value)
	}
}

func TestValidationResult_Error(t *testing.T) {
	result := &ValidationResult{
		Valid: false,
		Errors: []*ValidationError{
			{Field: "name", Message: "required field is missing"},
			{Field: "age", Message: "must be positive"},
		},
	}

	errStr := result.Error()
	assert.Contains(t, errStr, "name")
	assert.Contains(t, errStr, "required")
	assert.Contains(t, errStr, "age")
	assert.Contains(t, errStr, "positive")
}

func TestNestedObjectValidation(t *testing.T) {
	schema := &Schema{
		Type: "object",
		Properties: map[string]*Schema{
			"user": {
				Type:     "object",
				Required: []string{"email"},
				Properties: map[string]*Schema{
					"email": {Type: "string"},
					"name":  {Type: "string"},
				},
			},
		},
	}

	// Valid nested object
	result := ValidateAgainstSchema(map[string]interface{}{
		"user": map[string]interface{}{
			"email": "test@example.com",
			"name":  "Test User",
		},
	}, schema, "")
	assert.True(t, result.Valid)

	// Missing nested required field
	result = ValidateAgainstSchema(map[string]interface{}{
		"user": map[string]interface{}{
			"name": "Test User",
		},
	}, schema, "")
	assert.False(t, result.Valid)
	assert.Contains(t, result.Error(), "user.email")
}
