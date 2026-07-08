package hax

import "strings"

// FieldType represents the output type of a form field.
type FieldType int

const (
	FieldTypeString FieldType = iota
	FieldTypeFloat
	FieldTypeBool
	FieldTypeStringList
	FieldTypeInt
)

// FormBuilder is a fluent builder for form payloads with runtime type inference.
type FormBuilder struct {
	fields []map[string]any
	config map[string]any
	types  map[string]FieldType
}

// NewFormBuilder creates an empty FormBuilder.
func NewFormBuilder() *FormBuilder {
	return &FormBuilder{
		fields: []map[string]any{},
		config: map[string]any{},
		types:  map[string]FieldType{},
	}
}

// --- Form Configuration ---

// Title sets the form title displayed at the top.
func (f *FormBuilder) Title(title string) *FormBuilder {
	f.config["title"] = title
	return f
}

// Description sets the form description displayed below the title.
func (f *FormBuilder) Description(description string) *FormBuilder {
	f.config["description"] = description
	return f
}

// SubmitLabel sets the submit button label.
func (f *FormBuilder) SubmitLabel(label string) *FormBuilder {
	f.config["submitLabel"] = label
	return f
}

// Layout sets the form layout.
func (f *FormBuilder) Layout(layout map[string]any) *FormBuilder {
	f.config["layout"] = layout
	return f
}

// --- Field Methods ---

// Input adds a text input field. Output type: string.
func (f *FormBuilder) Input(id string, options map[string]any) *FormBuilder {
	field := map[string]any{"type": "input", "id": id}
	mergeOptions(field, options)
	f.fields = append(f.fields, field)
	f.types[id] = FieldTypeString
	return f
}

// Number adds a number input field. Output type: float64.
func (f *FormBuilder) Number(id string, options map[string]any) *FormBuilder {
	field := map[string]any{"type": "number", "id": id}
	mergeOptions(field, options)
	f.fields = append(f.fields, field)
	f.types[id] = FieldTypeFloat
	return f
}

// Textarea adds a multi-line text input field. Output type: string.
func (f *FormBuilder) Textarea(id string, options map[string]any) *FormBuilder {
	field := map[string]any{"type": "textarea", "id": id}
	mergeOptions(field, options)
	f.fields = append(f.fields, field)
	f.types[id] = FieldTypeString
	return f
}

// Select adds a dropdown select field. Output type: string.
func (f *FormBuilder) Select(id string, options map[string]any) *FormBuilder {
	field := map[string]any{"type": "select", "id": id}
	mergeOptions(field, options)
	f.fields = append(f.fields, field)
	f.types[id] = FieldTypeString
	return f
}

// RadioGroup adds a radio button group field. Output type: string.
func (f *FormBuilder) RadioGroup(id string, options map[string]any) *FormBuilder {
	field := map[string]any{"type": "radio-group", "id": id}
	mergeOptions(field, options)
	f.fields = append(f.fields, field)
	f.types[id] = FieldTypeString
	return f
}

// Checkbox adds a single checkbox field. Output type: bool.
func (f *FormBuilder) Checkbox(id string, options map[string]any) *FormBuilder {
	field := map[string]any{"type": "checkbox", "id": id}
	mergeOptions(field, options)
	f.fields = append(f.fields, field)
	f.types[id] = FieldTypeBool
	return f
}

// CheckboxGroup adds a multi-select checkbox group field. Output type: []string.
func (f *FormBuilder) CheckboxGroup(id string, options map[string]any) *FormBuilder {
	field := map[string]any{"type": "checkbox-group", "id": id}
	mergeOptions(field, options)
	f.fields = append(f.fields, field)
	f.types[id] = FieldTypeStringList
	return f
}

// Switch adds a toggle switch field. Output type: bool.
func (f *FormBuilder) Switch(id string, options map[string]any) *FormBuilder {
	field := map[string]any{"type": "switch", "id": id}
	mergeOptions(field, options)
	f.fields = append(f.fields, field)
	f.types[id] = FieldTypeBool
	return f
}

// Slider adds a slider field. Output type: float64.
func (f *FormBuilder) Slider(id string, options map[string]any) *FormBuilder {
	field := map[string]any{"type": "slider", "id": id}
	mergeOptions(field, options)
	f.fields = append(f.fields, field)
	f.types[id] = FieldTypeFloat
	return f
}

// Date adds a date picker field. Output type: string (ISO date format).
func (f *FormBuilder) Date(id string, options map[string]any) *FormBuilder {
	field := map[string]any{"type": "date", "id": id}
	mergeOptions(field, options)
	f.fields = append(f.fields, field)
	f.types[id] = FieldTypeString
	return f
}

// Hidden adds a hidden field with a preset value.
// The output type is inferred from the value type.
func (f *FormBuilder) Hidden(id string, value any) *FormBuilder {
	field := map[string]any{"type": "hidden", "id": id, "value": value}
	f.fields = append(f.fields, field)
	f.types[id] = inferHiddenType(value)
	return f
}

// --- Output Methods ---

// ToPayload converts the builder to a FormBuilderPayload map for the API.
func (f *FormBuilder) ToPayload() map[string]any {
	result := map[string]any{"fields": f.fields}
	for k, v := range f.config {
		result[k] = v
	}
	return result
}

// FieldTypes returns the type map for all fields.
func (f *FormBuilder) FieldTypes() map[string]FieldType {
	types := make(map[string]FieldType, len(f.types))
	for k, v := range f.types {
		types[k] = v
	}
	return types
}

// ParseResponse parses a raw API response into typed FormValues.
func (f *FormBuilder) ParseResponse(response map[string]any) *FormValues {
	values := map[string]any{}
	if response != nil {
		if v, ok := response["values"].(map[string]any); ok {
			values = v
		}
	}

	result := &FormValues{
		values: make(map[string]any, len(f.types)),
		types:  f.FieldTypes(),
	}
	for id := range f.types {
		if v, ok := values[id]; ok {
			result.values[id] = v
		}
	}
	return result
}

// FormValues holds typed form response values.
type FormValues struct {
	values map[string]any
	types  map[string]FieldType
}

// Get returns the raw value for a field ID.
func (v *FormValues) Get(id string) any {
	if v == nil {
		return nil
	}
	return v.values[id]
}

// GetString returns the string value for a field ID.
func (v *FormValues) GetString(id string) string {
	if v == nil {
		return ""
	}
	if s, ok := v.values[id].(string); ok {
		return s
	}
	return ""
}

// GetFloat returns the float64 value for a field ID.
func (v *FormValues) GetFloat(id string) float64 {
	if v == nil {
		return 0
	}
	switch n := v.values[id].(type) {
	case float64:
		return n
	case float32:
		return float64(n)
	case int:
		return float64(n)
	case int64:
		return float64(n)
	}
	return 0
}

// GetBool returns the bool value for a field ID.
func (v *FormValues) GetBool(id string) bool {
	if v == nil {
		return false
	}
	if b, ok := v.values[id].(bool); ok {
		return b
	}
	return false
}

// GetStringSlice returns the []string value for a field ID.
func (v *FormValues) GetStringSlice(id string) []string {
	if v == nil {
		return nil
	}
	if slice, ok := v.values[id].([]any); ok {
		result := make([]string, 0, len(slice))
		for _, item := range slice {
			if s, ok := item.(string); ok {
				result = append(result, s)
			}
		}
		return result
	}
	return nil
}

// GetInt returns the int value for a field ID.
func (v *FormValues) GetInt(id string) int {
	if v == nil {
		return 0
	}
	switch n := v.values[id].(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	}
	return 0
}

// --- Internal utilities ---

// snakeToCamel converts snake_case to camelCase.
func snakeToCamel(name string) string {
	components := strings.Split(name, "_")
	if len(components) == 1 {
		return name
	}
	result := components[0]
	for _, comp := range components[1:] {
		if len(comp) > 0 {
			result += strings.ToUpper(comp[:1]) + comp[1:]
		}
	}
	return result
}

// mergeOptions converts snake_case option keys to camelCase and merges into field.
func mergeOptions(field, options map[string]any) {
	for k, v := range options {
		field[snakeToCamel(k)] = v
	}
}

func inferHiddenType(value any) FieldType {
	switch value.(type) {
	case int, int64:
		return FieldTypeInt
	case float64, float32:
		return FieldTypeFloat
	case bool:
		return FieldTypeBool
	default:
		return FieldTypeString
	}
}
