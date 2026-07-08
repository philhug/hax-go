package hax

import "testing"

func TestFormBuilderEmpty(t *testing.T) {
	form := NewFormBuilder()
	if form == nil {
		t.Fatal("form builder should not be nil")
	}
}

func TestFormBuilderEmptyPayload(t *testing.T) {
	form := NewFormBuilder()
	payload := form.ToPayload()
	fields, ok := payload["fields"].([]map[string]any)
	if !ok {
		t.Fatalf("expected fields to be []map[string]any, got %T", payload["fields"])
	}
	if len(fields) != 0 {
		t.Fatalf("expected empty fields, got %d", len(fields))
	}
}

func TestFormBuilderSetTitle(t *testing.T) {
	form := NewFormBuilder().Title("Test Form")
	payload := form.ToPayload()
	if payload["title"] != "Test Form" {
		t.Fatalf("expected title 'Test Form', got %v", payload["title"])
	}
}

func TestFormBuilderSetDescription(t *testing.T) {
	form := NewFormBuilder().Description("A test form")
	payload := form.ToPayload()
	if payload["description"] != "A test form" {
		t.Fatalf("expected description, got %v", payload["description"])
	}
}

func TestFormBuilderSetSubmitLabel(t *testing.T) {
	form := NewFormBuilder().SubmitLabel("Submit Now")
	payload := form.ToPayload()
	if payload["submitLabel"] != "Submit Now" {
		t.Fatalf("expected submitLabel, got %v", payload["submitLabel"])
	}
}

func TestFormBuilderSetLayout(t *testing.T) {
	layout := map[string]any{"type": "grid", "columns": float64(2)}
	form := NewFormBuilder().Layout(layout)
	payload := form.ToPayload()
	if payload["layout"] == nil {
		t.Fatal("expected layout to be set")
	}
}

func TestFormBuilderChainAllConfig(t *testing.T) {
	form := NewFormBuilder().
		Title("My Form").
		Description("Description").
		SubmitLabel("Go").
		Layout(map[string]any{"type": "grid", "columns": float64(3)})

	payload := form.ToPayload()
	if payload["title"] != "My Form" {
		t.Fatalf("expected title, got %v", payload["title"])
	}
	if payload["description"] != "Description" {
		t.Fatalf("expected description, got %v", payload["description"])
	}
	if payload["submitLabel"] != "Go" {
		t.Fatalf("expected submitLabel, got %v", payload["submitLabel"])
	}
}

func TestFormBuilderInputField(t *testing.T) {
	form := NewFormBuilder().Input("email", nil)
	payload := form.ToPayload()
	fields := payload["fields"].([]map[string]any)
	if len(fields) != 1 {
		t.Fatalf("expected 1 field, got %d", len(fields))
	}
	if fields[0]["type"] != "input" {
		t.Fatalf("expected type input, got %v", fields[0]["type"])
	}
	if fields[0]["id"] != "email" {
		t.Fatalf("expected id email, got %v", fields[0]["id"])
	}
}

func TestFormBuilderInputWithOptions(t *testing.T) {
	form := NewFormBuilder().Input("email", map[string]any{
		"label":       "Email Address",
		"variant":     "email",
		"required":    true,
		"placeholder": "you@example.com",
	})
	payload := form.ToPayload()
	fields := payload["fields"].([]map[string]any)
	field := fields[0]
	if field["label"] != "Email Address" {
		t.Fatalf("expected label, got %v", field["label"])
	}
	if field["variant"] != "email" {
		t.Fatalf("expected variant, got %v", field["variant"])
	}
	if field["required"] != true {
		t.Fatalf("expected required, got %v", field["required"])
	}
	if field["placeholder"] != "you@example.com" {
		t.Fatalf("expected placeholder, got %v", field["placeholder"])
	}
}

func TestFormBuilderNumberField(t *testing.T) {
	form := NewFormBuilder().Number("age", nil)
	payload := form.ToPayload()
	fields := payload["fields"].([]map[string]any)
	if fields[0]["type"] != "number" {
		t.Fatalf("expected type number, got %v", fields[0]["type"])
	}
}

func TestFormBuilderNumberWithOptions(t *testing.T) {
	form := NewFormBuilder().Number("age", map[string]any{
		"label": "Your Age",
		"min":   0,
		"max":   120,
		"step":  1,
	})
	payload := form.ToPayload()
	field := payload["fields"].([]map[string]any)[0]
	if field["min"] != 0 {
		t.Fatalf("expected min 0, got %v", field["min"])
	}
	if field["max"] != 120 {
		t.Fatalf("expected max 120, got %v", field["max"])
	}
	if field["step"] != 1 {
		t.Fatalf("expected step 1, got %v", field["step"])
	}
}

func TestFormBuilderTextareaField(t *testing.T) {
	form := NewFormBuilder().Textarea("bio", nil)
	payload := form.ToPayload()
	field := payload["fields"].([]map[string]any)[0]
	if field["type"] != "textarea" {
		t.Fatalf("expected type textarea, got %v", field["type"])
	}
}

func TestFormBuilderTextareaWithOptions(t *testing.T) {
	form := NewFormBuilder().Textarea("bio", map[string]any{
		"rows":       5,
		"max_length": 500,
	})
	payload := form.ToPayload()
	field := payload["fields"].([]map[string]any)[0]
	if field["rows"] != 5 {
		t.Fatalf("expected rows 5, got %v", field["rows"])
	}
	if field["maxLength"] != 500 {
		t.Fatalf("expected maxLength 500, got %v", field["maxLength"])
	}
}

func TestFormBuilderSelectField(t *testing.T) {
	options := []any{
		map[string]any{"value": "us", "label": "United States"},
		map[string]any{"value": "ca", "label": "Canada"},
	}
	form := NewFormBuilder().Select("country", map[string]any{"options": options})
	payload := form.ToPayload()
	field := payload["fields"].([]map[string]any)[0]
	if field["type"] != "select" {
		t.Fatalf("expected type select, got %v", field["type"])
	}
	if field["id"] != "country" {
		t.Fatalf("expected id country, got %v", field["id"])
	}
}

func TestFormBuilderRadioGroupField(t *testing.T) {
	options := []any{
		map[string]any{"value": "free", "label": "Free"},
		map[string]any{"value": "pro", "label": "Pro"},
	}
	form := NewFormBuilder().RadioGroup("plan", map[string]any{"options": options})
	payload := form.ToPayload()
	field := payload["fields"].([]map[string]any)[0]
	if field["type"] != "radio-group" {
		t.Fatalf("expected type radio-group, got %v", field["type"])
	}
}

func TestFormBuilderRadioGroupWithOrientation(t *testing.T) {
	form := NewFormBuilder().RadioGroup("size", map[string]any{
		"options":     []any{map[string]any{"value": "s", "label": "Small"}},
		"orientation": "horizontal",
	})
	payload := form.ToPayload()
	field := payload["fields"].([]map[string]any)[0]
	if field["orientation"] != "horizontal" {
		t.Fatalf("expected orientation horizontal, got %v", field["orientation"])
	}
}

func TestFormBuilderCheckboxField(t *testing.T) {
	form := NewFormBuilder().Checkbox("newsletter", map[string]any{"checkbox_label": "Subscribe"})
	payload := form.ToPayload()
	field := payload["fields"].([]map[string]any)[0]
	if field["type"] != "checkbox" {
		t.Fatalf("expected type checkbox, got %v", field["type"])
	}
	if field["checkboxLabel"] != "Subscribe" {
		t.Fatalf("expected checkboxLabel, got %v", field["checkboxLabel"])
	}
}

func TestFormBuilderCheckboxGroupField(t *testing.T) {
	options := []any{
		map[string]any{"value": "tech", "label": "Technology"},
		map[string]any{"value": "sports", "label": "Sports"},
	}
	form := NewFormBuilder().CheckboxGroup("interests", map[string]any{"options": options})
	payload := form.ToPayload()
	field := payload["fields"].([]map[string]any)[0]
	if field["type"] != "checkbox-group" {
		t.Fatalf("expected type checkbox-group, got %v", field["type"])
	}
}

func TestFormBuilderSwitchField(t *testing.T) {
	form := NewFormBuilder().Switch("darkMode", map[string]any{"switch_label": "Enable dark mode"})
	payload := form.ToPayload()
	field := payload["fields"].([]map[string]any)[0]
	if field["type"] != "switch" {
		t.Fatalf("expected type switch, got %v", field["type"])
	}
	if field["switchLabel"] != "Enable dark mode" {
		t.Fatalf("expected switchLabel, got %v", field["switchLabel"])
	}
}

func TestFormBuilderSliderField(t *testing.T) {
	form := NewFormBuilder().Slider("volume", map[string]any{"min": 0, "max": 100, "step": 5})
	payload := form.ToPayload()
	field := payload["fields"].([]map[string]any)[0]
	if field["type"] != "slider" {
		t.Fatalf("expected type slider, got %v", field["type"])
	}
	if field["min"] != 0 {
		t.Fatalf("expected min 0, got %v", field["min"])
	}
	if field["max"] != 100 {
		t.Fatalf("expected max 100, got %v", field["max"])
	}
	if field["step"] != 5 {
		t.Fatalf("expected step 5, got %v", field["step"])
	}
}

func TestFormBuilderDateField(t *testing.T) {
	form := NewFormBuilder().Date("birthdate", nil)
	payload := form.ToPayload()
	field := payload["fields"].([]map[string]any)[0]
	if field["type"] != "date" {
		t.Fatalf("expected type date, got %v", field["type"])
	}
}

func TestFormBuilderDateWithOptions(t *testing.T) {
	form := NewFormBuilder().Date("eventDate", map[string]any{"min": "2024-01-01", "max": "2024-12-31"})
	payload := form.ToPayload()
	field := payload["fields"].([]map[string]any)[0]
	if field["min"] != "2024-01-01" {
		t.Fatalf("expected min, got %v", field["min"])
	}
	if field["max"] != "2024-12-31" {
		t.Fatalf("expected max, got %v", field["max"])
	}
}

func TestFormBuilderHiddenStringField(t *testing.T) {
	form := NewFormBuilder().Hidden("userId", "abc123")
	payload := form.ToPayload()
	field := payload["fields"].([]map[string]any)[0]
	if field["type"] != "hidden" {
		t.Fatalf("expected type hidden, got %v", field["type"])
	}
	if field["value"] != "abc123" {
		t.Fatalf("expected value abc123, got %v", field["value"])
	}
}

func TestFormBuilderHiddenNumberField(t *testing.T) {
	form := NewFormBuilder().Hidden("version", 42)
	payload := form.ToPayload()
	field := payload["fields"].([]map[string]any)[0]
	if field["value"] != 42 {
		t.Fatalf("expected value 42, got %v", field["value"])
	}
}

func TestFormBuilderHiddenBooleanField(t *testing.T) {
	form := NewFormBuilder().Hidden("isAdmin", true)
	payload := form.ToPayload()
	field := payload["fields"].([]map[string]any)[0]
	if field["value"] != true {
		t.Fatalf("expected value true, got %v", field["value"])
	}
}

func TestFormBuilderChainMultipleFields(t *testing.T) {
	form := NewFormBuilder().
		Title("Registration Form").
		Input("name", map[string]any{"label": "Name"}).
		Input("email", map[string]any{"variant": "email"}).
		Number("age", nil).
		Checkbox("terms", map[string]any{"checkbox_label": "I agree"})

	payload := form.ToPayload()
	fields := payload["fields"].([]map[string]any)
	if len(fields) != 4 {
		t.Fatalf("expected 4 fields, got %d", len(fields))
	}
	ids := []string{"name", "email", "age", "terms"}
	for i, id := range ids {
		if fields[i]["id"] != id {
			t.Fatalf("expected field %d id %s, got %v", i, id, fields[i]["id"])
		}
	}
}

func TestFormBuilderTypeInference(t *testing.T) {
	form := NewFormBuilder().
		Input("email", nil).
		Number("age", nil).
		Checkbox("newsletter", map[string]any{"checkbox_label": "Subscribe"}).
		Select("country", map[string]any{"options": []any{}}).
		Switch("enabled", map[string]any{"switch_label": "Enable"}).
		CheckboxGroup("tags", map[string]any{"options": []any{map[string]any{"value": "a", "label": "A"}}}).
		Hidden("version", 42).
		Hidden("source", "web").
		Hidden("active", true)

	types := form.FieldTypes()
	if types["email"] != FieldTypeString {
		t.Fatalf("expected email to be String")
	}
	if types["age"] != FieldTypeFloat {
		t.Fatalf("expected age to be Float")
	}
	if types["newsletter"] != FieldTypeBool {
		t.Fatalf("expected newsletter to be Bool")
	}
	if types["country"] != FieldTypeString {
		t.Fatalf("expected country to be String")
	}
	if types["enabled"] != FieldTypeBool {
		t.Fatalf("expected enabled to be Bool")
	}
	if types["tags"] != FieldTypeStringList {
		t.Fatalf("expected tags to be StringList")
	}
	if types["version"] != FieldTypeInt {
		t.Fatalf("expected version to be Int")
	}
	if types["source"] != FieldTypeString {
		t.Fatalf("expected source to be String")
	}
	if types["active"] != FieldTypeBool {
		t.Fatalf("expected active to be Bool")
	}
}

func TestFormBuilderParseResponseValues(t *testing.T) {
	form := NewFormBuilder().Input("email", nil).Number("age", nil)

	response := map[string]any{
		"values": map[string]any{
			"email": "test@example.com",
			"age":   float64(25),
		},
		"meta": map[string]any{"submittedAt": "2024-01-01T00:00:00Z"},
	}

	parsed := form.ParseResponse(response)
	if parsed.GetString("email") != "test@example.com" {
		t.Fatalf("expected email test@example.com, got %s", parsed.GetString("email"))
	}
	if parsed.GetFloat("age") != 25 {
		t.Fatalf("expected age 25, got %f", parsed.GetFloat("age"))
	}
}

func TestFormBuilderParseNullResponse(t *testing.T) {
	form := NewFormBuilder().Input("name", nil)
	parsed := form.ParseResponse(nil)
	if parsed.GetString("name") != "" {
		t.Fatalf("expected empty string for nil response, got %s", parsed.GetString("name"))
	}
}

func TestFormBuilderParseEmptyResponse(t *testing.T) {
	form := NewFormBuilder().Input("name", nil)
	parsed := form.ParseResponse(map[string]any{})
	if parsed.GetString("name") != "" {
		t.Fatalf("expected empty string for empty response, got %s", parsed.GetString("name"))
	}
}

func TestFormBuilderParseComplexResponse(t *testing.T) {
	form := NewFormBuilder().
		Input("firstName", nil).
		Input("lastName", nil).
		Input("email", nil).
		Number("age", nil).
		Select("ticketType", map[string]any{"options": []any{}}).
		Checkbox("newsletter", map[string]any{"checkbox_label": "Subscribe"})

	response := map[string]any{
		"values": map[string]any{
			"firstName":  "John",
			"lastName":    "Doe",
			"email":       "john@example.com",
			"age":         float64(30),
			"ticketType":  "vip",
			"newsletter":  true,
		},
	}

	parsed := form.ParseResponse(response)
	if parsed.GetString("firstName") != "John" {
		t.Fatalf("expected firstName John, got %s", parsed.GetString("firstName"))
	}
	if parsed.GetString("lastName") != "Doe" {
		t.Fatalf("expected lastName Doe, got %s", parsed.GetString("lastName"))
	}
	if parsed.GetString("email") != "john@example.com" {
		t.Fatalf("expected email, got %s", parsed.GetString("email"))
	}
	if parsed.GetFloat("age") != 30 {
		t.Fatalf("expected age 30, got %f", parsed.GetFloat("age"))
	}
	if parsed.GetString("ticketType") != "vip" {
		t.Fatalf("expected ticketType vip, got %s", parsed.GetString("ticketType"))
	}
	if !parsed.GetBool("newsletter") {
		t.Fatal("expected newsletter true")
	}
}

func TestFormBuilderConditionalRendering(t *testing.T) {
	form := NewFormBuilder().
		Checkbox("hasPhone", map[string]any{"checkbox_label": "I have a phone"}).
		Input("phone", map[string]any{
			"label":       "Phone Number",
			"conditional": map[string]any{"when": "hasPhone", "is": true},
		})
	payload := form.ToPayload()
	fields := payload["fields"].([]map[string]any)
	cond := fields[1]["conditional"].(map[string]any)
	if cond["when"] != "hasPhone" {
		t.Fatalf("expected when hasPhone, got %v", cond["when"])
	}
	if cond["is"] != true {
		t.Fatalf("expected is true, got %v", cond["is"])
	}
}

func TestFormBuilderValidationRules(t *testing.T) {
	form := NewFormBuilder().Input("email", map[string]any{
		"validation": []any{
			map[string]any{"type": "required", "message": "Email is required"},
			map[string]any{"type": "email", "message": "Invalid email format"},
		},
	})
	payload := form.ToPayload()
	field := payload["fields"].([]map[string]any)[0]
	validation := field["validation"].([]any)
	if len(validation) != 2 {
		t.Fatalf("expected 2 validation rules, got %d", len(validation))
	}
}

func TestFormBuilderDisabledField(t *testing.T) {
	form := NewFormBuilder().Input("readOnly", map[string]any{
		"disabled":      true,
		"default_value": "Cannot change",
	})
	payload := form.ToPayload()
	field := payload["fields"].([]map[string]any)[0]
	if field["disabled"] != true {
		t.Fatalf("expected disabled true, got %v", field["disabled"])
	}
	if field["defaultValue"] != "Cannot change" {
		t.Fatalf("expected defaultValue, got %v", field["defaultValue"])
	}
}
