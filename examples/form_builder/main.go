package main

import (
	"fmt"
	"os"

	hax "github.com/philhug/hax-go"
)

func main() {
	apiKey := os.Getenv("HAX_API_KEY")
	if apiKey == "" {
		fmt.Fprintln(os.Stderr, "Error: HAX_API_KEY environment variable is required")
		os.Exit(1)
	}

	client, err := hax.NewClient(hax.ClientOptions{
		APIKey:  apiKey,
		BaseURL: hax.DefaultBaseURL,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
	defer client.Close()

	form := hax.NewFormBuilder().
		Title("Event Registration").
		Description("Please fill out the form below to register.").
		SubmitLabel("Register Now").
		Input("name", map[string]any{"label": "Full Name", "required": true}).
		Input("email", map[string]any{"label": "Email", "variant": "email", "required": true}).
		Number("age", map[string]any{"label": "Age", "min": 0, "max": 120}).
		Select("ticketType", map[string]any{
			"label": "Ticket Type",
			"options": []any{
				map[string]any{"value": "general", "label": "General Admission"},
				map[string]any{"value": "vip", "label": "VIP"},
			},
		}).
		Checkbox("newsletter", map[string]any{"checkbox_label": "Subscribe to updates"}).
		Hidden("eventId", "evt_12345")

	webhookURL := "https://myapp.com/webhook"
	handle, err := client.CreateFormRequest(form, hax.CreateRequestParams{
		WebhookURL: &webhookURL,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}

	fmt.Printf("Form URL: %s\n", handle.URL())
	fmt.Println("Waiting for response (timeout: 5 minutes)...")

	response, err := handle.WaitForResponse(2.0, 300)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}

	fmt.Println("\nResponse received!")
	fmt.Printf("  Name:       %s\n", response.Values.GetString("name"))
	fmt.Printf("  Email:      %s\n", response.Values.GetString("email"))
	fmt.Printf("  Age:        %.0f\n", response.Values.GetFloat("age"))
	fmt.Printf("  Ticket:     %s\n", response.Values.GetString("ticketType"))
	fmt.Printf("  Newsletter: %v\n", response.Values.GetBool("newsletter"))
	fmt.Printf("  Event ID:   %s\n", response.Values.GetString("eventId"))
}
