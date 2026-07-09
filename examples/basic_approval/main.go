package main

import (
	"fmt"
	"os"

	hax "github.com/philhug/hax-go"
)

func main() {
	apiKey := os.Getenv("HAX_API_KEY")
	baseURL := os.Getenv("HAX_BASE_URL")
	if baseURL == "" {
		baseURL = hax.DefaultBaseURL
	}

	if apiKey == "" {
		fmt.Fprintln(os.Stderr, "Error: HAX_API_KEY environment variable is required")
		os.Exit(1)
	}

	client, err := hax.NewClient(hax.ClientOptions{
		APIKey:  apiKey,
		BaseURL: baseURL,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
	defer client.Close()

	request, err := client.CreateRequest(hax.CreateRequestParams{
		Type:        "text-approval-v1",
		Title:       hax.StringPtr("Action Approval Required"),
		Description: hax.StringPtr("Please review and approve or deny this action."),
		Payload: map[string]any{
			"text":         "Do you approve this action?",
			"approveLabel": "Approve",
			"denyLabel":    "Deny",
		},
		ExpiresInSeconds: hax.IntPtr(3600),
		Metadata:         map[string]any{"source": "basic_approval_example"},
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}

	fmt.Println("Request created:", request.ID)
	fmt.Println("Status:", request.Status)
	fmt.Println("\nShare this URL with the approver:")
	fmt.Println(" ", request.URL)
	fmt.Println("\nWaiting for response (timeout: 5 minutes)...")

	completed, err := client.WaitForResponse(request.ID, 2.0, 300)
	if err != nil {
		fmt.Fprintln(os.Stderr, "\nTimed out waiting for response:", err)
		client.CancelRequest(request.ID)
		fmt.Println("Request cancelled.")
		return
	}

	if completed.IsCompleted() {
		response := completed.Response
		decision := ""
		if response != nil {
			if d, ok := response["decision"].(string); ok {
				decision = d
			}
		}
		fmt.Println("\nResponse received!")
		fmt.Println("  Decision:", decision)
		if decision == "approve" {
			fmt.Println("\n✓ Action APPROVED - proceeding...")
		} else {
			fmt.Println("\n✗ Action DENIED.")
		}
	} else if completed.IsExpired() {
		fmt.Println("\n⚠ Request expired.")
	} else if completed.IsCancelled() {
		fmt.Println("\n⚠ Request was cancelled.")
	}
}
