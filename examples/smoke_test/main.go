package main

import (
	"fmt"
	"os"
	"time"

	hax "github.com/philhug/hax-go"
)

func main() {
	baseURL := "http://localhost:9090/api/v1"
	apiKey := "demo-key"

	// 1. API key client
	fmt.Println("=== API Key client ===")
	client, err := hax.NewClient(hax.ClientOptions{
		BaseURL: baseURL,
		APIKey:  apiKey,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "NewClient:", err)
		os.Exit(1)
	}
	defer client.Close()

	created, err := client.CreateRequest(hax.CreateRequestParams{
		Type:    "text-approval-v1",
		Title:   hax.StringPtr("Deploy to prod?"),
		Payload: map[string]any{"text": "Ship v1.2.3 to production?", "approveLabel": "Ship it", "denyLabel": "Hold"},
		Metadata: map[string]any{"source": "smoke-test"},
		ExpiresInSeconds: hax.IntPtr(3600),
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "CreateRequest:", err)
		os.Exit(1)
	}
	fmt.Println("  Created:", created.ID)
	fmt.Println("  Status: ", created.Status)
	fmt.Println("  URL:    ", created.URL)

	// Get it back
	req, err := client.GetRequest(created.ID)
	if err != nil {
		fmt.Fprintln(os.Stderr, "GetRequest:", err)
		os.Exit(1)
	}
	fmt.Println("  Got:    ", req.ID, "status=", req.Status)

	// List types
	types, err := client.ListTypes()
	if err != nil {
		fmt.Fprintln(os.Stderr, "ListTypes:", err)
		os.Exit(1)
	}
	fmt.Printf("  Types:  %d templates\n", len(types))

	// List requests
	list, err := client.ListRequests()
	if err != nil {
		fmt.Fprintln(os.Stderr, "ListRequests:", err)
		os.Exit(1)
	}
	fmt.Printf("  List:   %d requests\n", len(list))

	// Submit a response
	_, err = client.SubmitResponse(created.ID, map[string]any{"decision": "approve"})
	if err != nil {
		fmt.Fprintln(os.Stderr, "SubmitResponse:", err)
		os.Exit(1)
	}
	fmt.Println("  Response submitted: approve")

	// Verify completed
	req, err = client.GetRequest(created.ID)
	if err != nil {
		fmt.Fprintln(os.Stderr, "GetRequest:", err)
		os.Exit(1)
	}
	fmt.Println("  Final:  status=", req.Status, "decision=", req.Response["decision"])

	// 2. DID-only client (knock)
	fmt.Println("\n=== DID (knock) client ===")
	didClient, err := hax.NewClient(hax.ClientOptions{BaseURL: baseURL})
	if err != nil {
		fmt.Fprintln(os.Stderr, "NewClient DID:", err)
		os.Exit(1)
	}
	defer didClient.Close()

	id := didClient.GetIdentity()
	fmt.Println("  DID:", id["did"])

	ws := "demo-workspace"
	knockReq, err := didClient.CreateRequest(hax.CreateRequestParams{
		Type:      "text-approval-v1",
		Payload:   map[string]any{"text": "May I join?"},
		Workspace: &ws,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "Knock CreateRequest:", err)
		os.Exit(1)
	}
	fmt.Println("  Knock:  ", knockReq.ID, "status=", knockReq.Status)

	status, err := didClient.GetKnockStatus(ws, "")
	if err != nil {
		fmt.Fprintln(os.Stderr, "GetKnockStatus:", err)
		os.Exit(1)
	}
	fmt.Println("  Knock status:", status["status"])

	// 3. FormBuilder
	fmt.Println("\n=== FormBuilder ===")
	form := hax.NewFormBuilder().
		Title("Smoke Test Form").
		Input("name", map[string]any{"label": "Name", "required": true}).
		Number("score", map[string]any{"label": "Score", "min": 0, "max": 100}).
		Checkbox("agree", map[string]any{"label": "I agree"})

	handle, err := client.CreateFormRequest(form, hax.CreateRequestParams{})
	if err != nil {
		fmt.Fprintln(os.Stderr, "CreateFormRequest:", err)
		os.Exit(1)
	}
	fmt.Println("  Form:  ", handle.ID())
	fmt.Println("  URL:   ", handle.URL())

	// Submit form response via admin endpoint
	_, err = client.SubmitResponse(handle.ID(), map[string]any{
		"values": map[string]any{"name": "Alice", "score": float64(95), "agree": true},
		"meta":   map[string]any{"submittedAt": time.Now().UTC().Format(time.RFC3339Nano)},
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "Form SubmitResponse:", err)
		os.Exit(1)
	}
	resp, err := handle.WaitForResponse(0.5, 5)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Form WaitForResponse:", err)
		os.Exit(1)
	}
	fmt.Println("  Name:  ", resp.Values.GetString("name"))
	fmt.Println("  Score: ", resp.Values.GetFloat("score"))
	fmt.Println("  Agree: ", resp.Values.GetBool("agree"))

	// 4. Encryption
	fmt.Println("\n=== Encryption ===")
	encClient, err := hax.NewClient(hax.ClientOptions{
		BaseURL:       baseURL,
		APIKey:        apiKey,
		EncryptionKey: "secret-passphrase",
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "NewClient enc:", err)
		os.Exit(1)
	}
	defer encClient.Close()

	encReq, err := encClient.CreateRequest(hax.CreateRequestParams{
		Type:    "text-approval-v1",
		Payload: map[string]any{"text": "Sensitive approval"},
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "Enc CreateRequest:", err)
		os.Exit(1)
	}
	fmt.Println("  Encrypted request:", encReq.ID)

	_, err = client.SubmitResponse(encReq.ID, map[string]any{"decision": "deny", "reason": "too risky"})
	if err != nil {
		fmt.Fprintln(os.Stderr, "Enc SubmitResponse:", err)
		os.Exit(1)
	}

	encResult, err := encClient.GetRequest(encReq.ID)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Enc GetRequest:", err)
		os.Exit(1)
	}
	fmt.Println("  Decrypted decision:", encResult.Response["decision"])
	fmt.Println("  Decrypted reason:  ", encResult.Response["reason"])

	fmt.Println("\n=== All smoke tests passed ===")
}
