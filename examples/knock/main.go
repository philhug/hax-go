package main

import (
	"fmt"
	"os"

	hax "github.com/Agent-Field/hax-go"
)

func main() {
	workspace := "demo-workspace"
	if len(os.Args) > 1 {
		workspace = os.Args[1]
	}

	// No API key → the client resolves (and mints, if needed) a DID identity.
	client, err := hax.NewClient(hax.ClientOptions{
		BaseURL: hax.DefaultBaseURL,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
	defer client.Close()

	identity := client.GetIdentity()
	if identity == nil {
		fmt.Fprintln(os.Stderr, "No identity resolved")
		os.Exit(1)
	}
	fmt.Printf("Knocking as %s\n", identity["did"])

	ws := workspace
	request, err := client.CreateRequest(hax.CreateRequestParams{
		Type:      "text-approval-v1",
		Payload:   map[string]any{"text": "May I join this workspace?"},
		Workspace: &ws,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
	fmt.Printf("Knock sent — request %s: %s\n", request.ID, request.URL)

	fmt.Println("Waiting for the workspace owner to accept the sender...")
	status, err := client.WaitForAcceptance(workspace, "", 300, 3)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}

	switch status {
	case "active":
		fmt.Println("Accepted! This DID can now send requests to the workspace.")
	case "blocked":
		fmt.Println("Blocked by the workspace owner.")
	default:
		fmt.Println("Timed out waiting for acceptance.")
	}
}
