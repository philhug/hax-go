# HAX Go SDK

Go client for the [HAX (Human Approval eXchange)](https://github.com/Agent-Field/hax-sdk) API. Enables agents and automated systems to programmatically collect human input.

This is a Go reimplementation of the [Python hax-sdk](https://pypi.org/project/hax-sdk/), with full wire-format compatibility including deterministic RSA key generation, Ed25519 DID signing, and base58btc did:key encoding.

## Installation

```bash
go get github.com/philhug/hax-go
```

## Quick Start

```go
package main

import (
    "fmt"
    hax "github.com/philhug/hax-go"
)

func main() {
    client, err := hax.NewClient(hax.ClientOptions{
        APIKey:  "hax_live_...",
        BaseURL: "http://localhost:3000/api/v1",
    })
    if err != nil { panic(err) }
    defer client.Close()

    request, err := client.CreateRequest(hax.CreateRequestParams{
        Type:    "text-approval-v1",
        Payload: map[string]any{"text": "Deploy main to prod?", "approveLabel": "Ship it", "denyLabel": "Hold"},
        WebhookURL: hax.StringPtr("https://myapp.com/webhook"),
    })
    if err != nil { panic(err) }

    fmt.Println("Share with approver:", request.URL)

    // Poll until completed/expired/cancelled
    result, err := client.WaitForResponse(request.ID, 2.0, 300)
    if err != nil { panic(err) }

    if result.IsCompleted() {
        decision := result.Response["decision"]
        fmt.Println("Decision:", decision)
    }
}
```

## Features

- **Typed models**: Request/response structs with JSON tags and status helpers
- **FormBuilder**: Fluent API for building typed forms with runtime type inference
- **E2E encryption**: RSA-OAEP-SHA256 hybrid encryption for sensitive responses
- **Webhook verification**: HMAC-SHA256 signature verification
- **Delivery**: Send requests via email or SMS
- **Polling**: Built-in `WaitForResponse` with configurable timeout
- **DID identity**: Ed25519 `did:key` authentication for signature-only "knock" requests
- **Error handling**: Typed error hierarchy matching HTTP status codes
- **Zero dependencies**: Uses only the Go standard library

## Authentication

The client supports two authentication methods, which can be used together:

### API Key

```go
client, _ := hax.NewClient(hax.ClientOptions{
    APIKey: "hax_live_...",
})
```

### DID Identity (signature-only "knock")

```go
// No API key → a DID identity is resolved (and minted on first use,
// persisted to ~/.hax/identity.json).
client, _ := hax.NewClient(hax.ClientOptions{
    BaseURL: "https://your-hax.example.com/api/v1",
})

fmt.Println(client.GetIdentity()) // map[string]any{"did": "did:key:z6Mk..."}

// Knock a workspace by its public handle.
client.CreateRequest(hax.CreateRequestParams{
    Type:      "text-approval-v1",
    Payload:   map[string]any{"text": "May I join?"},
    Workspace: hax.StringPtr("acme"),
})

// Poll until accepted.
status, _ := client.WaitForAcceptance("acme", "", 300, 3)
// "active" | "blocked" | "timeout"
```

### Managing Identities

```go
identity, _ := hax.GenerateIdentity()
fmt.Println(identity.DID) // did:key:z6Mk...

fp, _ := hax.DidFingerprint(identity.PrivateKeyJWK) // ab:12:...

hax.SaveIdentity(identity, "") // writes ~/.hax/identity.json (0600)
```

## Request Methods

```go
// Create a request
request, _ := client.CreateRequest(hax.CreateRequestParams{
    Type:             "text-approval-v1",
    Payload:          map[string]any{"text": "Approve this action?"},
    Title:            hax.StringPtr("Optional title"),
    ExpiresInSeconds: hax.IntPtr(3600),
    Metadata:         map[string]any{"pr_number": 123},
})

// Send via email
request, _ = client.RequestViaEmail(hax.CreateRequestParams{
    Type:    "confirm-action-v1",
    Payload: map[string]any{"title": "Approve?", "confirmPhrase": "YES"},
}, "approver@example.com", hax.StringPtr("Approval Required"), nil)

// Send via SMS
request, _ = client.RequestViaSMS(hax.CreateRequestParams{
    Type:    "text-approval-v1",
    Payload: map[string]any{"text": "Approve?"},
}, "+15551234567", nil)

// Get a request by ID
request, _ = client.GetRequest("req_123")

// List recent requests
requests, _ := client.ListRequests()

// Cancel a pending request
client.CancelRequest("req_123")

// Submit a response (for testing)
client.SubmitResponse("req_123", map[string]any{"decision": "approve"})

// Wait for completion with timeout
result, _ := client.WaitForResponse("req_123", 2.0, 60)

// List available template types
types, _ := client.ListTypes()
```

### Status Helpers

```go
if request.IsPending()   { /* waiting... */ }
if request.IsCompleted() { /* response available */ }
if request.IsExpired()   { /* expired */ }
if request.IsCancelled() { /* cancelled */ }
if request.IsHeld()      { /* held pending sender acceptance */ }
```

## FormBuilder

Build typed forms with a fluent API:

```go
form := hax.NewFormBuilder().
    Title("Event Registration").
    Input("name", map[string]any{"label": "Full Name", "required": true}).
    Input("email", map[string]any{"label": "Email", "variant": "email", "required": true}).
    Number("age", map[string]any{"label": "Age", "min": 0, "max": 120}).
    Checkbox("newsletter", map[string]any{"checkbox_label": "Subscribe to newsletter"})

webhookURL := "https://myapp.com/webhook"
handle, _ := client.CreateFormRequest(form, hax.CreateRequestParams{
    WebhookURL: &webhookURL,
})

fmt.Printf("Form URL: %s\n", handle.URL())

// Wait for typed response
response, _ := handle.WaitForResponse(2.0, 300)
fmt.Println(response.Values.GetString("name"))    // string
fmt.Println(response.Values.GetFloat("age"))     // float64
fmt.Println(response.Values.GetBool("newsletter")) // bool
```

### Available Field Types

| Method | Output Type | Description |
|--------|-------------|-------------|
| `.Input(id)` | `string` | Text input (variants: text, email, url, tel) |
| `.Textarea(id)` | `string` | Multi-line text input |
| `.Select(id)` | `string` | Dropdown select |
| `.RadioGroup(id)` | `string` | Radio button group |
| `.Date(id)` | `string` | Date picker (ISO format) |
| `.Number(id)` | `float64` | Numeric input |
| `.Slider(id)` | `float64` | Slider control |
| `.Checkbox(id)` | `bool` | Single checkbox |
| `.Switch(id)` | `bool` | Toggle switch |
| `.CheckboxGroup(id)` | `[]string` | Multi-select checkboxes |
| `.Hidden(id, value)` | `type(value)` | Hidden field |

Field options use `map[string]any` with snake_case keys (automatically converted to camelCase for the API).

## Webhooks

Verify and parse webhook events:

```go
// In your HTTP handler
func handleWebhook(body []byte, signature string) {
    // Verify signature
    if !hax.VerifySignature(body, signature, "whsec_...") {
        http.Error(w, "Invalid signature", 400)
        return
    }

    // Parse the event
    event, err := hax.ParseEvent(body, nil)
    if err != nil { /* handle error */ }

    switch event.EventType() {
    case "completed":
        fmt.Printf("Request %s completed!\n", event.RequestID())
        fmt.Printf("Response: %v\n", event.Response())
    case "expired":
        fmt.Printf("Request %s expired\n", event.RequestID())
    }
}
```

### Event Types

- `request.sent` — Notification was delivered (email/SMS)
- `request.opened` — Human opened the request link
- `request.completed` — Human submitted a response
- `request.expired` — Request expired without action

## Encryption

For sensitive response data, use end-to-end encryption:

```go
client, _ := hax.NewClient(hax.ClientOptions{
    APIKey:        "hax_live_...",
    EncryptionKey: "my-secret-passphrase",
})

// Public key is automatically sent with requests.
// Response is automatically decrypted when retrieved.
request, _ := client.CreateRequest(hax.CreateRequestParams{
    Type:    "text-approval-v1",
    Payload: map[string]any{"text": "Approve this sensitive action?"},
})

completed, _ := client.GetRequest(request.ID)
fmt.Println(completed.Response) // Decrypted plaintext
```

### Manual Decryption

```go
publicKey, privateKey, _ := hax.GenerateKeyPair("my-secret")

client, _ := hax.NewClient(hax.ClientOptions{
    APIKey:     "hax_live_...",
    PublicKey:  publicKey,
})

// Later, manually decrypt
request, _ := client.GetRequest("req_123")
if hax.IsEncryptedResponse(request.Response) {
    decrypted, _ := hax.DecryptResponse(
        request.Response["_encrypted"].(string),
        privateKey,
    )
    fmt.Println(decrypted)
}
```

## Error Handling

```go
request, err := client.CreateRequest(params)
switch e := err.(type) {
case *hax.AuthenticationError:
    // Invalid API key (401)
case *hax.ForbiddenError:
    // Access forbidden (403) — check e.Code
case *hax.NotFoundError:
    // Resource not found (404)
case *hax.ValidationError:
    // Invalid request data (422)
case *hax.RateLimitError:
    // Rate limited (429) — check e.RetryAfter
case *hax.ServerError:
    // Server error (5xx)
case *hax.HaxError:
    // Other errors
}
```

## Template Types

| Template | Description |
|----------|-------------|
| `text-approval-v1` | Show text and collect an approve/deny decision |
| `confirm-action-v1` | Require typing a specific phrase to confirm |
| `collect-email-v1` | Prompt the user for an email address |
| `form-builder` | Advanced forms with field types and validation |
| `multi-choice-selection-v1` | Single or multiple selection from option cards |
| `code-changes-v1` | GitHub-style diff view with inline comments |
| `rich-text-editor-v1` | Markdown-formatted text editing |
| `file-upload-v1` | Collect files from users |
| `signature-capture-v1` | Capture e-signatures |
| `data-table-review-v1` | Review, select, or edit tabular data |
| `scheduling-picker-v1` | Date/time slot selection |
| `multi-step-wizard-v1` | Sequential steps with navigation |
| `side-by-side-comparison-v1` | Compare two versions with diff highlighting |
| `terminal-output-v1` | Display command output/logs with approve-to-continue |

## Reference Server

The `server/` package provides a reference HAX API server implementation. It implements the full API surface that the `HaxClient` talks to, making it useful for local development, testing, and integration validation.

### Running the Server

```bash
# Build and run
go run ./cmd/haxserver --addr :8080 --api-key my-secret-key

# With webhooks and manual knock acceptance
go run ./cmd/haxserver --webhook-secret whsec_... --no-auto-accept
```

### Using as a Library

```go
import "github.com/philhug/hax-go/server"

srv := server.NewServer(server.Config{
    Addr:    ":8080",
    APIKey:  "my-secret-key",
})
srv.ListenAndServe()
```

### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/requests` | Create a request |
| `GET` | `/api/v1/requests` | List recent requests |
| `GET` | `/api/v1/requests/{id}` | Get a request by ID |
| `PATCH` | `/api/v1/requests/{id}` | Update request status (cancel) |
| `POST` | `/api/v1/requests/{id}/response` | Submit a response |
| `GET` | `/api/v1/types` | List/search template types |
| `GET` | `/api/v1/knock/status` | Check DID knock status |
| `PATCH` | `/api/v1/workspaces/settings` | Configure messaging providers |
| `POST` | `/api/v1/admin/knock` | *(admin)* Accept/block a DID knock |
| `POST` | `/api/v1/admin/respond` | *(admin)* Submit a response on behalf |

### Features

- **Dual auth**: API key (Bearer) and DID JWS signature verification
- **Response encryption**: RSA-OAEP-SHA256 when `publicKey` is provided
- **Webhook dispatch**: HMAC-SHA256 signed webhooks on response submission
- **Knock flow**: Auto-accept (default) or manual DID acceptance with held requests
- **In-memory store**: Thread-safe, no external database needed
- **17 built-in types**: Matching the HAX artifact registry

### Testing Against the Server

```go
func TestMyFeature(t *testing.T) {
    _, baseURL, cleanup := server.NewTestServer(server.Config{
        APIKey: "test-key",
    })
    defer cleanup()

    client, _ := hax.NewClient(hax.ClientOptions{
        BaseURL: baseURL,
        APIKey:  "test-key",
    })
    defer client.Close()

    req, _ := client.CreateRequest(hax.CreateRequestParams{
        Type:    "text-approval-v1",
        Payload: map[string]any{"text": "Approve?"},
    })
    // ...
}
```

## License

MIT
