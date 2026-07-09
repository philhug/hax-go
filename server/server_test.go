package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	hax "github.com/philhug/hax-go"
)

// hubURL strips /api/v1 from baseURL for UI requests.
func hubURL(baseURL, path string) string {
	return strings.TrimSuffix(baseURL, "/api/v1") + path
}

// --- Test helpers ---

func newTestServer(t *testing.T, config Config) (*Server, string, func()) {
	t.Helper()
	s, baseURL, cleanup := NewTestServer(config)
	return s, baseURL, cleanup
}

func newDIDClient(t *testing.T, baseURL string) *hax.HaxClient {
	t.Helper()
	identity, err := hax.GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	client, err := hax.NewClient(hax.ClientOptions{
		BaseURL:       baseURL,
		DID:           identity.DID,
		PrivateKeyJWK: identity.PrivateKeyJWK,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return client
}

func newAPIKeyClient(t *testing.T, baseURL, apiKey string) *hax.HaxClient {
	t.Helper()
	t.Setenv("HAX_IDENTITY_FILE", "/nonexistent/hax-identity-test.json")
	client, err := hax.NewClient(hax.ClientOptions{
		BaseURL: baseURL,
		APIKey:  apiKey,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return client
}

// submitResponseViaAdmin submits a response to a request using the admin endpoint.
func submitResponseViaAdmin(t *testing.T, baseURL, requestID string, response map[string]any) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"requestId": requestID,
		"response":   response,
	})
	resp, err := http.Post(baseURL+"/admin/respond", "application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatalf("admin respond: %v", err)
	}
	resp.Body.Close()
}

// --- Tests ---

func TestCreateAndGetRequest_DIDAuth(t *testing.T) {
	_, baseURL, cleanup := newTestServer(t, Config{})
	defer cleanup()

	client := newDIDClient(t, baseURL)
	defer client.Close()

	created, err := client.CreateRequest(hax.CreateRequestParams{
		Type:  "text-approval-v1",
		Title: hax.StringPtr("Test Approval"),
		Payload: map[string]any{
			"text": "Approve this?",
		},
		Metadata: map[string]any{"source": "test"},
	})
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}

	if created.ID == "" {
		t.Error("expected non-empty ID")
	}
	if created.Type != "text-approval-v1" {
		t.Errorf("type = %q, want %q", created.Type, "text-approval-v1")
	}
	if created.Status != hax.StatusPending {
		t.Errorf("status = %q, want %q", created.Status, hax.StatusPending)
	}
	if created.URL == "" {
		t.Error("expected non-empty URL")
	}
	if created.CreatedAt == "" {
		t.Error("expected non-empty createdAt")
	}

	// Get the request.
	req, err := client.GetRequest(created.ID)
	if err != nil {
		t.Fatalf("GetRequest: %v", err)
	}
	if req.ID != created.ID {
		t.Errorf("ID = %q, want %q", req.ID, created.ID)
	}
	if req.Type != "text-approval-v1" {
		t.Errorf("type = %q, want %q", req.Type, "text-approval-v1")
	}
	if req.Status != hax.StatusPending {
		t.Errorf("status = %q, want %q", req.Status, hax.StatusPending)
	}
}

func TestCreateRequest_APIKeyAuth(t *testing.T) {
	_, baseURL, cleanup := newTestServer(t, Config{APIKey: "secret-key-123"})
	defer cleanup()

	client := newAPIKeyClient(t, baseURL, "secret-key-123")
	defer client.Close()

	created, err := client.CreateRequest(hax.CreateRequestParams{
		Type:    "code-approval-v1",
		Payload: map[string]any{"code": "print('hello')"},
	})
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	if created.ID == "" {
		t.Error("expected non-empty ID")
	}
}

func TestCreateRequest_WrongAPIKey(t *testing.T) {
	_, baseURL, cleanup := newTestServer(t, Config{APIKey: "correct-key"})
	defer cleanup()

	client := newAPIKeyClient(t, baseURL, "wrong-key")
	defer client.Close()

	_, err := client.CreateRequest(hax.CreateRequestParams{
		Type:    "text-approval-v1",
		Payload: map[string]any{"text": "test"},
	})
	if err == nil {
		t.Fatal("expected error for wrong API key")
	}

	var authErr *hax.AuthenticationError
	if !errorAs(err, &authErr) {
		t.Errorf("expected AuthenticationError, got %T: %v", err, err)
	}
}

func TestCreateRequest_NoAuth(t *testing.T) {
	_, baseURL, cleanup := newTestServer(t, Config{APIKey: "secret"})
	defer cleanup()

	// Direct HTTP without auth headers.
	resp, err := http.Post(baseURL+"/requests", "application/json", strings.NewReader(`{"type":"test"}`))
	if err != nil {
		t.Fatalf("HTTP POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}
}

func TestCreateRequest_MissingType(t *testing.T) {
	_, baseURL, cleanup := newTestServer(t, Config{APIKey: "key"})
	defer cleanup()

	client := newAPIKeyClient(t, baseURL, "key")
	defer client.Close()

	_, err := client.CreateRequest(hax.CreateRequestParams{
		Type:    "",
		Payload: map[string]any{},
	})
	if err == nil {
		t.Fatal("expected error for missing type")
	}

	var valErr *hax.ValidationError
	if !errorAs(err, &valErr) {
		t.Errorf("expected ValidationError, got %T: %v", err, err)
	}
}

func TestGetRequest_NotFound(t *testing.T) {
	_, baseURL, cleanup := newTestServer(t, Config{APIKey: "key"})
	defer cleanup()

	client := newAPIKeyClient(t, baseURL, "key")
	defer client.Close()

	_, err := client.GetRequest("nonexistent-id")
	if err == nil {
		t.Fatal("expected error for non-existent request")
	}

	var nfErr *hax.NotFoundError
	if !errorAs(err, &nfErr) {
		t.Errorf("expected NotFoundError, got %T: %v", err, err)
	}
}

func TestListRequests(t *testing.T) {
	_, baseURL, cleanup := newTestServer(t, Config{APIKey: "key"})
	defer cleanup()

	client := newAPIKeyClient(t, baseURL, "key")
	defer client.Close()

	for i := 0; i < 3; i++ {
		_, err := client.CreateRequest(hax.CreateRequestParams{
			Type:    "text-approval-v1",
			Payload: map[string]any{"text": fmt.Sprintf("request %d", i)},
		})
		if err != nil {
			t.Fatalf("CreateRequest %d: %v", i, err)
		}
	}

	list, err := client.ListRequests()
	if err != nil {
		t.Fatalf("ListRequests: %v", err)
	}
	if len(list) != 3 {
		t.Errorf("len = %d, want 3", len(list))
	}

	for _, r := range list {
		if r.ID == "" {
			t.Error("expected non-empty ID in list")
		}
		if r.Type != "text-approval-v1" {
			t.Errorf("type = %q, want %q", r.Type, "text-approval-v1")
		}
		if r.Status != hax.StatusPending {
			t.Errorf("status = %q, want %q", r.Status, hax.StatusPending)
		}
	}
}

func TestCancelRequest(t *testing.T) {
	_, baseURL, cleanup := newTestServer(t, Config{APIKey: "key"})
	defer cleanup()

	client := newAPIKeyClient(t, baseURL, "key")
	defer client.Close()

	created, err := client.CreateRequest(hax.CreateRequestParams{
		Type:    "text-approval-v1",
		Payload: map[string]any{"text": "cancel me"},
	})
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}

	req, err := client.CancelRequest(created.ID)
	if err != nil {
		t.Fatalf("CancelRequest: %v", err)
	}
	if !req.IsCancelled() {
		t.Errorf("status = %q, want %q", req.Status, hax.StatusCancelled)
	}
}

func TestSubmitResponse(t *testing.T) {
	_, baseURL, cleanup := newTestServer(t, Config{APIKey: "key"})
	defer cleanup()

	client := newAPIKeyClient(t, baseURL, "key")
	defer client.Close()

	created, err := client.CreateRequest(hax.CreateRequestParams{
		Type:    "text-approval-v1",
		Payload: map[string]any{"text": "approve?"},
	})
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}

	resp, err := client.SubmitResponse(created.ID, map[string]any{
		"decision": "approve",
	})
	if err != nil {
		t.Fatalf("SubmitResponse: %v", err)
	}
	if !resp.IsCompleted() {
		t.Errorf("status = %q, want %q", resp.Status, hax.StatusCompleted)
	}
	if resp.Response == nil {
		t.Fatal("expected non-nil response")
	}
	if d, _ := resp.Response["decision"].(string); d != "approve" {
		t.Errorf("decision = %q, want %q", d, "approve")
	}
}

func TestWaitForResponse(t *testing.T) {
	_, baseURL, cleanup := newTestServer(t, Config{APIKey: "key"})
	defer cleanup()

	client := newAPIKeyClient(t, baseURL, "key")
	defer client.Close()

	created, err := client.CreateRequest(hax.CreateRequestParams{
		Type:    "text-approval-v1",
		Payload: map[string]any{"text": "wait for me"},
	})
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}

	// Submit response asynchronously.
	go func() {
		time.Sleep(200 * time.Millisecond)
		submitResponseViaAdmin(t, baseURL, created.ID, map[string]any{
			"decision": "approve",
		})
	}()

	req, err := client.WaitForResponse(created.ID, 0.5, 10)
	if err != nil {
		t.Fatalf("WaitForResponse: %v", err)
	}
	if !req.IsCompleted() {
		t.Errorf("status = %q, want %q", req.Status, hax.StatusCompleted)
	}
}

func TestListTypes(t *testing.T) {
	_, baseURL, cleanup := newTestServer(t, Config{APIKey: "key"})
	defer cleanup()

	client := newAPIKeyClient(t, baseURL, "key")
	defer client.Close()

	types, err := client.ListTypes()
	if err != nil {
		t.Fatalf("ListTypes: %v", err)
	}
	if len(types) == 0 {
		t.Fatal("expected non-empty types list")
	}

	found := false
	for _, tp := range types {
		if name, _ := tp["name"]; name == "text-approval-v1" {
			found = true
		}
	}
	if !found {
		t.Error("text-approval-v1 not found in types")
	}
}

func TestSearchTypes(t *testing.T) {
	_, baseURL, cleanup := newTestServer(t, Config{APIKey: "key"})
	defer cleanup()

	client := newAPIKeyClient(t, baseURL, "key")
	defer client.Close()

	result, err := client.SearchTypes("approval", nil, "", nil)
	if err != nil {
		t.Fatalf("SearchTypes: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	count, _ := result["count"].(float64)
	if count < 1 {
		t.Errorf("expected count >= 1, got %v", count)
	}
}

func TestKnockStatus_AutoAccept(t *testing.T) {
	_, baseURL, cleanup := newTestServer(t, Config{})
	defer cleanup()

	client := newDIDClient(t, baseURL)
	defer client.Close()

	workspace := "test-workspace"
	status, err := client.GetKnockStatus(workspace, "")
	if err != nil {
		t.Fatalf("GetKnockStatus: %v", err)
	}
	s, _ := status["status"].(string)
	if s != "active" {
		t.Errorf("status = %q, want %q", s, "active")
	}
}

func TestWaitForAcceptance(t *testing.T) {
	_, baseURL, cleanup := newTestServer(t, Config{})
	defer cleanup()

	client := newDIDClient(t, baseURL)
	defer client.Close()

	workspace := "test-ws"
	result, err := client.WaitForAcceptance(workspace, "", 5, 0.5)
	if err != nil {
		t.Fatalf("WaitForAcceptance: %v", err)
	}
	if result != "active" {
		t.Errorf("result = %q, want %q", result, "active")
	}
}

func TestKnockStatus_ManualAccept(t *testing.T) {
	autoAccept := false
	_, baseURL, cleanup := newTestServer(t, Config{AutoAcceptKnocks: &autoAccept})
	defer cleanup()

	// Create a DID client.
	identity, err := hax.GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	client, err := hax.NewClient(hax.ClientOptions{
		BaseURL:       baseURL,
		DID:           identity.DID,
		PrivateKeyJWK: identity.PrivateKeyJWK,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	workspace := "manual-ws"

	// Create a request — should be "held".
	created, err := client.CreateRequest(hax.CreateRequestParams{
		Type:      "text-approval-v1",
		Payload:   map[string]any{"text": "held request"},
		Workspace: &workspace,
	})
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	if created.Status != hax.StatusHeld {
		t.Errorf("status = %q, want %q", created.Status, hax.StatusHeld)
	}

	// Knock status should be "pending".
	status, err := client.GetKnockStatus(workspace, "")
	if err != nil {
		t.Fatalf("GetKnockStatus: %v", err)
	}
	s, _ := status["status"].(string)
	if s != "pending" {
		t.Errorf("knock status = %q, want %q", s, "pending")
	}

	// Admin accepts the knock.
	acceptBody, _ := json.Marshal(map[string]any{
		"workspace": workspace,
		"did":       identity.DID,
		"status":    "active",
	})
	resp, err := http.Post(baseURL+"/admin/knock", "application/json", strings.NewReader(string(acceptBody)))
	if err != nil {
		t.Fatalf("admin knock: %v", err)
	}
	resp.Body.Close()

	// Now knock status should be "active".
	status, err = client.GetKnockStatus(workspace, "")
	if err != nil {
		t.Fatalf("GetKnockStatus after accept: %v", err)
	}
	s, _ = status["status"].(string)
	if s != "active" {
		t.Errorf("knock status = %q, want %q", s, "active")
	}

	// The held request should now be "pending".
	req, err := client.GetRequest(created.ID)
	if err != nil {
		t.Fatalf("GetRequest: %v", err)
	}
	if req.Status != hax.StatusPending {
		t.Errorf("held request status = %q, want %q", req.Status, hax.StatusPending)
	}
}

func TestConfigureMessaging(t *testing.T) {
	_, baseURL, cleanup := newTestServer(t, Config{APIKey: "key"})
	defer cleanup()

	client := newAPIKeyClient(t, baseURL, "key")
	defer client.Close()

	err := client.ConfigureMessaging(
		map[string]any{"provider": "sendgrid", "from": "noreply@example.com"},
		map[string]any{"provider": "twilio", "from": "+1234567890"},
	)
	if err != nil {
		t.Fatalf("ConfigureMessaging: %v", err)
	}
}

func TestRequestExpiration(t *testing.T) {
	_, baseURL, cleanup := newTestServer(t, Config{APIKey: "key"})
	defer cleanup()

	client := newAPIKeyClient(t, baseURL, "key")
	defer client.Close()

	created, err := client.CreateRequest(hax.CreateRequestParams{
		Type:             "text-approval-v1",
		Payload:          map[string]any{"text": "expires soon"},
		ExpiresInSeconds: hax.IntPtr(3600),
	})
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	if created.ExpiresAt == nil {
		t.Error("expected non-nil expiresAt")
	}
	if *created.ExpiresAt == "" {
		t.Error("expected non-empty expiresAt")
	}
}

func TestRequestWithSender(t *testing.T) {
	_, baseURL, cleanup := newTestServer(t, Config{APIKey: "key"})
	defer cleanup()

	client := newAPIKeyClient(t, baseURL, "key")
	defer client.Close()

	created, err := client.CreateRequest(hax.CreateRequestParams{
		Type:    "text-approval-v1",
		Payload: map[string]any{"text": "sender test"},
		Sender: &hax.SenderManifest{
			Key:         "agent-1",
			DisplayName: hax.StringPtr("Test Agent"),
			Project:     hax.StringPtr("proj-1"),
		},
		ThreadKey: hax.StringPtr("thread-1"),
	})
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	if created.SenderID == nil || *created.SenderID != "agent-1" {
		t.Errorf("senderId = %v, want %q", created.SenderID, "agent-1")
	}
	if created.ThreadID == nil || *created.ThreadID != "thread-1" {
		t.Errorf("threadId = %v, want %q", created.ThreadID, "thread-1")
	}
}

func TestEncryptedResponse(t *testing.T) {
	_, baseURL, cleanup := newTestServer(t, Config{APIKey: "key"})
	defer cleanup()

	// Create client with encryption key.
	client, err := hax.NewClient(hax.ClientOptions{
		BaseURL:      baseURL,
		APIKey:       "key",
		EncryptionKey: "test-passphrase",
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	if client.PublicKey() == nil {
		t.Fatal("expected non-nil public key")
	}
	if client.PrivateKey() == nil {
		t.Fatal("expected non-nil private key")
	}

	created, err := client.CreateRequest(hax.CreateRequestParams{
		Type:    "text-approval-v1",
		Payload: map[string]any{"text": "encrypt me"},
	})
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}

	// Submit a response via admin endpoint.
	submitResponseViaAdmin(t, baseURL, created.ID, map[string]any{
		"decision": "approve",
		"comment":  "looks good",
	})

	// Get the request — should auto-decrypt.
	req, err := client.GetRequest(created.ID)
	if err != nil {
		t.Fatalf("GetRequest: %v", err)
	}
	if !req.IsCompleted() {
		t.Fatalf("status = %q, want %q", req.Status, hax.StatusCompleted)
	}
	if req.Response == nil {
		t.Fatal("expected non-nil response")
	}
	decision, _ := req.Response["decision"].(string)
	if decision != "approve" {
		t.Errorf("decision = %q, want %q", decision, "approve")
	}
}

func TestFormBuilder(t *testing.T) {
	_, baseURL, cleanup := newTestServer(t, Config{APIKey: "key"})
	defer cleanup()

	client := newAPIKeyClient(t, baseURL, "key")
	defer client.Close()

	form := hax.NewFormBuilder()
	form.Title("Test Form")
	form.Input("name", map[string]any{"label": "Your Name"})
	form.Number("age", map[string]any{"label": "Age"})
	form.Checkbox("agree", map[string]any{"label": "I agree"})

	handle, err := client.CreateFormRequest(form, hax.CreateRequestParams{})
	if err != nil {
		t.Fatalf("CreateFormRequest: %v", err)
	}
	if handle.ID() == "" {
		t.Error("expected non-empty form request ID")
	}
	if handle.URL() == "" {
		t.Error("expected non-empty form request URL")
	}

	// Submit form response.
	submitResponseViaAdmin(t, baseURL, handle.ID(), map[string]any{
		"values": map[string]any{
			"name":  "Alice",
			"age":   float64(30),
			"agree": true,
		},
		"meta": map[string]any{
			"submittedAt": time.Now().UTC().Format(time.RFC3339Nano),
		},
	})

	// Wait for response.
	resp, err := handle.WaitForResponse(0.5, 10)
	if err != nil {
		t.Fatalf("WaitForResponse: %v", err)
	}
	if resp.Values == nil {
		t.Fatal("expected non-nil values")
	}
	if name := resp.Values.GetString("name"); name != "Alice" {
		t.Errorf("name = %q, want %q", name, "Alice")
	}
	if age := resp.Values.GetFloat("age"); age != 30 {
		t.Errorf("age = %v, want 30", age)
	}
	if !resp.Values.GetBool("agree") {
		t.Error("agree = false, want true")
	}
}

func TestWebhookDispatch(t *testing.T) {
	webhookReceived := make(chan map[string]any, 1)

	// Start a webhook receiver.
	webhookServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var event map[string]any
		if err := json.Unmarshal(body, &event); err != nil {
			t.Errorf("webhook unmarshal: %v", err)
			return
		}
		sig := r.Header.Get("X-Hax-Signature")
		if sig == "" {
			t.Error("missing X-Hax-Signature header")
		}
		webhookReceived <- event
	}))
	defer webhookServer.Close()

	_, baseURL, cleanup := newTestServer(t, Config{
		APIKey:        "key",
		WebhookSecret: "whsec_test",
	})
	defer cleanup()

	client := newAPIKeyClient(t, baseURL, "key")
	defer client.Close()

	webhookURL := webhookServer.URL
	created, err := client.CreateRequest(hax.CreateRequestParams{
		Type:      "text-approval-v1",
		Payload:   map[string]any{"text": "webhook test"},
		WebhookURL: &webhookURL,
	})
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}

	// Submit a response to trigger the webhook.
	submitResponseViaAdmin(t, baseURL, created.ID, map[string]any{
		"decision": "approve",
	})

	select {
	case event := <-webhookReceived:
		if event["type"] != "request.completed" {
			t.Errorf("event type = %v, want %q", event["type"], "request.completed")
		}
		data, _ := event["data"].(map[string]any)
		if data == nil {
			t.Fatal("expected non-nil data")
		}
		if data["id"] != created.ID {
			t.Errorf("event data id = %v, want %q", data["id"], created.ID)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("webhook not received within timeout")
	}
}

func TestJWSSignatureVerification(t *testing.T) {
	_, baseURL, cleanup := newTestServer(t, Config{APIKey: "key"})
	defer cleanup()

	// Create a valid DID identity.
	identity, err := hax.GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}

	// Sign a request with the SDK's signer.
	client, err := hax.NewClient(hax.ClientOptions{
		BaseURL:       baseURL,
		DID:           identity.DID,
		PrivateKeyJWK: identity.PrivateKeyJWK,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	// This should succeed — the server verifies the JWS.
	created, err := client.CreateRequest(hax.CreateRequestParams{
		Type:    "text-approval-v1",
		Payload: map[string]any{"text": "jws test"},
	})
	if err != nil {
		t.Fatalf("CreateRequest with valid JWS: %v", err)
	}
	if created.ID == "" {
		t.Error("expected non-empty ID")
	}
}

func TestTamperedJWSSignature(t *testing.T) {
	_, baseURL, cleanup := newTestServer(t, Config{})
	defer cleanup()

	// Create a valid identity.
	identity, err := hax.GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}

	// Create a raw HTTP request with a tampered signature.
	body := `{"type":"text-approval-v1","payload":{"text":"tampered"}}`
	req, _ := http.NewRequest("POST", baseURL+"/requests", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-HAX-DID", identity.DID)
	req.Header.Set("X-HAX-Signature", "invalid.signature.here")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("HTTP request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}
}

func TestRequestURL(t *testing.T) {
	srv, baseURL, cleanup := newTestServer(t, Config{APIKey: "key"})
	defer cleanup()
	_ = srv

	client := newAPIKeyClient(t, baseURL, "key")
	defer client.Close()

	created, err := client.CreateRequest(hax.CreateRequestParams{
		Type:    "text-approval-v1",
		Payload: map[string]any{"text": "url test"},
	})
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}

	// URL should contain /hub/r/.
	if !strings.Contains(created.URL, "/hub/r/") {
		t.Errorf("URL = %q, expected to contain /hub/r/", created.URL)
	}
}

func TestDeliveryConfig_Email(t *testing.T) {
	_, baseURL, cleanup := newTestServer(t, Config{APIKey: "key"})
	defer cleanup()

	client := newAPIKeyClient(t, baseURL, "key")
	defer client.Close()

	subject := "Approval Needed"
	message := "Please review"
	created, err := client.RequestViaEmail(
		hax.CreateRequestParams{
			Type:    "text-approval-v1",
			Payload: map[string]any{"text": "email delivery"},
		},
		"user@example.com",
		&subject,
		&message,
	)
	if err != nil {
		t.Fatalf("RequestViaEmail: %v", err)
	}
	if created.Delivery == nil {
		t.Fatal("expected non-nil delivery")
	}
	if !created.Delivery.Success {
		t.Error("expected delivery success = true")
	}
	if created.Delivery.Channel != "email" {
		t.Errorf("channel = %q, want %q", created.Delivery.Channel, "email")
	}
}

// errorAs wraps errors.As for cleaner test code.
func errorAs(err error, target any) bool {
	return errors.As(err, target)
}

// --- Tests for plan-review-v2 ---

func TestPlanReview_CreateAndGet(t *testing.T) {
	_, baseURL, cleanup := newTestServer(t, Config{APIKey: "key"})
	defer cleanup()

	client := newAPIKeyClient(t, baseURL, "key")
	defer client.Close()

	created, err := client.CreateRequest(hax.CreateRequestParams{
		Type:    "plan-review-v2",
		Title:   hax.StringPtr("Plan Review"),
		Payload: map[string]any{
			"planSummary": "Test plan",
			"prd":         "## PRD\n- Item 1",
			"architecture": "## Arch\nComponent A",
			"issues": []any{
				map[string]any{
					"name":        "issue-1",
					"title":       "First issue",
					"description": "Do something",
					"dependsOn":   []string{},
					"filesToModify": []string{"main.go"},
					"acceptanceCriteria": []string{"works"},
				},
			},
			"revisionNumber": 0,
		},
	})
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	if created.Status != hax.StatusPending {
		t.Errorf("status = %q, want %q", created.Status, hax.StatusPending)
	}

	req, err := client.GetRequest(created.ID)
	if err != nil {
		t.Fatalf("GetRequest: %v", err)
	}
	if req.Type != "plan-review-v2" {
		t.Errorf("type = %q", req.Type)
	}
}

func TestPlanReview_ResponseParsing(t *testing.T) {
	_, baseURL, cleanup := newTestServer(t, Config{APIKey: "key"})
	defer cleanup()

	client := newAPIKeyClient(t, baseURL, "key")
	defer client.Close()

	created, err := client.CreateRequest(hax.CreateRequestParams{
		Type:    "plan-review-v2",
		Payload: map[string]any{"planSummary": "test"},
	})
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}

	_, err = client.SubmitResponse(created.ID, map[string]any{
		"decision": "approve",
		"feedback":  "looks good",
	})
	if err != nil {
		t.Fatalf("SubmitResponse: %v", err)
	}

	req, err := client.GetRequest(created.ID)
	if err != nil {
		t.Fatalf("GetRequest: %v", err)
	}
	if !req.IsCompleted() {
		t.Fatalf("status = %q, want completed", req.Status)
	}
	if d, _ := req.Response["decision"].(string); d != "approve" {
		t.Errorf("decision = %q, want %q", d, "approve")
	}
	if f, _ := req.Response["feedback"].(string); f != "looks good" {
		t.Errorf("feedback = %q, want %q", f, "looks good")
	}
}

func TestPlanReview_RequestChanges(t *testing.T) {
	_, baseURL, cleanup := newTestServer(t, Config{APIKey: "key"})
	defer cleanup()

	client := newAPIKeyClient(t, baseURL, "key")
	defer client.Close()

	created, _ := client.CreateRequest(hax.CreateRequestParams{
		Type:    "plan-review-v2",
		Payload: map[string]any{"planSummary": "test"},
	})

	_, err := client.SubmitResponse(created.ID, map[string]any{
		"decision": "request_changes",
		"feedback": "need more tests",
	})
	if err != nil {
		t.Fatalf("SubmitResponse: %v", err)
	}

	req, _ := client.GetRequest(created.ID)
	if d, _ := req.Response["decision"].(string); d != "request_changes" {
		t.Errorf("decision = %q, want %q", d, "request_changes")
	}
}

// --- Tests for pr-af-review-v1 ---

func TestPraFReview_CreateAndGet(t *testing.T) {
	_, baseURL, cleanup := newTestServer(t, Config{APIKey: "key"})
	defer cleanup()

	client := newAPIKeyClient(t, baseURL, "key")
	defer client.Close()

	created, err := client.CreateRequest(hax.CreateRequestParams{
		Type:  "pr-af-review-v1",
		Title: hax.StringPtr("PR Review"),
		Payload: map[string]any{
			"intent":        "Fix bug in auth flow",
			"reviewSummary": "2 findings",
			"findings": []any{
				map[string]any{
					"id": "f1", "severity": "critical", "title": "Bug",
					"defaultSelected": true, "filePath": "main.go", "lineStart": 10,
				},
				map[string]any{
					"id": "f2", "severity": "low", "title": "Nit",
					"defaultSelected": false,
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}

	req, err := client.GetRequest(created.ID)
	if err != nil {
		t.Fatalf("GetRequest: %v", err)
	}
	if req.Type != "pr-af-review-v1" {
		t.Errorf("type = %q", req.Type)
	}
}

func TestPraFReview_ResponsePostSelected(t *testing.T) {
	_, baseURL, cleanup := newTestServer(t, Config{APIKey: "key"})
	defer cleanup()

	client := newAPIKeyClient(t, baseURL, "key")
	defer client.Close()

	created, _ := client.CreateRequest(hax.CreateRequestParams{
		Type: "pr-af-review-v1",
		Payload: map[string]any{
			"findings": []any{
				map[string]any{"id": "f1", "severity": "high", "title": "A", "defaultSelected": true},
				map[string]any{"id": "f2", "severity": "low", "title": "B", "defaultSelected": false},
			},
		},
	})

	_, err := client.SubmitResponse(created.ID, map[string]any{
		"action":          "post_selected",
		"findings_to_post": []any{"f1"},
		"instructions":     "",
	})
	if err != nil {
		t.Fatalf("SubmitResponse: %v", err)
	}

	req, _ := client.GetRequest(created.ID)
	if a, _ := req.Response["action"].(string); a != "post_selected" {
		t.Errorf("action = %q, want %q", a, "post_selected")
	}
}

func TestPraFReview_ResponseReject(t *testing.T) {
	_, baseURL, cleanup := newTestServer(t, Config{APIKey: "key"})
	defer cleanup()

	client := newAPIKeyClient(t, baseURL, "key")
	defer client.Close()

	created, _ := client.CreateRequest(hax.CreateRequestParams{
		Type:    "pr-af-review-v1",
		Payload: map[string]any{"findings": []any{}},
	})

	_, err := client.SubmitResponse(created.ID, map[string]any{
		"action": "reject",
	})
	if err != nil {
		t.Fatalf("SubmitResponse: %v", err)
	}

	req, _ := client.GetRequest(created.ID)
	if a, _ := req.Response["action"].(string); a != "reject" {
		t.Errorf("action = %q, want %q", a, "reject")
	}
}

// --- Test for auto-expiration ---

func TestAutoExpiration(t *testing.T) {
	_, baseURL, cleanup := newTestServer(t, Config{APIKey: "key"})
	defer cleanup()

	client := newAPIKeyClient(t, baseURL, "key")
	defer client.Close()

	created, err := client.CreateRequest(hax.CreateRequestParams{
		Type:             "text-approval-v1",
		Payload:          map[string]any{"text": "expires fast"},
		ExpiresInSeconds: hax.IntPtr(1),
	})
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	if created.ExpiresAt == nil {
		t.Fatal("expected non-nil expiresAt")
	}

	// Wait for expiration.
	time.Sleep(2 * time.Second)

	req, err := client.GetRequest(created.ID)
	if err != nil {
		t.Fatalf("GetRequest: %v", err)
	}
	if !req.IsExpired() {
		t.Errorf("status = %q, want %q", req.Status, hax.StatusExpired)
	}
}

// --- Test for opened status ---

func TestOpenedStatus(t *testing.T) {
	_, baseURL, cleanup := newTestServer(t, Config{APIKey: "key"})
	defer cleanup()

	client := newAPIKeyClient(t, baseURL, "key")
	defer client.Close()

	created, _ := client.CreateRequest(hax.CreateRequestParams{
		Type:    "text-approval-v1",
		Payload: map[string]any{"text": "test"},
	})

	// Simulate a human opening the request URL.
	resp, err := http.Get(hubURL(baseURL, "/hub/r/"+created.ID))
	if err != nil {
		t.Fatalf("HTTP GET: %v", err)
	}
	resp.Body.Close()

	// The request should now be "opened".
	req, err := client.GetRequest(created.ID)
	if err != nil {
		t.Fatalf("GetRequest: %v", err)
	}
	if req.Status != "opened" {
		t.Errorf("status = %q, want %q", req.Status, "opened")
	}
	if req.OpenedAt == nil {
		t.Error("expected non-nil openedAt")
	}
}

// --- Test for CORS headers ---

func TestCORSHeaders(t *testing.T) {
	_, baseURL, cleanup := newTestServer(t, Config{APIKey: "key"})
	defer cleanup()

	req, _ := http.NewRequest("OPTIONS", baseURL+"/requests", nil)
	req.Header.Set("Origin", "http://example.com")
	req.Header.Set("Access-Control-Request-Method", "POST")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("OPTIONS: %v", err)
	}
	defer resp.Body.Close()

	if resp.Header.Get("Access-Control-Allow-Origin") != "*" {
		t.Error("missing Access-Control-Allow-Origin: *")
	}
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("OPTIONS status = %d, want %d", resp.StatusCode, http.StatusNoContent)
	}
}

// --- Test for health endpoint ---

func TestHealthEndpoint(t *testing.T) {
	_, baseURL, cleanup := newTestServer(t, Config{APIKey: "key"})
	defer cleanup()

	// Health endpoint is at /healthz (not under /api/v1).
	host := strings.TrimSuffix(baseURL, "/api/v1")
	resp, err := http.Get(host + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var result map[string]any
	json.NewDecoder(resp.Body).Decode(&result)
	if result["status"] != "ok" {
		t.Errorf("status = %v, want %q", result["status"], "ok")
	}
}

// --- Test for pagination ---

func TestPagination(t *testing.T) {
	_, baseURL, cleanup := newTestServer(t, Config{APIKey: "key"})
	defer cleanup()

	client := newAPIKeyClient(t, baseURL, "key")
	defer client.Close()

	for i := 0; i < 5; i++ {
		_, err := client.CreateRequest(hax.CreateRequestParams{
			Type:    "text-approval-v1",
			Payload:  map[string]any{"text": fmt.Sprintf("req %d", i)},
		})
		if err != nil {
			t.Fatalf("CreateRequest %d: %v", i, err)
		}
	}

	// Limit to 2.
	req, _ := http.NewRequest("GET", baseURL+"/requests?limit=2", nil)
	req.Header.Set("Authorization", "Bearer key")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /requests?limit=2: %v", err)
	}
	defer resp.Body.Close()

	var result map[string]any
	json.NewDecoder(resp.Body).Decode(&result)

	reqs, _ := result["requests"].([]any)
	if len(reqs) != 2 {
		t.Errorf("requests len = %d, want 2", len(reqs))
	}
	if hasMore, _ := result["hasMore"].(bool); !hasMore {
		t.Error("expected hasMore = true")
	}
	if cursor, _ := result["nextCursor"].(string); cursor == "" {
		t.Error("expected non-empty nextCursor")
	}
}

// --- Test for GET workspace settings ---

func TestGetWorkspaceSettings(t *testing.T) {
	_, baseURL, cleanup := newTestServer(t, Config{APIKey: "key"})
	defer cleanup()

	client := newAPIKeyClient(t, baseURL, "key")
	defer client.Close()

	// Set settings.
	err := client.ConfigureMessaging(
		map[string]any{"provider": "sendgrid"},
		map[string]any{"provider": "twilio"},
	)
	if err != nil {
		t.Fatalf("ConfigureMessaging: %v", err)
	}

	// Get settings via HTTP (client SDK doesn't have a GET settings method).
	resp, err := http.Get(baseURL + "/workspaces/settings")
	if err != nil {
		t.Fatalf("GET settings: %v", err)
	}
	defer resp.Body.Close()

	// This should return 401 because we didn't send auth.
	if resp.StatusCode == http.StatusOK {
		t.Error("expected 401 for unauthenticated request")
	}

	// Now with auth.
	req, _ := http.NewRequest("GET", baseURL+"/workspaces/settings", nil)
	req.Header.Set("Authorization", "Bearer key")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET settings with auth: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

// --- Test for rate limiting ---

func TestRateLimit(t *testing.T) {
	_, baseURL, cleanup := newTestServer(t, Config{APIKey: "key", RateLimit: 3})
	defer cleanup()

	// Make 4 rapid requests; the 4th should be rate-limited.
	for i := 0; i < 3; i++ {
		req, _ := http.NewRequest("GET", baseURL+"/types", nil)
		req.Header.Set("Authorization", "Bearer key")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("request %d: status = %d, want %d", i, resp.StatusCode, http.StatusOK)
		}
		if remaining := resp.Header.Get("X-RateLimit-Remaining"); remaining == "" {
			t.Error("missing X-RateLimit-Remaining header")
		}
	}

	// 4th request should be 429.
	req, _ := http.NewRequest("GET", baseURL+"/types", nil)
	req.Header.Set("Authorization", "Bearer key")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request 4: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("request 4: status = %d, want %d", resp.StatusCode, http.StatusTooManyRequests)
	}
	if ra := resp.Header.Get("Retry-After"); ra == "" {
		t.Error("missing Retry-After header")
	}
}

// --- Test for webhook event types ---

func TestWebhookEventTypes(t *testing.T) {
	received := make(chan string, 5)
	webhookServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var event map[string]any
		json.Unmarshal(body, &event)
		eventType, _ := event["type"].(string)
		received <- eventType
	}))
	defer webhookServer.Close()

	_, baseURL, cleanup := newTestServer(t, Config{APIKey: "key", WebhookSecret: "whsec_test"})
	defer cleanup()

	client := newAPIKeyClient(t, baseURL, "key")
	defer client.Close()

	hookURL := webhookServer.URL
	created, _ := client.CreateRequest(hax.CreateRequestParams{
		Type:       "text-approval-v1",
		Payload:    map[string]any{"text": "webhook events"},
		WebhookURL: &hookURL,
	})

	// 1. Open the request URL → "request.opened"
	http.Get(hubURL(baseURL, "/hub/r/"+created.ID))
	select {
	case et := <-received:
		if et != "request.opened" {
			t.Errorf("event 1 = %q, want %q", et, "request.opened")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("opened webhook not received")
	}

	// 2. Cancel the request → "request.cancelled"
	client.CancelRequest(created.ID)
	select {
	case et := <-received:
		if et != "request.cancelled" {
			t.Errorf("event 2 = %q, want %q", et, "request.cancelled")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancelled webhook not received")
	}
}

// --- Test for form field description/defaultValue/checkboxLabel ---

func TestFormFieldOptions(t *testing.T) {
	_, baseURL, cleanup := newTestServer(t, Config{APIKey: "key"})
	defer cleanup()

	client := newAPIKeyClient(t, baseURL, "key")
	defer client.Close()

	form := hax.NewFormBuilder().
		Title("Test Options").
		Input("name", map[string]any{
			"label":        "Name",
			"description":  "Your full legal name",
			"defaultValue":  "John Doe",
			"required":      true,
		}).
		Checkbox("agree", map[string]any{
			"checkboxLabel": "I agree to the terms",
			"description":    "You must agree to continue",
		}).
		Switch("notify", map[string]any{
			"switchLabel":  "Send me notifications",
			"defaultValue":  true,
		})

	handle, err := client.CreateFormRequest(form, hax.CreateRequestParams{})
	if err != nil {
		t.Fatalf("CreateFormRequest: %v", err)
	}

	// Fetch the HTML and verify the options are rendered.
	resp, err := http.Get(hubURL(baseURL, "/hub/r/"+handle.ID()))
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	html := string(body)
	if !strings.Contains(html, "Your full legal name") {
		t.Error("missing field description")
	}
	if !strings.Contains(html, "John Doe") {
		t.Error("missing defaultValue")
	}
	if !strings.Contains(html, "I agree to the terms") {
		t.Error("missing checkboxLabel")
	}
	if !strings.Contains(html, "Send me notifications") {
		t.Error("missing switchLabel")
	}
}
