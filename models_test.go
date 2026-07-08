package hax

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSenderSnakeCaseNormalized(t *testing.T) {
	var capturedBody []byte

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedBody, _ = readBody(r)
		writeJSON(w, createdResponse())
	}))
	defer server.Close()

	client, err := NewClient(ClientOptions{
		APIKey:  "test_key",
		BaseURL: server.URL + "/api/v1",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	_, err = client.CreateRequest(CreateRequestParams{
		Type:    "text-approval-v1",
		Payload: map[string]any{"text": "Approve?"},
		Sender: map[string]any{
			"key":          "pr-bot",
			"display_name": "PR Bot",
			"thread_by":    "pr",
			"discuss_url":  "https://example.com/discuss",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	var body map[string]any
	if err := json.Unmarshal(capturedBody, &body); err != nil {
		t.Fatal(err)
	}

	sender := body["sender"].(map[string]any)
	if sender["key"] != "pr-bot" {
		t.Fatalf("expected key pr-bot, got %v", sender["key"])
	}
	if sender["displayName"] != "PR Bot" {
		t.Fatalf("expected displayName PR Bot, got %v", sender["displayName"])
	}
	if sender["threadBy"] != "pr" {
		t.Fatalf("expected threadBy pr, got %v", sender["threadBy"])
	}
	if sender["discussUrl"] != "https://example.com/discuss" {
		t.Fatalf("expected discussUrl, got %v", sender["discussUrl"])
	}
}

func TestSenderCamelCasePassThrough(t *testing.T) {
	var capturedBody []byte

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedBody, _ = readBody(r)
		writeJSON(w, createdResponse())
	}))
	defer server.Close()

	client, err := NewClient(ClientOptions{
		APIKey:  "test_key",
		BaseURL: server.URL + "/api/v1",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	_, err = client.CreateRequest(CreateRequestParams{
		Type:    "text-approval-v1",
		Payload: map[string]any{"text": "Approve?"},
		Sender: map[string]any{
			"key":         "pr-bot",
			"displayName": "PR Bot",
			"threadBy":    "pr",
			"discussUrl":  "https://example.com/discuss",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	var body map[string]any
	json.Unmarshal(capturedBody, &body)
	sender := body["sender"].(map[string]any)
	if sender["displayName"] != "PR Bot" {
		t.Fatalf("expected displayName, got %v", sender["displayName"])
	}
}

func TestSenderManifestModelSerialized(t *testing.T) {
	var capturedBody []byte

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedBody, _ = readBody(r)
		writeJSON(w, createdResponse())
	}))
	defer server.Close()

	client, err := NewClient(ClientOptions{
		APIKey:  "test_key",
		BaseURL: server.URL + "/api/v1",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	threadBy := "pr"
	_, err = client.CreateRequest(CreateRequestParams{
		Type:    "text-approval-v1",
		Payload: map[string]any{"text": "Approve?"},
		Sender: &SenderManifest{
			Key:      "pr-bot",
			ThreadBy: &threadBy,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	var body map[string]any
	json.Unmarshal(capturedBody, &body)
	sender := body["sender"].(map[string]any)
	if sender["key"] != "pr-bot" {
		t.Fatalf("expected key, got %v", sender["key"])
	}
	if sender["threadBy"] != "pr" {
		t.Fatalf("expected threadBy, got %v", sender["threadBy"])
	}
	if _, exists := sender["displayName"]; exists {
		t.Fatal("displayName should not be present (omitempty)")
	}
}

func TestSenderProjectDictSent(t *testing.T) {
	var capturedBody []byte

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedBody, _ = readBody(r)
		writeJSON(w, createdResponse())
	}))
	defer server.Close()

	client, err := NewClient(ClientOptions{
		APIKey:  "test_key",
		BaseURL: server.URL + "/api/v1",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	_, err = client.CreateRequest(CreateRequestParams{
		Type:    "text-approval-v1",
		Payload: map[string]any{"text": "Approve?"},
		Sender: map[string]any{
			"key":     "pr-bot",
			"project": "Engineering",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	var body map[string]any
	json.Unmarshal(capturedBody, &body)
	sender := body["sender"].(map[string]any)
	if sender["project"] != "Engineering" {
		t.Fatalf("expected project Engineering, got %v", sender["project"])
	}
}

func TestCreatedRequestExposesSagaFields(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{
			"id":           "req_123",
			"url":          "https://hax.example.com/hub/r/req_123",
			"type":         "text-approval-v1",
			"payload":      map[string]any{"text": "Approve?"},
			"status":       "pending",
			"createdAt":    "2024-01-15T10:00:00Z",
			"senderId":     "snd_1",
			"threadId":     "thr_1",
			"senderStatus": "active",
		})
	}))
	defer server.Close()

	client, err := NewClient(ClientOptions{
		APIKey:  "test_key",
		BaseURL: server.URL + "/api/v1",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	created, err := client.CreateRequest(CreateRequestParams{
		Type:    "text-approval-v1",
		Payload: map[string]any{"text": "Approve?"},
		Sender:  map[string]any{"key": "pr-bot"},
	})
	if err != nil {
		t.Fatal(err)
	}

	if created.SenderID == nil || *created.SenderID != "snd_1" {
		t.Fatalf("expected senderId snd_1, got %v", created.SenderID)
	}
	if created.ThreadID == nil || *created.ThreadID != "thr_1" {
		t.Fatalf("expected threadId thr_1, got %v", created.ThreadID)
	}
	if created.SenderStatus == nil || *created.SenderStatus != "active" {
		t.Fatalf("expected senderStatus active, got %v", created.SenderStatus)
	}
}

func TestGetRequestParsesSenderAndThreadIDs(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{
			"request": map[string]any{
				"id":          "req_123",
				"workspaceId": "proj_1",
				"type":        "text-approval-v1",
				"payload":     map[string]any{"text": "Approve?"},
				"status":      "pending",
				"senderId":    "snd_1",
				"threadId":    "thr_1",
				"createdAt":   "2024-01-15T10:00:00Z",
				"updatedAt":   "2024-01-15T10:00:00Z",
			},
		})
	}))
	defer server.Close()

	client, err := NewClient(ClientOptions{
		APIKey:  "test_key",
		BaseURL: server.URL + "/api/v1",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	req, err := client.GetRequest("req_123")
	if err != nil {
		t.Fatal(err)
	}

	if req.SenderID == nil || *req.SenderID != "snd_1" {
		t.Fatalf("expected senderId snd_1, got %v", req.SenderID)
	}
	if req.ThreadID == nil || *req.ThreadID != "thr_1" {
		t.Fatalf("expected threadId thr_1, got %v", req.ThreadID)
	}
}

func TestSagaFieldsDefaultToNil(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{
			"request": map[string]any{
				"id":          "req_123",
				"workspaceId": "proj_1",
				"type":        "text-approval-v1",
				"payload":     map[string]any{"text": "Approve?"},
				"status":      "pending",
				"createdAt":   "2024-01-15T10:00:00Z",
				"updatedAt":   "2024-01-15T10:00:00Z",
			},
		})
	}))
	defer server.Close()

	client, err := NewClient(ClientOptions{
		APIKey:  "test_key",
		BaseURL: server.URL + "/api/v1",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	req, err := client.GetRequest("req_123")
	if err != nil {
		t.Fatal(err)
	}

	if req.SenderID != nil {
		t.Fatalf("expected nil senderId, got %v", *req.SenderID)
	}
	if req.ThreadID != nil {
		t.Fatalf("expected nil threadId, got %v", *req.ThreadID)
	}
}

func TestHeldStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{
			"id":           "req_123",
			"url":          "https://hax.example.com/hub/r/req_123",
			"type":         "text-approval-v1",
			"payload":      map[string]any{"text": "Approve?"},
			"status":       "held",
			"createdAt":    "2024-01-15T10:00:00Z",
			"senderStatus": "needs_review",
		})
	}))
	defer server.Close()

	client, err := NewClient(ClientOptions{
		APIKey:  "test_key",
		BaseURL: server.URL + "/api/v1",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	created, err := client.CreateRequest(CreateRequestParams{
		Type:    "text-approval-v1",
		Payload: map[string]any{"text": "Approve?"},
	})
	if err != nil {
		t.Fatal(err)
	}

	if created.Status != StatusHeld {
		t.Fatalf("expected status held, got %s", created.Status)
	}
	if !created.IsHeld() {
		t.Fatal("expected IsHeld to be true")
	}
	if created.IsPending() {
		t.Fatal("expected IsPending to be false")
	}
}

func TestRequestURL(t *testing.T) {
	req := &Request{ID: "req_123"}
	req.SetBaseURL("https://hax.example.com/api/v1")
	expected := "https://hax.example.com/hub/r/req_123"
	if req.URL() != expected {
		t.Fatalf("expected URL %s, got %s", expected, req.URL())
	}
}

func TestRequestURLNoBaseURL(t *testing.T) {
	req := &Request{ID: "req_123"}
	if req.URL() != "/hub/r/req_123" {
		t.Fatalf("expected /hub/r/req_123, got %s", req.URL())
	}
}

func TestDeliveryEmailConfig(t *testing.T) {
	var capturedBody []byte

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedBody, _ = readBody(r)
		writeJSON(w, createdResponse())
	}))
	defer server.Close()

	client, err := NewClient(ClientOptions{
		APIKey:  "test_key",
		BaseURL: server.URL + "/api/v1",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	subject := "Test Subject"
	message := "Custom message"
	_, err = client.CreateRequest(CreateRequestParams{
		Type:    "confirm-action-v1",
		Payload: map[string]any{"title": "Test"},
		Delivery: &DeliveryConfig{
			Channel:   "email",
			Recipient: "test@example.com",
			Subject:   &subject,
			Message:   &message,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	var body map[string]any
	json.Unmarshal(capturedBody, &body)
	delivery := body["delivery"].(map[string]any)
	if delivery["channel"] != "email" {
		t.Fatalf("expected channel email, got %v", delivery["channel"])
	}
	if delivery["recipient"] != "test@example.com" {
		t.Fatalf("expected recipient, got %v", delivery["recipient"])
	}
	if delivery["subject"] != "Test Subject" {
		t.Fatalf("expected subject, got %v", delivery["subject"])
	}
}

func TestRequestViaEmail(t *testing.T) {
	var capturedBody []byte

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedBody, _ = readBody(r)
		writeJSON(w, createdResponse())
	}))
	defer server.Close()

	client, err := NewClient(ClientOptions{
		APIKey:  "test_key",
		BaseURL: server.URL + "/api/v1",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	subject := "Custom Subject"
	_, err = client.RequestViaEmail(CreateRequestParams{
		Type:    "confirm-action-v1",
		Payload: map[string]any{"title": "Test"},
	}, "user@example.com", &subject, nil)
	if err != nil {
		t.Fatal(err)
	}

	var body map[string]any
	json.Unmarshal(capturedBody, &body)
	delivery := body["delivery"].(map[string]any)
	if delivery["channel"] != "email" {
		t.Fatalf("expected channel email, got %v", delivery["channel"])
	}
	if delivery["recipient"] != "user@example.com" {
		t.Fatalf("expected recipient, got %v", delivery["recipient"])
	}
	if delivery["subject"] != "Custom Subject" {
		t.Fatalf("expected subject, got %v", delivery["subject"])
	}
}

func TestRequestViaSMS(t *testing.T) {
	var capturedBody []byte

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedBody, _ = readBody(r)
		writeJSON(w, createdResponse())
	}))
	defer server.Close()

	client, err := NewClient(ClientOptions{
		APIKey:  "test_key",
		BaseURL: server.URL + "/api/v1",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	_, err = client.RequestViaSMS(CreateRequestParams{
		Type:    "confirm-action-v1",
		Payload: map[string]any{"title": "Test"},
	}, "+15551234567", nil)
	if err != nil {
		t.Fatal(err)
	}

	var body map[string]any
	json.Unmarshal(capturedBody, &body)
	delivery := body["delivery"].(map[string]any)
	if delivery["channel"] != "sms" {
		t.Fatalf("expected channel sms, got %v", delivery["channel"])
	}
	if delivery["recipient"] != "+15551234567" {
		t.Fatalf("expected recipient, got %v", delivery["recipient"])
	}
}

func TestWaitForAcceptanceReturnsActive(t *testing.T) {
	identity, _ := GenerateIdentity()

	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		status := "pending"
		if callCount >= 2 {
			status = "active"
		}
		writeJSON(w, map[string]any{"status": status})
	}))
	defer server.Close()

	client, err := NewClient(ClientOptions{
		BaseURL: server.URL + "/api/v1",
		DID:     identity.DID,
		PrivateKeyJWK: identity.PrivateKeyJWK,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	result, err := client.WaitForAcceptance("acme", "", 5.0, 0.0)
	if err != nil {
		t.Fatal(err)
	}
	if result != "active" {
		t.Fatalf("expected active, got %s", result)
	}
}

func TestWaitForAcceptanceReturnsBlocked(t *testing.T) {
	identity, _ := GenerateIdentity()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"status": "blocked"})
	}))
	defer server.Close()

	client, err := NewClient(ClientOptions{
		BaseURL: server.URL + "/api/v1",
		DID:     identity.DID,
		PrivateKeyJWK: identity.PrivateKeyJWK,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	result, err := client.WaitForAcceptance("acme", "", 5.0, 0.0)
	if err != nil {
		t.Fatal(err)
	}
	if result != "blocked" {
		t.Fatalf("expected blocked, got %s", result)
	}
}

// --- helpers ---

func readBody(r *http.Request) ([]byte, error) {
	return io.ReadAll(r.Body)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func createdResponse() map[string]any {
	return map[string]any{
		"id":        "req_123",
		"url":       "https://hax.example.com/hub/r/req_123",
		"type":      "confirm-action-v1",
		"payload":   map[string]any{"title": "Test"},
		"status":    "pending",
		"createdAt": "2024-01-15T10:00:00Z",
	}
}
