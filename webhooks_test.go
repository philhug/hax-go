package hax

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func TestVerifySignatureValid(t *testing.T) {
	secret := "whsec_test_secret"
	payload := []byte(`{"type":"request.completed","data":{}}`)

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	expected := hex.EncodeToString(mac.Sum(nil))
	signature := "sha256=" + expected

	if !VerifySignature(payload, signature, secret) {
		t.Fatal("valid signature should be accepted")
	}
}

func TestVerifySignatureInvalid(t *testing.T) {
	secret := "whsec_test_secret"
	payload := []byte(`{"type":"request.completed"}`)
	signature := "sha256=invalid_signature_here"

	if VerifySignature(payload, signature, secret) {
		t.Fatal("invalid signature should be rejected")
	}
}

func TestVerifySignatureWrongPrefix(t *testing.T) {
	secret := "whsec_test_secret"
	payload := []byte(`{"type":"request.completed"}`)
	signature := "md5=some_hash"

	if VerifySignature(payload, signature, secret) {
		t.Fatal("wrong prefix should be rejected")
	}
}

func TestVerifySignatureEmpty(t *testing.T) {
	secret := "whsec_test_secret"
	payload := []byte(`{"type":"request.completed"}`)
	signature := ""

	if VerifySignature(payload, signature, secret) {
		t.Fatal("empty signature should be rejected")
	}
}

func TestVerifySignatureTamperedPayload(t *testing.T) {
	secret := "whsec_test_secret"
	original := []byte(`{"type":"request.completed","amount":100}`)
	tampered := []byte(`{"type":"request.completed","amount":1000}`)

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(original)
	signature := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	if VerifySignature(tampered, signature, secret) {
		t.Fatal("tampered payload should be rejected")
	}
}

func TestSignPayload(t *testing.T) {
	secret := "whsec_test_secret"
	payload := map[string]any{"type": "request.completed", "data": map[string]any{"id": "123"}}

	signature, err := SignPayload(payload, secret)
	if err != nil {
		t.Fatal(err)
	}

	if !startsWith(signature, "sha256=") {
		t.Fatalf("signature should start with sha256=: %s", signature)
	}
	if len(signature) != 7+64 {
		t.Fatalf("expected signature length %d, got %d", 7+64, len(signature))
	}
}

func TestSignAndVerifyRoundtrip(t *testing.T) {
	secret := "whsec_test_secret"
	payload := map[string]any{"type": "request.completed", "data": map[string]any{"id": "123"}}

	signature, err := SignPayload(payload, secret)
	if err != nil {
		t.Fatal(err)
	}

	payloadBytes, err := compactJSON(payload)
	if err != nil {
		t.Fatal(err)
	}

	if !VerifySignature(payloadBytes, signature, secret) {
		t.Fatal("signed payload should verify")
	}
}

func TestDeterministicSigning(t *testing.T) {
	secret := "whsec_test_secret"
	payload := map[string]any{"a": float64(1), "b": float64(2)}

	sig1, err := SignPayload(payload, secret)
	if err != nil {
		t.Fatal(err)
	}
	sig2, err := SignPayload(payload, secret)
	if err != nil {
		t.Fatal(err)
	}

	if sig1 != sig2 {
		t.Fatal("signing should be deterministic")
	}
}

func TestParseEventBytes(t *testing.T) {
	payload := sampleWebhookPayload()
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}

	event, err := ParseEvent(payloadBytes, nil)
	if err != nil {
		t.Fatal(err)
	}

	if event.Type != "request.completed" {
		t.Fatalf("expected type request.completed, got %s", event.Type)
	}
	if event.Timestamp != "2024-01-01T01:00:00Z" {
		t.Fatalf("expected timestamp 2024-01-01T01:00:00Z, got %s", event.Timestamp)
	}
}

func TestParseEventString(t *testing.T) {
	payload := sampleWebhookPayload()
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}

	event, err := ParseEvent(payloadBytes, nil)
	if err != nil {
		t.Fatal(err)
	}

	if event.Type != "request.completed" {
		t.Fatalf("expected type request.completed, got %s", event.Type)
	}
}

func TestWebhookEventEventType(t *testing.T) {
	payload := sampleWebhookPayload()
	payloadBytes, _ := json.Marshal(payload)
	event, err := ParseEvent(payloadBytes, nil)
	if err != nil {
		t.Fatal(err)
	}

	if event.Type != "request.completed" {
		t.Fatalf("expected type request.completed, got %s", event.Type)
	}
	if event.EventType() != "completed" {
		t.Fatalf("expected event_type completed, got %s", event.EventType())
	}
}

func TestWebhookEventEventTypeWithoutPrefix(t *testing.T) {
	payload := map[string]any{
		"type":      "custom_event",
		"timestamp": "2024-01-01T00:00:00Z",
		"data":      map[string]any{"id": "123"},
	}
	payloadBytes, _ := json.Marshal(payload)
	event, err := ParseEvent(payloadBytes, nil)
	if err != nil {
		t.Fatal(err)
	}

	if event.EventType() != "custom_event" {
		t.Fatalf("expected event_type custom_event, got %s", event.EventType())
	}
}

func TestWebhookEventRequestID(t *testing.T) {
	payload := sampleWebhookPayload()
	payloadBytes, _ := json.Marshal(payload)
	event, err := ParseEvent(payloadBytes, nil)
	if err != nil {
		t.Fatal(err)
	}

	if event.RequestID() != "req_abc123" {
		t.Fatalf("expected request_id req_abc123, got %s", event.RequestID())
	}
}

func TestWebhookEventRequest(t *testing.T) {
	payload := sampleWebhookPayload()
	payloadBytes, _ := json.Marshal(payload)
	event, err := ParseEvent(payloadBytes, nil)
	if err != nil {
		t.Fatal(err)
	}

	req := event.Request()
	if req.ID != "req_abc123" {
		t.Fatalf("expected request id req_abc123, got %s", req.ID)
	}
	if req.Type != "text-approval-v1" {
		t.Fatalf("expected type text-approval-v1, got %s", req.Type)
	}
	if req.Status != StatusCompleted {
		t.Fatalf("expected status completed, got %s", req.Status)
	}
}

func TestWebhookEventMetadata(t *testing.T) {
	payload := sampleWebhookPayload()
	payloadBytes, _ := json.Marshal(payload)
	event, err := ParseEvent(payloadBytes, nil)
	if err != nil {
		t.Fatal(err)
	}

	meta := event.Metadata()
	if meta["source"] != "test" {
		t.Fatalf("expected metadata source test, got %v", meta["source"])
	}
}

func TestWebhookEventResponse(t *testing.T) {
	payload := sampleWebhookPayload()
	payloadBytes, _ := json.Marshal(payload)
	event, err := ParseEvent(payloadBytes, nil)
	if err != nil {
		t.Fatal(err)
	}

	resp := event.Response()
	if resp["decision"] != "approve" {
		t.Fatalf("expected response decision approve, got %v", resp["decision"])
	}
}

func TestWebhookEventResponseNoneForNonCompleted(t *testing.T) {
	payload := map[string]any{
		"type":      "request.opened",
		"timestamp": "2024-01-01T00:00:00Z",
		"data": map[string]any{
			"id":     "req_123",
			"type":   "text-approval-v1",
			"status": "opened",
		},
	}
	payloadBytes, _ := json.Marshal(payload)
	event, err := ParseEvent(payloadBytes, nil)
	if err != nil {
		t.Fatal(err)
	}

	if event.Response() != nil {
		t.Fatal("response should be nil for non-completed events")
	}
}

func TestWebhookAllEventTypes(t *testing.T) {
	eventTypes := []string{"request.sent", "request.opened", "request.completed", "request.expired"}

	for _, et := range eventTypes {
		payload := map[string]any{
			"type":      et,
			"timestamp": "2024-01-01T00:00:00Z",
			"data": map[string]any{
				"id":        "req_123",
				"type":      "text-approval-v1",
				"status":    et[strings.LastIndex(et, ".")+1:],
				"createdAt": "2024-01-01T00:00:00Z",
				"updatedAt": "2024-01-01T00:00:00Z",
				"payload":   map[string]any{},
			},
		}
		payloadBytes, _ := json.Marshal(payload)
		event, err := ParseEvent(payloadBytes, nil)
		if err != nil {
			t.Fatal(err)
		}
		if event.Type != et {
			t.Fatalf("expected type %s, got %s", et, event.Type)
		}
	}
}

func startsWith(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

func sampleWebhookPayload() map[string]any {
	return map[string]any{
		"type":      "request.completed",
		"timestamp": "2024-01-01T01:00:00Z",
		"data": map[string]any{
			"id":          "req_abc123",
			"workspaceId": "proj_xyz789",
			"type":        "text-approval-v1",
			"status":      "completed",
			"metadata":    map[string]any{"source": "test"},
			"response":    map[string]any{"decision": "approve"},
			"respondedBy": "user_123",
			"respondedAt": "2024-01-01T01:00:00Z",
			"createdAt":   "2024-01-01T00:00:00Z",
			"updatedAt":   "2024-01-01T01:00:00Z",
			"payload":     map[string]any{"text": "Approve?"},
		},
	}
}
