package hax

import "encoding/json"

// RequestStatus represents the status of a HAX request.
type RequestStatus string

const (
	StatusPending   RequestStatus = "pending"
	StatusOpened    RequestStatus = "opened"
	StatusCompleted RequestStatus = "completed"
	StatusExpired   RequestStatus = "expired"
	StatusCancelled RequestStatus = "cancelled"
	StatusHeld      RequestStatus = "held"
)

// SenderManifest attributes a request to a sender and groups related
// requests into one saga (thread).
type SenderManifest struct {
	Key         string  `json:"key"`
	DisplayName *string `json:"displayName,omitempty"`
	Description *string `json:"description,omitempty"`
	Icon        *string `json:"icon,omitempty"`
	ThreadBy    *string `json:"threadBy,omitempty"`
	DiscussURL  *string `json:"discussUrl,omitempty"`
	Project     *string `json:"project,omitempty"`
}

// DeliveryConfig configures delivery of a request URL via email or SMS.
type DeliveryConfig struct {
	Channel   string  `json:"channel"`
	Recipient string  `json:"recipient"`
	Subject   *string `json:"subject,omitempty"`
	Message   *string `json:"message,omitempty"`
}

// DeliveryResult is the result of a delivery attempt.
type DeliveryResult struct {
	Success bool   `json:"success"`
	Channel string `json:"channel"`
	Error   string `json:"error,omitempty"`
}

// CreatedRequest is the response from creating a request.
type CreatedRequest struct {
	ID           string          `json:"id"`
	URL          string          `json:"url"`
	Type         string          `json:"type"`
	Title        *string         `json:"title,omitempty"`
	Description  *string         `json:"description,omitempty"`
	Payload      map[string]any  `json:"payload"`
	Metadata     map[string]any  `json:"metadata,omitempty"`
	WebhookURL   *string         `json:"webhookUrl,omitempty"`
	Status       RequestStatus   `json:"status"`
	CreatedAt    string          `json:"createdAt"`
	ExpiresAt    *string         `json:"expiresAt,omitempty"`
	UserID       *string         `json:"userId,omitempty"`
	SenderID     *string         `json:"senderId,omitempty"`
	ThreadID     *string         `json:"threadId,omitempty"`
	SenderStatus *string         `json:"senderStatus,omitempty"`
	Delivery     *DeliveryResult `json:"delivery,omitempty"`
}

func (r *CreatedRequest) IsHeld() bool      { return r.Status == StatusHeld }
func (r *CreatedRequest) IsPending() bool   { return r.Status == StatusPending }
func (r *CreatedRequest) IsOpened() bool    { return r.Status == StatusOpened }
func (r *CreatedRequest) IsCompleted() bool { return r.Status == StatusCompleted }
func (r *CreatedRequest) IsExpired() bool   { return r.Status == StatusExpired }
func (r *CreatedRequest) IsCancelled() bool { return r.Status == StatusCancelled }

// RequestSummary is minimal request info returned from the list endpoint.
type RequestSummary struct {
	ID        string        `json:"id"`
	Type      string        `json:"type"`
	Status    RequestStatus `json:"status"`
	CreatedAt string        `json:"createdAt"`
}

// Request is the full request model with all fields.
type Request struct {
	ID          string         `json:"id"`
	WorkspaceID string         `json:"workspaceId"`
	Type        string         `json:"type"`
	Title       *string        `json:"title,omitempty"`
	Description *string        `json:"description,omitempty"`
	Payload     map[string]any `json:"payload"`
	Metadata    map[string]any `json:"metadata,omitempty"`
	Status      RequestStatus  `json:"status"`
	ExpiresAt   *string        `json:"expiresAt,omitempty"`
	Response    map[string]any `json:"response,omitempty"`
	RespondedBy *string        `json:"respondedBy,omitempty"`
	RespondedAt *string        `json:"respondedAt,omitempty"`
	WebhookURL  *string        `json:"webhookUrl,omitempty"`
	OpenedAt    *string        `json:"openedAt,omitempty"`
	UserID      *string        `json:"userId,omitempty"`
	SenderID    *string        `json:"senderId,omitempty"`
	ThreadID    *string        `json:"threadId,omitempty"`
	CreatedAt   string         `json:"createdAt"`
	UpdatedAt   string         `json:"updatedAt"`

	baseURL string
}

// SetBaseURL sets the base URL for generating request URLs.
func (r *Request) SetBaseURL(baseURL string) {
	r.baseURL = stripAPIPath(baseURL)
}

// URL returns the URL for a human to respond to this request.
func (r *Request) URL() string {
	if r.baseURL != "" {
		return r.baseURL + "/hub/r/" + r.ID
	}
	return "/hub/r/" + r.ID
}

func (r *Request) IsHeld() bool      { return r.Status == StatusHeld }
func (r *Request) IsPending() bool   { return r.Status == StatusPending }
func (r *Request) IsOpened() bool    { return r.Status == StatusOpened }
func (r *Request) IsCompleted() bool { return r.Status == StatusCompleted }
func (r *Request) IsExpired() bool   { return r.Status == StatusExpired }
func (r *Request) IsCancelled() bool { return r.Status == StatusCancelled }

// VerifiableCredential returns the verifiable credential from the response
// if present.
func (r *Request) VerifiableCredential() map[string]any {
	if r.Response != nil {
		if vc, ok := r.Response["vc"].(map[string]any); ok {
			return vc
		}
	}
	return nil
}

// stripAPIPath removes trailing slash and the /api/v1 suffix from a base URL.
func stripAPIPath(baseURL string) string {
	s := baseURL
	for len(s) > 0 && s[len(s)-1] == '/' {
		s = s[:len(s)-1]
	}
	const suffix = "/api/v1"
	if len(s) > len(suffix) && s[len(s)-len(suffix):] == suffix {
		s = s[:len(s)-len(suffix)]
	}
	return s
}

// marshalJSON returns compact JSON bytes without HTML escaping.
func marshalJSON(v any) ([]byte, error) {
	return json.Marshal(v)
}
