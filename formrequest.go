package hax

import "time"

// FormRequestResponse is a typed response from a completed form request.
type FormRequestResponse struct {
	Values      *FormValues
	SubmittedAt *time.Time
	RespondedBy *string
	RespondedAt *string
}

// FormRequestStatus is the current status of a form request.
type FormRequestStatus struct {
	Status    string
	Completed bool
	Response  *FormRequestResponse
}

// FormRequestHandle is a handle for a form request with typed responses.
type FormRequestHandle struct {
	client *HaxClient
	id     string
	url    string
	form   *FormBuilder
}

// ID returns the request ID.
func (h *FormRequestHandle) ID() string { return h.id }

// URL returns the URL for a human to respond.
func (h *FormRequestHandle) URL() string { return h.url }

// WaitForResponse polls until the form is completed, expired, or cancelled.
func (h *FormRequestHandle) WaitForResponse(pollInterval, timeout float64) (*FormRequestResponse, error) {
	result, err := h.client.WaitForResponse(h.id, pollInterval, timeout)
	if err != nil {
		return nil, err
	}

	return h.buildResponse(result), nil
}

// GetStatus returns the current status of the form request.
func (h *FormRequestHandle) GetStatus() (*FormRequestStatus, error) {
	result, err := h.client.GetRequest(h.id)
	if err != nil {
		return nil, err
	}

	completed := result.IsCompleted()

	var response *FormRequestResponse
	if completed && result.Response != nil {
		response = h.buildResponse(result)
	}

	return &FormRequestStatus{
		Status:    string(result.Status),
		Completed: completed,
		Response:  response,
	}, nil
}

func (h *FormRequestHandle) buildResponse(result *Request) *FormRequestResponse {
	var submittedAt *time.Time
	if result.Response != nil {
		if meta, ok := result.Response["meta"].(map[string]any); ok {
			if s, ok := meta["submittedAt"].(string); ok {
				if t, ok := parseTimestamp(s); ok {
					submittedAt = &t
				}
			}
		}
	}

	var respondedBy *string
	if result.RespondedBy != nil {
		respondedBy = result.RespondedBy
	}

	var respondedAt *string
	if result.RespondedAt != nil {
		respondedAt = result.RespondedAt
	}

	return &FormRequestResponse{
		Values:      h.form.ParseResponse(result.Response),
		SubmittedAt: submittedAt,
		RespondedBy: respondedBy,
		RespondedAt: respondedAt,
	}
}

func parseTimestamp(s string) (time.Time, bool) {
	formats := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02T15:04:05.000Z",
		"2006-01-02T15:04:05Z",
	}
	for _, f := range formats {
		if t, err := time.Parse(f, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}
