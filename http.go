package hax

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const defaultTimeout = 30.0

const userAgent = "hax-go-sdk/0.2.8"

// Signer signs a request with DID headers.
// Returns extra headers to add to the request.
type Signer func(method, htu string, rawBody []byte) (map[string]string, error)

// HttpClient is the HTTP client wrapper with authentication and error handling.
type HttpClient struct {
	apiKey  string
	baseURL string
	signer  Signer
	client  *http.Client
}

// NewHttpClient creates a new HTTP client.
func NewHttpClient(baseURL string, apiKey string, timeout float64, signer Signer) *HttpClient {
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	return &HttpClient{
		apiKey:  apiKey,
		baseURL: strings.TrimRight(baseURL, "/"),
		signer:  signer,
		client: &http.Client{
			Timeout: time.Duration(timeout * float64(time.Second)),
		},
	}
}

// htuPath returns the URL path (including the /api/v1 prefix) the signature binds to.
func (c *HttpClient) htuPath(path string) string {
	u, err := url.Parse(c.baseURL + path)
	if err != nil {
		return c.baseURL + path
	}
	return u.Path
}

func (c *HttpClient) doRequest(method, path string, body map[string]any, params map[string]any) (map[string]any, error) {
	// Serialize the body exactly once so the hashed bytes == the sent bytes.
	var rawBody []byte
	if body != nil {
		var err error
		rawBody, err = compactJSON(body)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize request body: %w", err)
		}
	} else {
		rawBody = []byte{}
	}

	// Build the URL with query params.
	fullURL := c.baseURL + path
	if len(params) > 0 {
		vals := url.Values{}
		for k, v := range params {
			vals.Set(k, fmt.Sprintf("%v", v))
		}
		fullURL += "?" + vals.Encode()
	}

	req, err := http.NewRequest(method, fullURL, bytes.NewReader(rawBody))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)

	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	// Sign the request if a signer is present.
	if c.signer != nil {
		htu := c.htuPath(path)
		headers, err := c.signer(method, htu, rawBody)
		if err != nil {
			return nil, fmt.Errorf("failed to sign request: %w", err)
		}
		for k, v := range headers {
			req.Header.Set(k, v)
		}
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, c.handleErrorResponse(resp, respBody)
	}

	if len(respBody) == 0 {
		return nil, nil
	}

	var result map[string]any
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return result, nil
}

func (c *HttpClient) handleErrorResponse(resp *http.Response, body []byte) error {
	var data map[string]any
	message := resp.Status
	var details map[string]any

	if err := json.Unmarshal(body, &data); err == nil {
		if m, ok := data["error"].(string); ok {
			message = m
		}
		if d, ok := data["details"].(map[string]any); ok {
			details = d
		}
	}

	status := resp.StatusCode

	switch {
	case status == 401:
		return authenticationError(message, details)
	case status == 403:
		return forbiddenError(message, details)
	case status == 404:
		return notFoundError(message, details)
	case status == 422:
		return validationError(message, details)
	case status == 429:
		retryAfter := 0
		if ra := resp.Header.Get("Retry-After"); ra != "" {
			if n, err := parseInt(ra); err == nil {
				retryAfter = n
			}
		}
		return rateLimitError(message, retryAfter, details)
	case status >= 500:
		return serverError(message, status, details)
	default:
		return newHaxError(fmt.Sprintf("HTTP %d: %s", status, message), details, status)
	}
}

// Get makes a GET request (empty body — signed over empty bytes).
func (c *HttpClient) Get(path string, params map[string]any) (map[string]any, error) {
	return c.doRequest("GET", path, nil, params)
}

// Post makes a POST request.
func (c *HttpClient) Post(path string, body map[string]any) (map[string]any, error) {
	return c.doRequest("POST", path, body, nil)
}

// Patch makes a PATCH request.
func (c *HttpClient) Patch(path string, body map[string]any) (map[string]any, error) {
	return c.doRequest("PATCH", path, body, nil)
}

// Delete makes a DELETE request (empty body — signed over empty bytes).
func (c *HttpClient) Delete(path string) (map[string]any, error) {
	return c.doRequest("DELETE", path, nil, nil)
}

// Close closes the HTTP client.
func (c *HttpClient) Close() {
	// net/http.Client doesn't need explicit closing.
}

func parseInt(s string) (int, error) {
	var n int
	_, err := fmt.Sscanf(s, "%d", &n)
	return n, err
}
