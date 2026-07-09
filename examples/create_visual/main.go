package main

import (
	"fmt"
	"os"

	hax "github.com/philhug/hax-go"
)

func main() {
	baseURL := "http://localhost:9090/api/v1"
	apiKey := "demo-key"

	client, err := hax.NewClient(hax.ClientOptions{
		BaseURL: baseURL,
		APIKey:  apiKey,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "NewClient:", err)
		os.Exit(1)
	}
	defer client.Close()

	// 1. Plan review (plan-review-v2)
	planReq, _ := client.CreateRequest(hax.CreateRequestParams{
		Type:    "plan-review-v2",
		Title:   hax.StringPtr("SWE-AF Plan Review"),
		Description: hax.StringPtr("Review the proposed implementation plan before execution begins"),
		Payload: map[string]any{
			"planSummary": "Add OAuth2 authentication to the API gateway using PKCE flow. The plan includes 3 issues: add auth middleware, create token endpoint, and update existing routes to require auth.",
			"prd": "## Description\nAdd OAuth2 PKCE authentication to protect API endpoints.\n\n## Must Have\n- Token endpoint at /oauth/token\n- Auth middleware validating JWTs\n- All /api routes require valid token\n\n## Acceptance Criteria\n- Unauthenticated requests return 401\n- Token expiry returns 403\n- Token refresh works",
			"architecture": "## Summary\nPKCE flow with RS256 signing.\n\n## Components\n### AuthMiddleware\nValidates JWT bearer tokens on every request. Files: `internal/middleware/auth.go`\n\n### TokenEndpoint\nIssues access and refresh tokens. Files: `internal/handlers/oauth.go`",
			"issues": []any{
				map[string]any{
					"name":        "add-auth-middleware",
					"title":       "Add JWT auth middleware",
					"description": "Create middleware that validates JWT bearer tokens",
					"dependsOn":    []string{},
					"filesToModify": []string{"internal/router.go"},
					"filesToCreate": []string{"internal/middleware/auth.go"},
					"acceptanceCriteria": []string{"Missing token returns 401", "Invalid token returns 401", "Valid token passes through"},
				},
				map[string]any{
					"name":        "create-token-endpoint",
					"title":       "Create OAuth token endpoint",
					"description": "POST /oauth/token that issues access + refresh tokens",
					"dependsOn":   []string{"add-auth-middleware"},
					"filesToCreate": []string{"internal/handlers/oauth.go"},
					"acceptanceCriteria": []string{"Returns 200 with token pair", "Rejects invalid client_id"},
				},
				map[string]any{
					"name":        "update-routes",
					"title":       "Update existing routes to require auth",
					"description": "Apply auth middleware to all /api routes",
					"dependsOn":    []string{"add-auth-middleware"},
					"filesToModify": []string{"internal/router.go", "internal/handlers/users.go"},
					"acceptanceCriteria": []string{"All /api routes return 401 without token"},
				},
			},
			"revisionNumber": 0,
		},
	})
	fmt.Printf("PLAN REVIEW (plan-review-v2):\n  %s\n\n", planReq.URL)

	// 2. PR-AF review (pr-af-review-v1)
	prafReq, _ := client.CreateRequest(hax.CreateRequestParams{
		Type:  "pr-af-review-v1",
		Title: hax.StringPtr("PR-AF Review Approval — sentry#67876"),
		Payload: map[string]any{
			"title":          "PR-AF Review Approval — sentry#67876",
			"intent":         "Add user-mismatch check to GitHub installation dispatch. The PR adds a check that verifies the authenticated user matches the sender metadata before proceeding with the installation flow.",
			"reviewSummary":   "PR-AF found 3 finding(s): 1 critical, 1 high, 1 medium.",
			"postLabel":       "Post Selected",
			"rerunLabel":      "Re-review with Instructions",
			"rejectLabel":     "Reject",
			"instructionsPlaceholder": "e.g. too aggressive, tone it down and drop the nitpicks",
			"findings": []any{
				map[string]any{
					"id":              "f1",
					"severity":        "critical",
					"title":           "KeyError on missing 'sender' in metadata",
					"defaultSelected": true,
					"filePath":        "src/sentry/integrations/github/integration.py",
					"lineStart":       503,
					"lineEnd":         505,
					"body":            "The user-mismatch check accesses `integration.metadata[\"sender\"][\"login\"]` without first verifying that the `\"sender\"` key exists. This raises an unhandled `KeyError` that escapes as a 500 error.",
					"suggestion":      "Add a guard: `if \"sender\" not in integration.metadata: return HttpResponse(status=404)`",
					"dimension":       "error-handling",
					"confidence":      0.95,
				},
				map[string]any{
					"id":              "f2",
					"severity":        "high",
					"title":           "Inconsistent fallback shape for destinationCalendar",
					"defaultSelected": true,
					"filePath":        "handleNewBooking.ts",
					"lineStart":       1063,
					"lineEnd":         1067,
					"body":            "BOOKING_CREATED uses `null` fallback while BOOKING_REJECTED uses `[]`. Subscribers parsing `destinationCalendar` must handle both shapes.",
					"dimension":       "api-consistency",
					"confidence":      0.88,
				},
				map[string]any{
					"id":              "f3",
					"severity":        "medium",
					"title":           "Test assertion locks in inconsistency",
					"defaultSelected": false,
					"filePath":        "webhook.e2e.ts",
					"lineStart":       119,
					"body":            "The e2e test asserts `destinationCalendar: null` for BOOKING_CREATED, locking in the divergent behavior rather than catching it.",
					"dimension":       "test-quality",
					"confidence":      0.72,
				},
			},
			"pr": map[string]any{
				"repo":    "getsentry/sentry",
				"number":  67876,
				"branch":  "fix/github-installation-user-check",
			},
		},
	})
	fmt.Printf("PR-AF REVIEW (pr-af-review-v1):\n  %s\n\n", prafReq.URL)

	// 3. Text approval
	approval, _ := client.CreateRequest(hax.CreateRequestParams{
		Type: "text-approval-v1",
		Title: hax.StringPtr("Deploy v2.0 to Production?"),
		Payload: map[string]any{
			"text":         "We've completed testing for v2.0. Shall we deploy to production?",
			"approveLabel": "Ship It",
			"denyLabel":    "Hold",
		},
	})
	fmt.Printf("TEXT APPROVAL:\n  %s\n\n", approval.URL)

	// 4. Job application form
	form := hax.NewFormBuilder().
		Title("Software Engineer Application").
		Description("Please fill out all fields.").
		SubmitLabel("Submit Application").
		Input("fullName", map[string]any{"label": "Full Name", "required": true, "placeholder": "Jane Doe"}).
		Input("email", map[string]any{"label": "Email", "variant": "email", "required": true}).
		Select("experience", map[string]any{
			"label": "Experience Level",
			"options": []any{
				map[string]any{"value": "junior", "label": "Junior (0-2 years)"},
				map[string]any{"value": "mid", "label": "Mid-level (3-5 years)"},
				map[string]any{"value": "senior", "label": "Senior (6-10 years)"},
			},
		}).
		RadioGroup("workMode", map[string]any{
			"label": "Work Arrangement",
			"options": []any{
				map[string]any{"value": "remote", "label": "Remote"},
				map[string]any{"value": "hybrid", "label": "Hybrid"},
				map[string]any{"value": "onsite", "label": "On-site"},
			},
		}).
		Number("salary", map[string]any{"label": "Salary Expectation (USD)", "min": 40000, "max": 500000, "step": 5000}).
		Slider("codingSkill", map[string]any{"label": "Self-rated Coding Skill", "min": 1, "max": 10}).
		CheckboxGroup("languages", map[string]any{
			"label": "Languages",
			"options": []any{
				map[string]any{"value": "go", "label": "Go"},
				map[string]any{"value": "python", "label": "Python"},
				map[string]any{"value": "rust", "label": "Rust"},
				map[string]any{"value": "typescript", "label": "TypeScript"},
			},
		}).
		Textarea("coverLetter", map[string]any{"label": "Cover Letter", "required": true, "rows": 5}).
		Switch("relocation", map[string]any{"label": "Willing to relocate"}).
		Checkbox("terms", map[string]any{"label": "I certify all info is accurate"})

	formReq, _ := client.CreateFormRequest(form, hax.CreateRequestParams{})
	fmt.Printf("JOB APPLICATION FORM:\n  %s\n\n", formReq.URL())

	fmt.Println("Open any URL in your browser to respond visually.")
}
