package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/philhug/hax-go/server"
)

func main() {
	addr := flag.String("addr", ":8080", "listen address")
	apiKey := flag.String("api-key", "", "API key for Bearer auth (empty = DID-only)")
	webhookSecret := flag.String("webhook-secret", "", "secret for signing outgoing webhooks")
	baseURL := flag.String("base-url", "", "external base URL for request URLs")
	noAutoAccept := flag.Bool("no-auto-accept", false, "disable auto-accepting DID knocks")
	rateLimit := flag.Int("rate-limit", 0, "max requests per IP per minute (0 = unlimited)")
	flag.Parse()

	autoAccept := !*noAutoAccept
	srv := server.NewServer(server.Config{
		Addr:              *addr,
		APIKey:            *apiKey,
		WebhookSecret:     *webhookSecret,
		BaseURL:           *baseURL,
		AutoAcceptKnocks:  &autoAccept,
		RateLimit:         *rateLimit,
	})

	fmt.Fprintf(os.Stderr, "hax-server: starting on %s\n", *addr)
	if err := srv.ListenAndServe(); err != nil {
		fmt.Fprintf(os.Stderr, "hax-server: %v\n", err)
		os.Exit(1)
	}
}
