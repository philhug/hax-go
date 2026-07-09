# AGENTS.md

Guide for agents working in the `hax-go` repository — a Go SDK for the HAX (Human Approval eXchange) API plus a reference server implementation.

## Project overview

- **Module**: `github.com/philhug/hax-go` (Go 1.26.2, **zero external dependencies** — standard library only).
- **Two packages**:
  - Root package `hax` (`client.go`, `models.go`, `crypto.go`, `did.go`, `formbuilder.go`, …) — the client SDK.
  - `server/` — a reference HAX API server the client talks to, useful for local dev and integration testing.
- **Wire-format compatibility**: This is a Go reimplementation of the [Python `hax-sdk`](https://pypi.org/project/hax-sdk/). Crypto code (deterministic RSA key generation, Ed25519 DID signing, base58btc `did:key` encoding, JWS envelope) **must produce byte-for-byte identical output** to the Python SDK. Do not "modernize" the serialization or crypto primitives — they are intentionally shaped to match Python.

## Essential commands

> **CRITICAL — `GOWORK=off` is required.** A parent `go.work` lives at `../go.work` (the `asanti` workspace) and does **not** include this module. Plain `go build ./...` / `go test ./...` fail with `directory prefix . does not contain modules listed in go.work`. Always prefix commands with `GOWORK=off`, or `cd` into the module and set the env var.

```bash
GOWORK=off go build ./...          # build all packages
GOWORK=off go vet ./...            # vet (currently clean)
GOWORK=off go test ./...           # run all tests (root hax + server packages)
GOWORK=off go test ./server/...    # server tests only
GOWORK=off go test -run TestName . # single test

# Run the reference server
GOWORK=off go run ./cmd/haxserver --addr :8080 --api-key my-secret-key
GOWORK=off go run ./cmd/haxserver --webhook-secret whsec_... --no-auto-accept

# Run an example (each is its own main package under examples/<name>/)
GOWORK=off go run ./examples/smoke_test
```

There is no Makefile, no CI config, and no linter config in this repo. `go vet` is the only static check.

## Architecture & data flow

### Client SDK (`package hax`)

`HaxClient` (`client.go`) is the entry point. `NewClient` wires together:
1. **Identity resolution** (`identity.go` `LoadIdentity`) — order: explicit DID+JWK → explicit file → `HAX_IDENTITY_FILE` env → `~/.hax/identity.json` → mint-on-first-use (only when no API key).
2. **HTTP layer** (`http.go` `HttpClient`) — serializes the body **once** with `compactJSON`, then signs those exact bytes, so the hashed body equals the sent body.
3. **Encryption** (`crypto.go`) — if `EncryptionKey` (passphrase) is given, derives an RSA keypair deterministically; if only `PublicKey` is given, encrypt-only.

Request lifecycle: `CreateRequest` → (optional delivery via email/SMS) → poll `GetRequest` / `WaitForResponse` → terminal state (`completed`/`expired`/`cancelled`). Form requests go through `CreateFormRequest` → `FormRequestHandle` which parses typed `FormValues`.

### Reference server (`package server`)

`Server` (`server/server.go`) uses Go 1.22+ `http.ServeMux` method+path patterns (e.g. `"POST /api/v1/requests"`). Middleware chain per route: `rateLimit` → `auth` → handler. `store` (`store.go`) is an in-memory, `sync.RWMutex`-guarded map; requests auto-expire lazily on read (`getAndExpire`).

Two route families:
- **API routes** (`/api/v1/...`) — require auth (API key Bearer **or** DID JWS signature).
- **Human UI routes** (`/hub/r/{id}`) — no auth; render HTML (`ui.go`, `renderers.go`) and accept form POSTs that complete a request.
- **Admin routes** (`/api/v1/admin/knock`, `/api/v1/admin/respond`) — **no auth**, intended for driving tests. `server_test.go` uses `submitResponseViaAdmin` to simulate a human response.

## Non-obvious gotchas & conventions

- **`compactJSON` is load-bearing** (`json.go`): `json.Encoder` with `SetEscapeHTML(false)`, trailing newline trimmed. This mirrors Python's `json.dumps(separators=(",", ":"))`. The JWS `bh` (body hash) claim is `sha256:<base64url(sha256(rawBody))>` over these exact bytes — changing JSON formatting breaks signature verification. When adding request fields, build `map[string]any` and let `HttpClient.doRequest` serialize; do not pre-serialize.
- **snake_case → camelCase conversion** (`formbuilder.go` `snakeToCamel` / `mergeOptions`): FormBuilder field options are written in `snake_case` but converted to `camelCase` for the API. The same conversion is applied to `sender` maps passed as `map[string]any` (`normalizeSender`).
- **Pointer helpers**: Use `hax.StringPtr(s)` / `hax.IntPtr(i)` for optional `*string` / `*int` params (e.g. `Title`, `ExpiresInSeconds`). gopls suggests `new(s)` instead — ignore; the helpers are the established convention.
- **Duplicated status helpers**: `IsPending()`/`IsCompleted()`/`IsExpired()`/`IsCancelled()`/`IsHeld()` are defined on **both** `*CreatedRequest` and `*Request` (`models.go`). When adding a new status, update both.
- **Response unwrap quirk**: `unwrap(data, "request")` (`client.go`) returns the nested `"request"` object if present, else the whole map. The create endpoint returns a **flat** object (no wrapping); get/list/respond endpoints wrap in `{"request": ...}`. Keep this asymmetry in mind when adding endpoints.
- **Auto-decryption**: `GetRequest`/`ListRequests` transparently decrypt `_encrypted` response fields when a private key is present (`decryptResponseField`). Two formats are handled: whole-response encryption and `values`-only encryption.
- **Identity file permissions**: `SaveIdentity` writes `~/.hax/identity.json` with mode `0600`. The default path can be overridden via `HAX_IDENTITY_FILE`. Tests set `HAX_IDENTITY_FILE` to a nonexistent path to prevent accidental minting (`server_test.go:newAPIKeyClient`).
- **`storedRequest` JSON tags**: Several fields are `json:"-"` (e.g. `WebhookURL`, `PublicKey`, `Delivery`, `CreatedByDID`) — they exist in memory but are never serialized to clients; the server selectively exposes them via `requestToMap`.
- **Timestamp format**: The server hardcodes `"2006-01-02T15:04:05.000Z"` for `expiresAt` parsing (`store.go`). Match this format when constructing expiry times.

## Testing patterns

- Tests live **in the same package** as the code (`package hax` / `package server`), not `_test` external packages.
- The reference server doubles as a test fixture: `server.NewTestServer(Config{...})` returns `(*Server, baseURL, cleanup)` starting on a random port (`:0`). Prefer this over `httptest.NewServer` for integration-style tests.
- `server/server_test.go` has shared helpers: `newTestServer`, `newDIDClient`, `newAPIKeyClient`, `submitResponseViaAdmin`. Reuse these rather than reinventing.
- Client-side unit tests (`http_test.go`, `did_test.go`, `crypto_test.go`, `webhooks_test.go`) use `httptest.NewServer` to capture headers/bodies and assert on auth/encryption behavior.
- No table-driven test framework; tests are plain `func TestX(t *testing.T)`. Follow the existing `t.Helper()` + `t.Fatalf` style.

## Crypto specifics (do not refactor casually)

- `crypto.go` `GenerateKeyPair`: deterministic RSA-2048 from a passphrase via a custom `seededPRNG` (SHA-256 counter stream with periodic state re-keying) + Miller-Rabin primality. Replicates the Python SDK's `_create_seeded_prng` exactly.
- `did.go`: hand-rolled base58btc encode/decode (Bitcoin alphabet), `did:key` multicodec prefix `0xED 0x01`. `SignKnockJWS` produces a DPoP-shaped compact JWS (`alg: EdDSA`) over `header.payload` (ASCII), signature is Ed25519. `VerifyKnockJWS` recovers the public key from the `did:key`.
- `EncryptWithPublicKey` (`crypto.go:375`) is server-side only (used by `admin/respond`); the client only decrypts.

## Adding a new API endpoint

1. Add the method on `HaxClient` in `client.go` using the existing `c.http.Get/Post/Patch` helpers — they handle auth, signing, and error mapping.
2. Map the response with `unwrap` + `parseRequest`/`parseCreatedRequest` (re-serialize through `compactJSON` then `json.Unmarshal` into the typed struct).
3. If the endpoint needs a new typed error, add it to `errors.go` following the `HaxError` embedding pattern and wire it in `http.go:handleErrorResponse`.
4. Mirror the route in `server/server.go:registerRoutes` with the `rateLimit(s.auth(...))` wrapper, and implement the handler in `server/handlers.go`.
5. Add a test in `server/server_test.go` using the admin helpers to drive the lifecycle.
