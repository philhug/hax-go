# syntax=docker/dockerfile:1

# --- build stage ---
FROM golang:1.26 AS build
WORKDIR /src

ENV GOWORK=off CGO_ENABLED=0

# Cache module downloads (no-op today: zero external deps).
COPY go.mod ./
RUN go mod download

COPY . .

RUN go build -trimpath -ldflags="-s -w" -o /out/haxserver ./cmd/haxserver

# --- runtime stage ---
# alpine (not scratch/distroless-static) because the server makes outbound
# HTTPS webhook calls that need a CA bundle.
FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata && update-ca-certificates

COPY --from=build /out/haxserver /usr/local/bin/haxserver

# Non-root user.
USER 65532:65532

EXPOSE 8080
ENTRYPOINT ["haxserver"]
CMD ["--addr", ":8080"]
