# Scrub Proxy

A transparent Go reverse proxy for OpenAI-compatible LLM APIs (default upstream:
[OpenRouter](https://openrouter.ai)) that scrubs sensitive data out of requests
and restores it in responses: secrets are redacted one-way via
[gitleaks](https://github.com/gitleaks/gitleaks), PII is anonymized via
[Presidio-Analyzer](https://github.com/data-privacy-stack/presidio) and restored
from placeholders before returning to the client.

## How it works

1. **Scrub requests**: The proxy extracts all user textual inputs from the
   request body (`messages[].content`, `input`, `prompt`), detects the language
   of each text with [Lingua](https://github.com/pemistahl/lingua-go) (restricted
   to the codes in `ANALYZER_LANGUAGES`), sends each to Presidio `POST /analyze`
   with the detected language, and replaces every detected PII span with a
   **bounded placeholder** like `<Name_1>`. Before that, a gitleaks scan
   redacts anything that looks like an API key, token, or credential — those
   are never restorable.
2. **Forward**: The scrubbed request is forwarded to the upstream LLM API.
   The client's `Authorization` header is passed through unchanged.
3. **Restore responses**: The proxy scans upstream responses for placeholders
   and replaces them with the original plaintext before returning to the client.
   This works for both non-streaming JSON and streaming (SSE / streamableHttp)
   responses.

The `placeholder → plaintext` mapping lives only in memory for the lifetime of
a single request and is never persisted or logged. The upstream LLM never sees
the PII — only the placeholder. Redacted secrets are never seen by anyone.

## Why placeholders instead of encryption?

Placeholders have a **bounded, well-defined format** (e.g. `<Name_1>`, max 41
characters) that the proxy controls. This makes streaming restoration 100%
reliable: a placeholder can be split across stream chunks, and the proxy holds
back a bounded suffix until it completes. This is the same approach used by
[prompt-anonymizer](https://github.com/akazah/prompt-anonymizer).

## Supported endpoints

| Endpoint | Streaming | Format |
|---|---|---|
| `POST /v1/chat/completions` | Yes | SSE (`text/event-stream`) |
| `POST /v1/chat/completions` | No | JSON |
| `POST /v1/responses` | Yes | streamableHttp (JSON events) |
| `POST /v1/responses` | No | JSON |
| `POST /v1/completions` | Yes/No | SSE / JSON |
| `GET /v1/models` | No | JSON |

All other paths are passed through to the upstream unmodified, preserving the
original HTTP method (so `GET /v1/models` is forwarded as a GET). Query strings
are preserved on forwarded requests.

`GET /healthz` is served locally for liveness probes and never forwarded.

## Configuration

Configuration is via environment variables (see `config.example.env`):

| Var | Default | Purpose |
|---|---|---|
| `PRESIDIO_ANALYZER_URL` | `http://presidio-analyzer` | Presidio analyzer base URL |
| `UPSTREAM_BASE_URL` | `https://openrouter.ai/api/v1` | Upstream LLM base URL |
| `PORT` | `8080` | Proxy listen port |
| `HTTP_LOG` | `false` | Log incoming HTTP traffic (`true`/`false`) |
| `UPSTREAM_LOG` | `false` | Log outgoing upstream HTTP traffic (`true`/`false`) |
| `LOG_LEVEL` | `info` | Log level: `debug`, `info`, `warn`, `error` |
| `ANALYZER_LANGUAGES` | `en,de` | Comma-separated ISO 639-1 codes the language detector may choose from |
| `SECRET_SCAN_ENABLED` | `true` | Enable the gitleaks secret redaction stage |
| `GITLEAKS_CONFIG` | *(empty)* | Path to a custom gitleaks TOML config |
| `MAX_REQUEST_BODY_BYTES` | `10485760` | Maximum accepted request body size (10 MiB) |

The proxy does **not** configure an upstream API key — it forwards the client's
`Authorization` header to the upstream unchanged.

## Usage

```bash
# Build
go build ./...

# Run (with env vars set)
PRESIDIO_ANALYZER_URL=http://localhost:3000 \
UPSTREAM_BASE_URL=https://openrouter.ai/api/v1 \
PORT=8080 \
go run .

# Point any OpenAI-compatible client at the proxy
export OPENAI_BASE_URL=http://localhost:8080/v1
```

## Logging

Every PII replacement is logged with the entity type, span, score, placeholder,
the detected language, and Presidio's full `analysis_explanation`:

```
pii_replaced entity_type=PERSON start=11 end=21 score=0.9 placeholder=<Name_1> language=en analysis_explanation={...}
```

The plaintext value is never logged. Secret detections log only the rule,
offsets, and entropy — never the secret itself.

When `HTTP_LOG=true`, every incoming HTTP request and its response are logged
with method, path, query, remote address, user agent, content type, content
length, accept header, and response status:

```
http_request method=POST path=/v1/chat/completions query= remote=127.0.0.1:54321 user_agent=curl/8.0 content_type=application/json content_length=123 accept=*/*
http_response method=POST path=/v1/chat/completions status=200 content_type=application/json
```

When `UPSTREAM_LOG=true`, every outgoing upstream request and response are
logged with method, URL, and response status. Anonymized request bodies are
included; passthrough bodies bypass anonymization and are therefore never
logged:

```
upstream_request method=POST url=https://openrouter.ai/api/v1/chat/completions body={...}
upstream_response url=https://openrouter.ai/api/v1/chat/completions status=200
```

Set `LOG_LEVEL=debug` to see detailed tool-call unmasking logs in streaming
responses:

```
sse_tool_call_arguments raw={"name":"<Na restored={"name":"John Smith
streamable_tool_call_arguments type=response.function_call_arguments.delta raw=... restored=...
```

## Security notes

- **Secrets are redacted one-way**: gitleaks findings are replaced with
  `[REDACTED]` before any further processing; the value is discarded and never
  restorable or logged.
- **Request bodies are size-capped** (`MAX_REQUEST_BODY_BYTES`) because they
  are fully buffered for analysis — protects against memory-exhaustion DoS.
- **Hop-by-hop headers and `Content-Length` are stripped** from upstream
  responses; `Content-Length` is recomputed after restoration changes the body.
- **Forwarded paths are normalized** so dot segments cannot escape the
  configured upstream prefix.
- **TLS is verified** for both upstream connections using the default
  transport; no certificates are skipped.
- **Graceful shutdown** on SIGINT/SIGTERM drains in-flight requests.
- The server sets `ReadHeaderTimeout`, `IdleTimeout`, and `MaxHeaderBytes`;
  `WriteTimeout` stays zero so long-lived streams are not cut off.

## Project structure

```
├── main.go                   # entrypoint + graceful shutdown
├── config.go                 # env-based config
├── proxy/
│   ├── server.go             # HTTP server (timeouts, graceful shutdown)
│   ├── proxy_handler.go      # main proxy handler: scrub → forward → restore
│   └── upstream.go           # upstream LLM client
├── language/
│   └── detector.go           # lingua-based language detection
├── presidio/
│   ├── client.go             # POST /analyze client
│   └── models.go             # request/response models
├── anonymize/
│   ├── pipeline.go           # detect language → analyze → replace → log
│   ├── extract.go            # extract user text from request
│   └── placeholder.go        # bounded placeholder format + generator
├── restore/
│   ├── json.go               # non-streaming JSON walker
│   ├── sse.go                # SSE stream restorer
│   ├── streamable.go         # streamableHttp restorer
│   └── holdback.go           # bounded hold-back restorer
└── secrets/
    ├── scanner.go            # gitleaks wrapper
    ├── finding.go            # finding model + offset conversion
    └── redact.go             # one-way redaction
```

## Tests

```bash
go test ./...
```
