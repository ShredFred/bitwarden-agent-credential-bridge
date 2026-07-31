# Phase 4a: fake HTTP API-key header contract

Phase 4a extends the local contract harness with one fake-only version-2
credential class. It does not connect to Bitwarden, OneCLI, a vault, Docker, or
the network.

## Policy

A version-2 policy has exactly these fields:

```json
{
  "version": 2,
  "service": "fake-sample-api",
  "credential_class": "http_api_key_header",
  "bind": "http://127.0.0.1:0",
  "upstream": "http://127.0.0.1:0",
  "method": "GET",
  "path": "/v1/resource",
  "header_name": "x-fake-api-key",
  "header_value": "{{credential}}"
}
```

`header_name` must be a canonical lowercase ASCII HTTP token no longer than 128
characters (and therefore 128 bytes). Authorization, proxy authorization, host,
cookie, hop-by-hop, framing, content, forwarding, and browser protocol header
names are forbidden. `header_value` must be exactly `{{credential}}`; it is not
a general template. Unknown fields are rejected.

The runtime fake value is generated in memory and passed explicitly to the
broker and fake API. It is never placed in policy JSON, an environment
variable, a file, a response, a log, or an error message.

## Broker boundary

The broker revalidates the complete policy when it starts. For an allowed
request it:

1. rejects query strings, fragment-like syntax, and ambiguous request targets;
2. strips the caller's pinned header, authorization/proxy-authorization,
   cookies, content/framing headers, standard hop-by-hop headers, and headers
   named by `Connection`;
3. adds exactly one policy-pinned API-key header with the explicit runtime fake
   value;
4. keeps redirect handling in manual, fail-closed mode;
5. checks a valid upstream `Content-Length`, then counts every streamed body
   chunk against `MAX_UPSTREAM_RESPONSE_BODY_BYTES`;
6. best-effort cancels the reader after any bounded read failure while keeping
   the original read or size error authoritative;
7. scans the complete concatenated body and response headers for the raw fake
   value plus its percent-encoded UTF-8, standard Base64 UTF-8, and Base64url
   UTF-8 forms; and
8. removes upstream `Content-Encoding` because Node fetch may have already
   decoded the buffered bytes, then returns a sanitized response.

The same deduplicated, non-empty sensitive-variant set is used recursively to
redact log and error metadata. The values exist only in memory and are never
printed or persisted.

The upstream response limit is 1 MiB, matching the broker request limit. This
is intentionally conservative for the constant-response sample API.

## Compatibility and exclusions

Valid version-1 `http_bearer` policies continue to inject one outbound bearer
authorization value. Basic Auth, browser or website passwords, query, cookie,
form, process-environment, SSH, database, RDP, and desktop credential injection
remain unsupported and fail closed.

Run the focused contract suite with:

```bash
npm run test:phase4a
```

The tests use generated fake sentinels only and cover version-1 regression,
version-2 success, caller spoofing and duplicate case variants, strict schema
rejection, query denial without an upstream call, declared and streamed
response overflow, split-chunk echo detection, and agent-readable exposure
surfaces, including encoded body, header, and error echoes.
