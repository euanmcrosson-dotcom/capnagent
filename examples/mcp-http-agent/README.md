# `@capnagent-examples/mcp-http-agent`

An origin-scoped HTTP agent — the second real-world consumer of
`@capnagent/mcp`. Demonstrates how capabilities can bound the most
common AI-agent attack surface: **data exfiltration to attacker-
controlled origins via fetch**.

## What the issued capability says

```text
identifier: http.get
caveats:
  - caller == "agent:http"
  - now <= @2099-01-01T00:00:00Z
  - tool == "http.get" AND (
        arg.origin == "https://api.example.com"
     OR arg.origin == "https://api.weather.com"
    )
```

There is no clause permitting `http.post`, `http.put`, or
`http.delete`. Those are denied at the caveat-evaluation gate before
fetch is invoked.

## Why `arg.origin`, not `arg.url`

The caveat compares `arg.origin` (a normalized field), not `arg.url`
(the raw input). The verifier-controlled `Context` provider parses
the URL with the standard `URL` constructor and writes the parsed
origin into `arg.origin` BEFORE the verifier sees it.

That defends against:

| Trick                                      | URL                                                | `URL.origin`                       | Verdict |
|--------------------------------------------|----------------------------------------------------|------------------------------------|---------|
| Userinfo splitting                         | `https://api.example.com@evil.com/x`               | `https://evil.com`                 | denied  |
| Subdomain confusion                        | `https://api.example.com.evil.com/x`               | `https://api.example.com.evil.com` | denied  |
| Default-port mismatch                      | `https://api.example.com:443`                      | `https://api.example.com`          | (depends on the issued allowlist) |
| Malformed URL                              | `not a url`                                        | (parse fails)                      | denied  |

If the URL fails to parse, `arg.origin` is absent. The equality check
on a missing field is `false` → denied. Fail-closed.

## Run it

```bash
# from the repo root
npm run -w @capnagent-examples/mcp-http-agent demo
```

Expected output:

```
→ GET allowlisted origin                              ✓ allowed
→ GET allowlisted origin with query                   ✓ allowed
→ GET non-allowlisted origin                          ✓ denied
→ GET userinfo splitting (api.example.com@evil.com)   ✓ denied
→ GET subdomain confusion (api.example.com.evil.com)  ✓ denied
→ POST allowlisted origin                             ✓ denied
requests that hit allowlisted stub: 2
requests that hit attacker stub:    0
```

## Test it

```bash
npm test -w @capnagent-examples/mcp-http-agent
```

The vitest suite spins up two localhost `node:http` stub servers
(one stands in for the allowlisted origin, one for the attacker
origin) and asserts that:

- denied calls never reach EITHER stub server,
- allowed calls reach only the allowlisted stub,
- every decision produces a signed receipt.

No real network is touched.

## Issuance preconditions

`issueOriginScopedGetCapability` rejects:

- empty allowlists (`allowedOrigins: []`),
- non-canonical origin strings (must be `scheme://host[:port]` with
  no path, no query, no userinfo, no fragment),
- malformed origins.

The check is sync and runs at issuance time, so misconfigured
deployments fail before any token is minted — not at the first
fetch.
