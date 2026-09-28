# Live Recon — asknarelle-4-sc1003.azurewebsites.net

**Date:** 2026-09-28
**Target:** `https://asknarelle-4-sc1003.azurewebsites.net` (Streamlit course chatbot, MSAL device-flow login)
**Scope:** Authorized, non-intrusive, unauthenticated recon (HTTPS GET/HEAD, headers, TLS, robots.txt, public static endpoints). No login, no chat submission, no fuzzing/brute force.

---

## Outcome (read first)

**The live target could not be reached from this environment.** All outbound HTTPS from this sandbox is forced through an Anthropic egress proxy that enforces a **host allowlist**, and `asknarelle-4-sc1003.azurewebsites.net` is **not on the allowlist**. Every attempt to reach the host was denied by the egress layer, not by the target.

As a result, **none of the five review findings could be corroborated or refuted with live evidence.** No genuine response headers, TLS certificate, redirect behavior, or error pages from the actual application were observed. The items below are therefore all recorded as **BLOCKED — not verifiable from this environment**, not as pass/fail results.

I did not attempt to bypass the egress policy (per environment rules: policy denials are reported, not circumvented). I did not log in, submit chat, or send payloads.

---

## What was tested (method) and the raw evidence

Total requests to the target: 4 (small, spaced): curl-via-proxy GET, curl-via-proxy robots.txt, one openssl direct HEAD, one WebFetch. All denied at the egress layer.

### 1. curl GET / HEAD via the configured HTTPS proxy
The proxy answered the CONNECT tunnel with 403 before any request reached the host:

```
> CONNECT asknarelle-4-sc1003.azurewebsites.net:443 HTTP/1.1
< HTTP/1.1 403 Forbidden
< Connection: close
* CONNECT tunnel failed, response 403
```

Proxy status endpoint recorded the reason explicitly:

```json
{ "kind": "connect_rejected",
  "detail": "gateway answered 403 to CONNECT (policy denial or upstream failure)",
  "host": "asknarelle-4-sc1003.azurewebsites.net:443" }
```

### 2. Proxy allowlist confirmation (control tests)
To prove this is a host-specific policy block and not a broken proxy or a target outage:

| Host | Result |
|------|--------|
| `https://login.microsoftonline.com/.../openid-configuration` | **HTTP 200** (allowed) |
| `https://example.com/` | 403 CONNECT tunnel failed (denied) |
| `https://asknarelle-4-sc1003.azurewebsites.net/` | 403 CONNECT tunnel failed (denied) |

The proxy works and reaches allowlisted hosts; arbitrary hosts (including the target) are denied. This is an allowlist, not an outage.

### 3. openssl direct TLS + single HEAD
openssl (which does not use the HTTP proxy) completed a TLS handshake, but the certificate presented is a **forged leaf minted by the Anthropic egress gateway**, not the target's real certificate:

```
0 s:CN = *.azurewebsites.net
  i:O = Anthropic, CN = Egress Gateway SDS Issuing CA (production)
  v:NotBefore: Sep 28 16:32:57 2026 GMT; NotAfter: Oct 28 16:33:57 2026 GMT
1 i:O = Anthropic, CN = sandbox-egress-gateway-production Egress Gateway CA
```

> **Important — do not misread this as target TLS evidence.** The issuer is the Anthropic egress gateway CA; the validity dates are the freshly-minted interception cert (today + ~30 days), not the target's. The subject `CN=*.azurewebsites.net` is a generic Azure App Service wildcard mirrored by the gateway. This tells us nothing reliable about the target's real TLS protocol versions, real issuer, or real expiry.

A single benign HEAD over that TLS channel was rejected at the HTTP layer by the gateway:

```
HTTP/1.1 403 Forbidden
x-deny-reason: host_not_allowed
content-length: 124
content-type: text/plain
```

### 4. WebFetch
```
{"error_type":"EGRESS_BLOCKED",
 "domain":"asknarelle-4-sc1003.azurewebsites.net",
 "message":"Access to asknarelle-4-sc1003.azurewebsites.net is blocked by the network egress proxy."}
```

---

## Findings vs. the code review (all BLOCKED)

| # | Goal | Status | Notes |
|---|------|--------|-------|
| 1 | Login authority `common` vs specific NTU tenant | **BLOCKED — not observed** | Could not load the page or observe any redirect/network call to `login.microsoftonline.com`. Note: `login.microsoftonline.com` itself is reachable from here, but that only proves the IdP host is allowlisted — it says nothing about which authority *this app* configures. Requires reaching the app. |
| 2 | Security headers (HSTS, CSP, X-Frame-Options/frame-ancestors, X-Content-Type-Options, Referrer-Policy, Cache-Control, server banner) | **BLOCKED — not observed** | No genuine target response headers were ever received. The only `X-Content-Type-Options: nosniff` / server banners seen belong to the egress proxy's own 403 responses, not the app. |
| 3 | TLS protocol versions + cert issuer/subject/expiry | **BLOCKED — not observed** | Only the gateway's forged interception cert was seen (see caveat above). Real target TLS was never negotiated. |
| 4 | Error handling / info disclosure on bad paths (`/nonexistent`, `/admin`) | **BLOCKED — not tested** | Not attempted beyond `/` since even `/` is unreachable; any bad-path probe would hit the same egress 403, not the app. |
| 5 | robots.txt / exposed endpoints (`/healthz`, `/_stcore/health`, `/static`) | **BLOCKED — not observed** | `robots.txt` request denied at proxy CONNECT. Streamlit health/static endpoints not probed for the same reason. |

**Corroborated:** none. **Refuted:** none. All five remain open pending recon from an environment whose egress allows the host.

---

## Requires authenticated testing (explicitly NOT done)

Even with live reachability, the following are out of scope for a non-intrusive unauthenticated pass and were **not** attempted:

- Completing or exercising the MSAL device-flow login (device code request, token acquisition, tenant confirmation via an authenticated `/me` or token claims).
- Verifying that the `common` authority actually accepts a non-NTU (external/personal or other-tenant) Microsoft account — the security-relevant question — which necessarily requires an authentication attempt.
- Submitting any chat message or observing post-login application behavior, session cookies set after auth, or authorization checks on the chat backend (would incur LLM cost / requires auth).
- Any authenticated-endpoint enumeration or access-control checks behind login.

## Recommendation to unblock the non-intrusive pass

Re-run this exact recon from an environment whose egress policy permits `asknarelle-4-sc1003.azurewebsites.net` (e.g. add the host to the allowlist, or run from an unrestricted network). The intended request set is small and non-intrusive: `GET /` (headers), `robots.txt`, `/_stcore/health`, `/healthz`, `/static`, 2–3 benign bad paths, plus `curl -vI` / `openssl s_client` for real TLS and cert inspection.

---

*End of report.*
