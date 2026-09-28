# ChattyBot / AskNarelle — Pre-Launch Security Review

**Target:** `chinannong/ChattyBot` (Streamlit + LangChain + Azure OpenAI course assistant "Narelle")
**Scope:** Source code review of the repository at HEAD. Static/defensive review only — no attacks were run against the live test deployment.
**Posture:** Findings are grounded in specific code and paired with remediations so they can be fixed before go-live. This document deliberately contains no ready-to-run exploit payloads or attack playbooks; it is written to be used by the maintainers to harden the app.

---

## Executive summary

The app is a small, well-contained Streamlit chatbot. There is **no committed secret, no SQL, no obvious RCE, and no user secret placed into the LLM context** — so several of the scariest theoretical risks do not actually apply here. The material issues are in three areas, in priority order:

1. **Authentication / authorization design** — the "NTU students only" gate is weaker than intended and relies on a mutable identity claim and a multi-tenant login authority. (High)
2. **Operational secret hygiene** — no `.gitignore`, and a CI step that zips the whole working tree, together create a real *future* exposure path even though nothing is leaked today. (High)
3. **Hardening & supply chain** — EOL base image, container runs as root, unauthenticated-by-default DB helper, no rate limiting, and pinned-but-aging dependencies. (Medium)

---

## Findings

### 1. Authorization relies on a mutable claim and a weak suffix match — High
**Where:** `Home.py` (device-flow auth block, ~lines 100–170)

```python
app = PublicClientApplication(client_id=..., authority='https://login.microsoftonline.com/common')
...
st.session_state.email = result['id_token_claims']['preferred_username']
...
elif "ntu.edu.sg" in st.session_state.email[-10:] or st.session_state.email in allowed_users:
```

Three problems compound:

- **`authority=.../common`** accepts sign-ins from *any* Azure AD tenant and personal Microsoft accounts, not just NTU. The only thing keeping non-NTU users out is the string check below it.
- **`preferred_username` is not a secure authorization identifier.** Microsoft documents it as mutable and not guaranteed unique/verified; it can differ from the user's real UPN. Authorization decisions should key off the immutable `oid` (object id) + `tid` (tenant id), not a display-oriented username.
- **The suffix check is a substring test on the last 10 characters**, i.e. it only requires the email to *end in* `ntu.edu.sg`. It does not anchor on an `@` boundary, so any address whose tail matches (e.g. a look-alike domain ending in those characters) passes the same test as a real `@e.ntu.edu.sg` / `@ntu.edu.sg` address.

**Impact:** The intended "NTU-only" restriction can be satisfied without an NTU identity, giving unintended parties access to the assistant (and to LLM spend and stored conversations).

**Remediation:**
- Set `authority` to the **specific NTU tenant** (`https://login.microsoftonline.com/<NTU_TENANT_ID>`) so only that tenant can authenticate.
- Authorize on **`tid == <NTU_TENANT_ID>`** and use `oid` as the stable user key; treat the tenant match as the gate, not a string on the email.
- If an email-domain check is still wanted as defense-in-depth, validate the domain properly: split on `@`, lowercase, and compare the domain against an allowlist (`{"ntu.edu.sg", "e.ntu.edu.sg", ...}`) with exact/`endswith("."+domain)` matching — not a fixed-length slice.
- Store the allow/block lists keyed on `oid`, not on a display username.

---

### 2. No `.gitignore` + CI zips the whole tree = a future secret-exposure path — High
**Where:** repository root (no `.gitignore`); `.github/workflows/main_asknarelle.yml`

```yaml
- name: Zip artifact for deployment
  run: zip release.zip ./* -r
- name: Upload artifact for deployment jobs
  uses: actions/upload-artifact@v3
  with:
    name: python-app
    path: |
      release.zip
      !venv/
```

**Current state:** No secret is committed today, and `load_dotenv()` implies a local `.env` is used at runtime. The risk is prospective but realistic: with no `.gitignore`, a developer can trivially `git add .` a `.env`, at which point it lives in the repository and its history, readable by anyone with repo access. (Correction after verification: the CI command `zip release.zip ./*` uses a shell glob that **excludes dotfiles**, so it would *not* bundle a `.env` from the working directory — the dominant exposure path is committing the secret to git, not the artifact. The artifact does still package the full non-dotfile source.) Secrets in this app (Azure OpenAI key, Azure AI Search key, Mongo/Cosmos connection string, app-registration client id) grant control of real cloud resources. See `verification/VERIFICATION.md` for the `git check-ignore` evidence.

**Remediation:**
- Add a `.gitignore` that excludes `.env`, `*.env`, `.env.*`, `venv/`, `__pycache__/`, `.streamlit/secrets.toml`.
- Add a pre-commit / CI secret scan (e.g. `gitleaks` or `trufflehog`) that **fails the build** on detection.
- Package only the files needed to run (an explicit include list), not `./*`.
- Prefer **Azure Key Vault + Managed Identity** (or App Service application settings) over shipping secrets in the artifact at all; keep secrets out of the deployable zip entirely.
- Reduce artifact retention and restrict who can download build artifacts; add branch protection so `main` (which triggers deploy) requires review.
- Update the outdated actions (`setup-python@v1`, `upload-artifact@v3`, `download-artifact@v3`) and consider **OIDC federated deployment** instead of a long-lived publish profile secret.

---

### 3. Prompt-injection exposure is real but bounded — Medium
**Where:** `Narelle.py` (`answer_this`, `get_context`), `Home.py` (query handling)

The system prompt and retrieved vector-store chunks are added as `SystemMessage`s and the user's question as a `HumanMessage`. Two accurate points:

- **Good news:** the system prompt contains only course metadata and instructor emails — **no credentials or secrets** — so a "trick the bot into printing its secrets" attack has nothing to exfiltrate. The earlier concern about the LLM leaking env vars does not apply as written.
- **Actual risk:** (a) a user can still jailbreak the assistant into producing off-topic, abusive, or brand-damaging output attributed to NTU; and (b) if the Azure AI Search index ingests documents from any semi-trusted source, a poisoned document could steer answers when it is retrieved into context (indirect prompt injection).

**Remediation:**
- Keep treating all retrieved context and user input as untrusted; keep secrets out of prompts and context (already the case — maintain it).
- Add output moderation (Azure AI Content Safety or an allow-topic classifier) and an explicit refusal path for out-of-scope requests.
- Control vector-store ingestion: only index vetted course material; record provenance; re-review on update.
- Log and monitor for anomalous query patterns.

---

### 4. Database helper connects unauthenticated by default; loaded credentials are unused — Medium
**Where:** `AN_Util.py` `DBConnector`; `Home.py` DB init

```python
# Home.py
DB_USER = os.environ['CA_MONGO_DB_USER']
DB_PASS = os.environ['CA_MONGO_DB_PASS']
st.session_state.mongodb = DBConnector(DB_HOST).getDB(DB_NAME)   # user/pass never passed
```
```python
# AN_Util.py
def __init__(self, DB_HOST, DB_USER=None, DB_PASS=None, ...):
    if DB_USER is not None:
        self.connection = MongoClient(DB_HOST, username=DB_USER, password=DB_PASS)
    else:
        self.connection = MongoClient(DB_HOST)   # no auth args
```

`Home.py` reads `CA_MONGO_DB_USER`/`CA_MONGO_DB_PASS` but never passes them, so the single-argument branch runs. This is only safe if `CA_MONGO_DB_HOST` is a **full connection string that already carries credentials and TLS** (typical for Cosmos DB). If it is ever set to a bare `host:port`, the connection is unauthenticated and unencrypted, and the stored `USER`/`PASS` give a false sense of protection.

**Remediation:**
- Make authentication explicit and mandatory: pass credentials, or require a connection string that includes `tls=true`/`ssl=true` and auth; fail fast if neither is present.
- Enforce TLS and restrict DB network access (VNet / private endpoint / firewall).
- Remove the dead `DB_USER`/`DB_PASS` reads or actually use them, so the code's intent matches its behavior.

---

### 5. Container hardening: EOL base image, runs as root — Medium
**Where:** `Dockerfile`

```dockerfile
FROM python:3.8
...
CMD ["python3", "-m", "streamlit", "run", "/app/Home.py", ...]
```

`python:3.8` is end-of-life (no security patches), and no `USER` is set so the process runs as root.

**Remediation:**
- Move to a supported slim base (e.g. `python:3.11-slim` or `3.12-slim`) and re-test.
- Create and switch to a non-root user (`RUN adduser --disabled-password app && USER app`).
- Pin the base by digest, add a `HEALTHCHECK`, and scan the image (Trivy/Grype) in CI.

---

### 6. No rate limiting / abuse controls — Medium
**Where:** `Home.py` chat loop; `Narelle.py` cost tracking

Token cost is tracked (`get_total_tokens_cost`) but never enforced. Any authenticated user can send unlimited queries, driving Azure OpenAI spend and enabling denial-of-wallet.

**Remediation:**
- Enforce per-user and global request/token quotas server-side (e.g. counters in Mongo with a rolling window) and a hard daily cap.
- Add basic input length limits and a cooldown between messages.
- Alert on spend thresholds at the Azure OpenAI resource.

---

### 7. Dependency freshness — Medium
**Where:** `requirements.txt` (note: file is UTF-16 encoded — worth normalizing to UTF-8)

Pins include `langchain==0.1.0`, `langchain-community==0.0.11`, `openai==1.7.0`, `streamlit==1.31.0`, `msal==1.26.0`, `pymongo==4.6.1`, `requests==2.31.0`. Several are old enough to have advisories (older `langchain`/`langchain-community` in particular have had multiple CVEs).

**Remediation:**
- Run `pip-audit` / enable Dependabot; update to patched versions and re-test.
- Re-encode `requirements.txt` as UTF-8 (the current UTF-16 encoding can break tooling that assumes UTF-8).

---

### 8. Minor: verbose auth error output & callback logging — Low
**Where:** `Home.py` (`st.write(result.get("error_description"))`, `correlation_id`), `Narelle.py`/`AN_Util.py` (`print(cb)` / token prints)

Surfacing raw MSAL error/correlation details to end users and printing callback objects to logs is low-risk here (no secrets in those objects) but leaks internal detail and clutters logs.

**Remediation:** Show a generic error to users, log details server-side only, and redact/summarize callback logging.

---

## What is NOT a problem (to focus effort)
- **No secrets committed** to the tree (verified at HEAD).
- **No secrets in the LLM system prompt or retrieved context** — the "bot leaks its keys" scenario does not apply as written.
- **No SQL injection** (no SQL; Mongo access uses `_id`/document APIs, not string-built queries).
- **No `eval`/`exec`/`subprocess`/`os.system`** on user input — no obvious RCE path in the reviewed files.

## Suggested pre-launch checklist
- [ ] Lock MSAL to the NTU tenant; authorize on `tid`/`oid`, not `preferred_username`.
- [ ] Add `.gitignore` + CI secret scanning; package an explicit file list, not `./*`.
- [ ] Move secrets to Key Vault / Managed Identity; rotate any key that has ever been in a local `.env` shared insecurely.
- [ ] Enforce DB auth + TLS; remove dead credential reads.
- [ ] Update Dockerfile base, add non-root user; update GitHub Actions versions.
- [ ] Add rate/spend limits and output moderation.
- [ ] Run `pip-audit`/Dependabot and patch; re-encode `requirements.txt` as UTF-8.

*Review method: static source review of the repository at HEAD. History scan was limited to a shallow clone; maintainers should run a full-history secret scan (`gitleaks`/`trufflehog`) on an unshallowed clone as a final gate.*

*Reproducible evidence for these findings — logic reproductions, a `pip-audit` run (115 advisories across 14 packages), and config checks — is in `verification/VERIFICATION.md`.*
