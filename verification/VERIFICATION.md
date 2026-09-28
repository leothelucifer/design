# Verification & Evidence — ChattyBot / AskNarelle findings

Purpose: **prove** the `SECURITY_AUDIT.md` findings are real, using reproducible,
non-destructive evidence. Nothing here attacks the live deployment; every proof
runs against the source code, the dependency manifest, or the config. That is
deliberate — for a pre-launch review, a defect demonstrated in the code is
stronger and safer evidence than a live exploit.

How to think about "proof" for each finding:
- **Logic flaws** (auth gate, DB branch) → run the exact decision logic in isolation and show wrong outcomes.
- **Dependency risk** → run `pip-audit`, which maps pinned versions to published advisories (authoritative, third-party).
- **Config/hygiene** (gitignore, Dockerfile) → show the property directly with git/docker/grep.
- **Design risks with a behavioural component** (prompt injection, rate limiting) → prove the *absence of a control* by code inspection; behavioural confirmation should be done only against your own authorized test instance.

---

## Finding 1 — Authorization suffix check is bypassable (HIGH)

**Claim:** `"ntu.edu.sg" in email[-10:]` (Home.py ~line 162) admits non-NTU identities, and it runs on the mutable `preferred_username` claim behind an `authority=.../common` login (any Microsoft account can authenticate).

**Run:** `python3 verification/proof_auth.py`

**Observed output:**
```
ADMITTED?  case                         email
ALLOW      legit NTU student            alice@e.ntu.edu.sg   (email[-10:]='ntu.edu.sg')
ALLOW      legit NTU staff              bob@ntu.edu.sg   (email[-10:]='ntu.edu.sg')
deny       random gmail (should FAIL)   attacker@gmail.com   (email[-10:]='@gmail.com')
ALLOW      look-alike domain tail       attacker@evilntu.edu.sg   (email[-10:]='ntu.edu.sg')
ALLOW      subdomain look-alike         mallory@notntu.edu.sg   (email[-10:]='ntu.edu.sg')
```

**Why this proves it:** the check is a fixed-length suffix test with no `@`
boundary, so any address ending in the ten characters `ntu.edu.sg` passes the
same test as a genuine NTU address. Combined with the `common` authority and
the use of `preferred_username` (documented by Microsoft as mutable and not a
safe authorization key), the "NTU-only" control does not hold.

**Independent confirmation reviewers can request:** ask the Azure AD admin what
`tid` (tenant id) the app restricts to — the code restricts none. The fix is to
pin `authority` to the NTU tenant and authorize on `tid`/`oid`.

---

## Finding 4 — DB credentials are loaded but never applied (MEDIUM)

**Claim:** `Home.py` reads `CA_MONGO_DB_USER`/`CA_MONGO_DB_PASS` but calls
`DBConnector(DB_HOST)` with a single argument, so `AN_Util.DBConnector` takes
the un-authenticated `MongoClient(DB_HOST)` branch.

**Run:** `python3 verification/proof_db.py`

**Observed output:**
```
Home.py call -> UNAUTHENTICATED MongoClient(host)   <-- credentials NOT applied
(DB_USER / DB_PASS were loaded but never passed => else-branch runs)
```

**Why this proves it:** the reproduction uses the same branch condition
(`if DB_USER is not None`) and the same call arity as `Home.py`. Safety
therefore depends entirely on `CA_MONGO_DB_HOST` being a full credentialed +
TLS connection string; if it is ever a bare host, the connection is
unauthenticated. The loaded `USER`/`PASS` give a false sense of protection.

---

## Finding 7 — Dependencies carry many published advisories (MEDIUM)

**Claim:** the pinned versions in `requirements.txt` have known CVEs/advisories.

**Reproduce:**
```bash
iconv -f UTF-16 -t UTF-8 requirements.txt | tr -d '\r' | sed '/^\s*$/d' > requirements_utf8.txt
python3 -m pip install pip-audit
python3 -m pip_audit -r requirements_utf8.txt --desc on
```
(the `iconv` step is needed because the committed `requirements.txt` is UTF-16 —
itself a finding; most tooling assumes UTF-8.)

**Observed result:** `pip-audit` reported **115 known vulnerabilities in 14 of the
18 packages**. Heaviest hitters by advisory count:

| package | advisories |
|---|---|
| langchain-core | 15 |
| urllib3 | 13 |
| langchain-community | 12 |
| langchain | 9 |
| streamlit | 7 |
| requests | 7 |

**Why this proves it:** `pip-audit` maps exact pinned versions to the PyPA /
OSV advisory databases — an authoritative, third-party source, not opinion.
The full machine-readable report can be regenerated with
`python3 -m pip_audit -r requirements_utf8.txt -f json`.

---

## Finding 2 — Secret hygiene: no `.gitignore` (HIGH) — *scope corrected*

**Claim (corrected during verification):** the repo has **no `.gitignore`**, so a
`.env` can be committed and then lives in the repository and its history,
readable by anyone with repo access. *Note:* the CI command `zip release.zip ./*`
uses a shell glob that **excludes dotfiles**, so it would not bundle a `.env`
sitting in the working directory — the earlier "CI leaks .env in the artifact"
framing was too strong and has been narrowed. The artifact does bundle the full
non-dotfile source; the dominant secret-exposure path is the missing
`.gitignore` plus committing secrets to git.

**Reproduce:**
```bash
git check-ignore .env    # empty output => NOT ignored
```
**Observed:** empty output — `.env` is not ignored. (This session verified it.)

Full-history secret scan (final go-live gate), run on a full clone:
```bash
git clone https://github.com/chinannong/ChattyBot && cd ChattyBot
gitleaks detect --source . --no-banner       # or: trufflehog git file://.
```

**Why this proves it:** `git check-ignore` returning nothing is direct evidence
there is no rule protecting `.env`. The current tree has no committed secret
(also verified), so this is a *preventable future* exposure — exactly the kind
of thing to fix before launch.

---

## Finding 5 — Container runs as root on an EOL base (MEDIUM)

**Claim:** `Dockerfile` sets no `USER`, so the app runs as root; base is EOL `python:3.8`.

**Reproduce:**
```bash
grep -iE '^\s*USER' Dockerfile          # no match => defaults to root
docker build -t chattybot . && docker run --rm chattybot id   # uid=0(root)
# or just the base image:
docker run --rm python:3.8 id           # uid=0(root) gid=0(root)
```
**Observed here:** the `grep` returns no match (no `USER` directive) — conclusive
on its own. The `docker run` confirmation is left for a host with a running
Docker daemon (unavailable in this review sandbox).

**Supporting fact:** Python 3.8 reached upstream end-of-life on 2024-10-07
(PEP 569) — no further security fixes.

---

## Findings 3 & 6 — proving the *absence of a control*

For prompt injection (3) and rate limiting (6), the proof is that no mitigating
code exists:

```bash
# No output moderation / refusal-on-off-topic layer around the LLM call:
grep -rniE 'moderat|content.?safety|refus|blocklist|jailbreak' *.py    # (no hits)
# No rate/quota enforcement (cost is tracked but never capped):
grep -rniE 'rate.?limit|quota|throttle|cooldown|max.?requests' *.py    # (no hits)
```
Cost is *observed* (`get_total_tokens_cost`) but never *enforced*, so there is no
denial-of-wallet control. Any behavioural demonstration of injection or spend
abuse should be performed **only against your own authorized test instance**,
kept benign (e.g. an off-topic-compliance probe), and never used to exfiltrate
data — note that the system prompt/context contain no secrets, so there is
nothing sensitive to extract, which is worth stating in the report.

---

## Summary table

| # | Finding | Proof type | Status |
|---|---------|-----------|--------|
| 1 | Auth suffix bypass | logic reproduction | **demonstrated** |
| 2 | No `.gitignore` | `git check-ignore` | **demonstrated** (scope corrected) |
| 4 | DB creds unused | logic reproduction | **demonstrated** |
| 5 | Root container / EOL base | `grep`/PEP 569 | **demonstrated** (runtime step provided) |
| 7 | Dependency CVEs | `pip-audit` (115/14) | **demonstrated** |
| 3 | Prompt-injection exposure | absence-of-control grep | code-confirmed |
| 6 | No rate limiting | absence-of-control grep | code-confirmed |
