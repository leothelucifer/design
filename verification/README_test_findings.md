# ChattyBot security findings — automated test harness

Reproducible, **non-destructive**, **offline** pytest suite that proves the
security findings in the ChattyBot code.

## Run
```bash
cd /home/user/design
python3 -m pip install pytest          # if not already installed
python3 -m pytest verification/test_findings.py -v
```

## Guarantees
- The clone at `/home/user/chinannong/chattybot` is treated as **read-only**
  (the suite sets `sys.dont_write_bytecode = True`, so not even `.pyc` files are
  written into it).
- **No network / Azure / Mongo / OpenAI calls.** Every heavy or network-touching
  import (`pymongo`, `dotenv`, `langchain*`, `bson`) is replaced with an in-memory
  fake in `sys.modules` before `AN_Util` is imported. `pymongo.MongoClient` is a
  spy that records constructor args instead of connecting.
- **`Home.py` is never imported** (importing it would execute the Streamlit app).
  Its logic is proven two ways: (a) tiny local functions that mirror the exact
  predicates, and (b) assertions against the raw source text with line citations
  (Home.py:112, :151, :161, :168).

## What each group proves
1. **Auth-gate bypass** (`auth_gate`, mirrors Home.py:168) — a broad identity
   matrix shows look-alike tails (`evilntu.edu.sg`, `xntu.edu.sg`, `notntu.edu.sg`)
   and even a bare `xntu.edu.sg` are **admitted**, while uppercase real NTU emails
   are **denied**. Also cites the mutable `preferred_username` claim (Home.py:151)
   and the multi-tenant `/common` authority (Home.py:112).
2. **Unauthenticated DB** — `DBConnector(DB_HOST)` (Home.py:161) drives the
   `MongoClient(DB_HOST)` branch with **no username/password**; the spy confirms
   it. A counterfactual shows credentials WOULD be passed if the caller supplied
   `DB_USER`. Source proof: Home.py reads `CA_MONGO_DB_USER/PASS` but calls with
   one positional arg.
3. **No secrets in LLM context** (negative control) — the reconstructed
   `Narelle.__init__` system prompt contains no secret-like keywords, no `sk-`
   keys, no connection strings, and interpolates only `COURSE_NAME` /
   `LAST_CONTENT_UPDATE`. Substantiates that prompt-injection can't exfiltrate
   secrets that were never placed in context.
4. **Absence of controls** — grepping all `*.py` finds no rate-limit / quota /
   throttle and no moderation / refusal / content-blocklist patterns. The
   identity-based `blocked_users` check is explicitly scoped out as account
   gating, not content moderation.
