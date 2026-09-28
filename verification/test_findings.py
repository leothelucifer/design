"""
Non-destructive, reproducible test harness that PROVES the security findings in
the ChattyBot code (Streamlit course chatbot).

Design constraints honoured here:
  * The clone at /home/user/chinannong/chattybot is treated as READ-ONLY.
  * NO network / Azure / Mongo / OpenAI calls are ever made -- every heavy or
    network-touching dependency is faked in sys.modules BEFORE the app code is
    imported.
  * Home.py is NEVER imported (importing it executes the Streamlit app at module
    load). Instead we (a) mirror its exact decision logic in tiny local functions
    and (b) assert against the raw source text with line citations.
  * AN_Util is imported, but only after pymongo is replaced by a spy that records
    call args instead of opening a real connection.

Run from /home/user/design:
    python3 -m pytest verification/test_findings.py -v
"""

import os
import re
import sys
import types

import pytest

# ---------------------------------------------------------------------------
# Source locations (READ-ONLY clone). Nothing here is ever written to.
# ---------------------------------------------------------------------------
SRC_DIR = "/home/user/chinannong/chattybot"
HOME_PY = os.path.join(SRC_DIR, "Home.py")
AN_UTIL_PY = os.path.join(SRC_DIR, "AN_Util.py")
NARELLE_PY = os.path.join(SRC_DIR, "Narelle.py")


def _read(path):
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


def _find_line(source, needle):
    """Return (1-based line number, stripped line text) of the first line
    containing `needle`, or (None, None)."""
    for i, line in enumerate(source.splitlines(), start=1):
        if needle in line:
            return i, line.strip()
    return None, None


HOME_SRC = _read(HOME_PY)
AN_UTIL_SRC = _read(AN_UTIL_PY)
NARELLE_SRC = _read(NARELLE_PY)


# ===========================================================================
# FINDING 1 -- AUTH GATE BYPASS  (Home.py ~line 168)
#
#   elif "ntu.edu.sg" in st.session_state.email[-10:] or email in allowed_users:
#
# The predicate takes the last 10 characters of the email and checks whether the
# literal "ntu.edu.sg" (also exactly 10 chars) appears in them. Because the slice
# is exactly 10 chars, the test degenerates to "does the email END WITH the
# substring 'ntu.edu.sg'" -- a naive suffix check with NO '@' boundary and NO
# case-folding. Any domain whose tail is 'ntu.edu.sg' (evilntu.edu.sg,
# xntu.edu.sg, notntu.edu.sg) is admitted. Correct behaviour would validate the
# registrable domain after the '@' against an allow-list (== 'ntu.edu.sg' or a
# real subdomain like 'e.ntu.edu.sg'), case-insensitively.
# ===========================================================================

def auth_gate(email, allowed_users=()):
    """EXACT mirror of the Home.py predicate (line ~168). Do not 'fix' it here --
    this function intentionally reproduces the buggy logic so the tests can
    document reality."""
    return ("ntu.edu.sg" in email[-10:]) or (email in allowed_users)


# (case_id, email, ACTUAL_gate_result, SHOULD_be_allowed_if_correct)
AUTH_MATRIX = [
    # --- legitimate NTU identities: correctly allowed ---
    ("legit_ntu_staff",        "bob@ntu.edu.sg",          True,  True),
    ("legit_ntu_student_sub",  "alice@e.ntu.edu.sg",      True,  True),
    # --- plain external: correctly denied ---
    ("external_gmail",         "attacker@gmail.com",      False, False),
    ("external_hotmail",       "person@hotmail.com",      False, False),
    # --- look-alike tails: BYPASS -- admitted but should be denied ---
    ("lookalike_evilntu",      "attacker@evilntu.edu.sg", True,  False),
    ("lookalike_xntu",         "mallory@xntu.edu.sg",     True,  False),
    ("lookalike_notntu",       "eve@notntu.edu.sg",       True,  False),
    # --- edge / empty strings ---
    ("empty_string",           "",                        False, False),
    ("just_the_domain",        "ntu.edu.sg",              True,  True),  # no '@' at all, still admitted
    ("bare_tail_no_at",        "xntu.edu.sg",             True,  False), # no '@', tail matches -> admitted
    # --- uppercase legit NTU: FALSE NEGATIVE -- denied though it should pass ---
    ("uppercase_legit_ntu",    "BOB@NTU.EDU.SG",          False, True),
    ("mixedcase_legit_ntu",    "Bob@Ntu.Edu.Sg",          False, True),
    # --- display-name style value (not an email at all) ---
    ("display_name_value",     "Ong Chin Ann",            False, False),
]


@pytest.mark.parametrize("case_id,email,actual,_should", AUTH_MATRIX,
                         ids=[c[0] for c in AUTH_MATRIX])
def test_auth_gate_actual_behavior_is_documented(case_id, email, actual, _should):
    """The mirrored gate must produce exactly the ACTUAL (buggy) verdict we
    recorded. This pins current behaviour so any future change is caught."""
    assert auth_gate(email) is actual, (
        f"[{case_id}] auth_gate({email!r}) returned {auth_gate(email)!r}, "
        f"expected recorded actual={actual!r}"
    )


# The bypass cases: emails that a correct validator would DENY but the shipped
# gate ADMITS. Proving this set is non-empty IS the vulnerability.
BYPASS_CASES = [(cid, email) for (cid, email, actual, should) in AUTH_MATRIX
                if actual is True and should is False]

# False negatives: legit NTU emails the gate wrongly DENIES (case-sensitivity).
FALSE_NEGATIVE_CASES = [(cid, email) for (cid, email, actual, should) in AUTH_MATRIX
                        if actual is False and should is True]


def test_auth_gate_admits_lookalike_domains_BYPASS():
    """PROOF of the bypass: every look-alike / no-'@' tail is ADMITTED even
    though correct behaviour would DENY it."""
    assert BYPASS_CASES, "expected at least one bypass case in the matrix"
    for cid, email in BYPASS_CASES:
        assert auth_gate(email) is True, f"[{cid}] {email!r} should be admitted by the buggy gate"
    # Spell out the headline attacker case explicitly for the report.
    assert auth_gate("attacker@evilntu.edu.sg") is True


def test_auth_gate_rejects_uppercase_legit_ntu_FALSE_NEGATIVE():
    """PROOF the gate is case-sensitive: real NTU emails in uppercase are
    wrongly DENIED (usability bug + evidence the check is a raw substring test)."""
    assert FALSE_NEGATIVE_CASES, "expected at least one false-negative case"
    for cid, email in FALSE_NEGATIVE_CASES:
        assert auth_gate(email) is False, f"[{cid}] {email!r} is wrongly denied by the buggy gate"


def test_auth_gate_slice_equals_suffix_check():
    """Explain WHY the bypass exists: 'ntu.edu.sg' is 10 chars and the code
    slices email[-10:], so the membership test collapses into 'endswith'."""
    assert len("ntu.edu.sg") == 10
    for _cid, email, actual, _should in AUTH_MATRIX:
        collapsed = email.endswith("ntu.edu.sg")  # what the slice really does
        assert auth_gate(email) == (collapsed or (email in ())), (
            f"gate for {email!r} does not match the 'endswith' collapse"
        )


def test_home_uses_mutable_preferred_username_claim():
    """Home.py trusts the `preferred_username` claim as identity. That claim is
    user-mutable in Entra ID / AAD, so it is unsafe as an authorization key
    (should use the immutable `oid`/`sub`)."""
    ln, text = _find_line(HOME_SRC, "preferred_username")
    assert ln is not None, "expected Home.py to read preferred_username"
    assert "email" in text and "preferred_username" in text
    # Cited for the report: Home.py:{ln}
    assert ln == 151, f"preferred_username expected on Home.py:151, found on :{ln}"


def test_home_uses_common_authority_tenant():
    """Home.py points MSAL at the multi-tenant `/common` authority, so tokens
    from ANY Microsoft tenant (including personal MSAs) are accepted -- there is
    no tenant restriction backing the email check."""
    ln, text = _find_line(HOME_SRC, "login.microsoftonline.com/common")
    assert ln is not None, "expected Home.py to use the /common authority"
    assert text.endswith("/common'") or "/common" in text
    assert ln == 112, f"/common authority expected on Home.py:112, found on :{ln}"


def test_home_auth_predicate_source_is_the_one_we_mirror():
    """Anchor: assert the raw predicate text really exists in Home.py so the
    mirrored auth_gate() cannot silently drift from the shipped code."""
    ln, _ = _find_line(HOME_SRC, 'in st.session_state.email[-10:]')
    assert ln is not None
    assert 'or st.session_state.email in allowed_users' in HOME_SRC
    assert ln == 168, f"auth predicate expected on Home.py:168, found on :{ln}"


# ===========================================================================
# FINDING 2 -- UNAUTHENTICATED DB CONNECTION  (AN_Util.DBConnector)
#
# DBConnector.__init__ selects its branch on whether DB_USER is None. Home.py
# loads CA_MONGO_DB_USER / _PASS from the environment (Home.py:158-159) but then
# calls DBConnector(DB_HOST) with a SINGLE positional arg (Home.py:161), so
# DB_USER stays None and the unauthenticated MongoClient(DB_HOST) branch runs --
# credentials are silently dropped.
#
# We prove this by replacing pymongo.MongoClient with a spy that records its
# call args, then importing AN_Util and driving DBConnector both ways.
# ===========================================================================

class _MongoClientSpy:
    """Records every constructor call without touching the network."""
    calls = []  # list of (args, kwargs)

    def __init__(self, *args, **kwargs):
        type(self).calls.append((args, kwargs))

    def __getitem__(self, name):  # DBConnector.getDB indexes the client
        return {"__db__": name}


def _install_fake_modules():
    """Fake every heavy / network import AN_Util pulls in at module load, so the
    import is pure and offline. Returns the freshly imported AN_Util module."""
    fake_dotenv = types.ModuleType("dotenv")
    fake_dotenv.load_dotenv = lambda *a, **k: None
    sys.modules["dotenv"] = fake_dotenv

    # langchain_community.vectorstores.azuresearch.AzureSearch
    lc = types.ModuleType("langchain_community")
    lc_vs = types.ModuleType("langchain_community.vectorstores")
    lc_az = types.ModuleType("langchain_community.vectorstores.azuresearch")
    lc_az.AzureSearch = type("AzureSearch", (), {})
    lc.vectorstores = lc_vs
    lc_vs.azuresearch = lc_az
    sys.modules["langchain_community"] = lc
    sys.modules["langchain_community.vectorstores"] = lc_vs
    sys.modules["langchain_community.vectorstores.azuresearch"] = lc_az

    # langchain_openai.AzureOpenAIEmbeddings / AzureChatOpenAI
    lco = types.ModuleType("langchain_openai")
    lco.AzureOpenAIEmbeddings = type("AzureOpenAIEmbeddings", (), {})
    lco.AzureChatOpenAI = type("AzureChatOpenAI", (), {})
    sys.modules["langchain_openai"] = lco

    # langchain.callbacks.get_openai_callback  (+ schema/memory used by Narelle)
    lca = types.ModuleType("langchain")
    lca_cb = types.ModuleType("langchain.callbacks")
    lca_cb.get_openai_callback = lambda *a, **k: None
    lca_schema = types.ModuleType("langchain.schema")
    for _n in ("HumanMessage", "AIMessage", "SystemMessage"):
        setattr(lca_schema, _n, type(_n, (), {"__init__": lambda self, content=None: setattr(self, "content", content)}))
    lca_mem = types.ModuleType("langchain.memory")
    lca_mem.ConversationBufferMemory = type("ConversationBufferMemory", (), {})
    sys.modules["langchain"] = lca
    sys.modules["langchain.callbacks"] = lca_cb
    sys.modules["langchain.schema"] = lca_schema
    sys.modules["langchain.memory"] = lca_mem

    # pymongo.MongoClient -> spy ; bson.objectid.ObjectId -> passthrough
    fake_pymongo = types.ModuleType("pymongo")
    fake_pymongo.MongoClient = _MongoClientSpy
    sys.modules["pymongo"] = fake_pymongo
    fake_bson = types.ModuleType("bson")
    fake_bson_oid = types.ModuleType("bson.objectid")
    fake_bson_oid.ObjectId = lambda x=None: x
    fake_bson.objectid = fake_bson_oid
    sys.modules["bson"] = fake_bson
    sys.modules["bson.objectid"] = fake_bson_oid

    # AN_Util must be importable by name; add the read-only clone to sys.path.
    # Keep the clone truly read-only: never emit .pyc/__pycache__ into it.
    sys.dont_write_bytecode = True
    if SRC_DIR not in sys.path:
        sys.path.insert(0, SRC_DIR)
    sys.modules.pop("AN_Util", None)
    import AN_Util  # noqa: E402
    return AN_Util


@pytest.fixture()
def an_util():
    _MongoClientSpy.calls = []
    mod = _install_fake_modules()
    _MongoClientSpy.calls = []  # discard any import-time noise
    return mod


def test_dbconnector_single_arg_is_unauthenticated(an_util):
    """PROOF: DBConnector(DB_HOST) -- the exact call shape used by Home.py --
    constructs MongoClient WITHOUT username/password."""
    _MongoClientSpy.calls = []
    conn = an_util.DBConnector("mongo-host:27017")
    assert conn is not None
    assert len(_MongoClientSpy.calls) == 1, "MongoClient should be constructed exactly once"
    args, kwargs = _MongoClientSpy.calls[0]
    assert args == ("mongo-host:27017",), f"host should be the only positional arg, got {args!r}"
    assert "username" not in kwargs, f"credentials leaked into single-arg call: {kwargs!r}"
    assert "password" not in kwargs, f"credentials leaked into single-arg call: {kwargs!r}"


def test_dbconnector_with_user_would_authenticate(an_util):
    """Counterfactual: had Home.py passed DB_USER/DB_PASS, MongoClient WOULD get
    credentials -- confirming the class supports auth and the fault is the caller."""
    _MongoClientSpy.calls = []
    an_util.DBConnector("mongo-host:27017", DB_USER="ca_user", DB_PASS="ca_pass")
    args, kwargs = _MongoClientSpy.calls[0]
    assert kwargs.get("username") == "ca_user"
    assert kwargs.get("password") == "ca_pass"


def test_home_reads_db_creds_but_calls_connector_with_one_arg():
    """Source proof of the caller-side fault: Home.py loads CA_MONGO_DB_USER and
    CA_MONGO_DB_PASS from the environment, yet invokes DBConnector with a single
    positional argument, so those credentials are never passed."""
    assert "CA_MONGO_DB_USER" in HOME_SRC
    assert "CA_MONGO_DB_PASS" in HOME_SRC
    ln_user, _ = _find_line(HOME_SRC, "CA_MONGO_DB_USER")
    ln_call, call_text = _find_line(HOME_SRC, "DBConnector(DB_HOST)")
    assert ln_call is not None, "expected the single-arg DBConnector(DB_HOST) call"
    # It is called with exactly one positional arg (no comma / no kwargs inside).
    inside = call_text[call_text.index("DBConnector(") + len("DBConnector("):]
    inside = inside[: inside.index(")")]
    assert inside.strip() == "DB_HOST", f"expected one positional arg 'DB_HOST', got {inside!r}"
    assert "username" not in call_text and "password" not in call_text
    # Cited for the report: creds read on Home.py:{ln_user}, call on Home.py:{ln_call}
    assert ln_call == 161


def test_dbconnector_source_branch_selection():
    """Anchor the branch logic in AN_Util source: auth branch is gated purely on
    DB_USER is not None."""
    assert "if DB_USER is not None:" in AN_UTIL_SRC
    assert "MongoClient(DB_HOST, username=DB_USER, password=DB_PASS)" in AN_UTIL_SRC
    assert "MongoClient(DB_HOST)" in AN_UTIL_SRC


# ===========================================================================
# FINDING 3 -- NO SECRETS IN LLM CONTEXT  (Narelle.__init__ system prompt)
#
# Honest negative control: prove the system prompt string carries NO secret-like
# material. This substantiates the report's claim that prompt-injection cannot
# exfiltrate secrets from context -- because none are placed there. We rebuild the
# EXACT f-string from Narelle.py using dummy env values (no imports, no network).
# ===========================================================================

def _build_narelle_sysmsg():
    """Reproduce the sysmsg f-string from Narelle.__init__ verbatim, with dummy
    env values, so we test the real template without importing/executing Narelle
    (which would construct AzureChatOpenAI + a retriever)."""
    os.environ.setdefault("COURSE_NAME", "SC1015 Introduction to Data Science and AI")
    os.environ.setdefault("LAST_CONTENT_UPDATE", "2024-04-01")
    now = "2026-09-28"
    sysmsg = f"You are a university course assistant. Your name is Narelle. Your task is to answer student queries for the course {os.environ['COURSE_NAME']} based on the information retrieved from the knowledge base (as of {os.environ['LAST_CONTENT_UPDATE']}) along with the conversation with user. There are some terminologies which referring to the same thing, for example: assignment is also refer to assessment, project also refer to mini-project, test also refer to quiz. Week 1 starting from 15 Jan 2024, Week 8 starting from 11 March 2024, while Week 14 starting from 22 April 2024. \n\nIn addition to that, the second half of this course which is the AI part covers the syllabus and content from the textbook named 'Artificial Intelligence: A Modern Approach (3rd edition)' by Russell and Norvig . When user ask for tips or sample questions for AI Quiz or AI Theory Quiz, you can generate a few MCQ questions with the answer based on the textbook, 'Artificial Intelligence: A Modern Approach (3rd edition)' from Chapter 1, 2, 3, 4, and 6. Lastly, remember today is {now} in the format of YYYY-MM-DD.\n\nIf you are unsure how to respond to a query based on the course information provided, just say sorry, inform the user you are not sure, and recommend the user to email to the course coordinator or instructors (smitha@ntu.edu.sg | chinann.ong@ntu.edu.sg)."
    return sysmsg


def test_narelle_sysmsg_template_matches_source():
    """Guard: the reproduced template's static skeleton must actually appear in
    Narelle.py, so this negative proof is about the real prompt."""
    for phrase in (
        "You are a university course assistant. Your name is Narelle.",
        "based on the information retrieved from the knowledge base",
        "just say sorry, inform the user you are not sure",
    ):
        assert phrase in NARELLE_SRC, f"phrase missing from Narelle.py: {phrase!r}"


@pytest.mark.parametrize("token", ["KEY", "PASSWORD", "SECRET", "TOKEN", "APIKEY",
                                   "CONNECTION STRING", "MONGODB", "ENDPOINT"])
def test_narelle_sysmsg_contains_no_secret_words(token):
    """PROOF (negative): no secret-like keyword appears in the system prompt."""
    sysmsg = _build_narelle_sysmsg().upper()
    assert token not in sysmsg, f"unexpected secret-like token {token!r} in system prompt"


def test_narelle_sysmsg_contains_no_secret_patterns():
    """PROOF (negative): no OpenAI-style 'sk-' key, no mongodb:// / postgres://
    connection string, and no obvious KEY=VALUE credential pair in the prompt."""
    sysmsg = _build_narelle_sysmsg()
    assert not re.search(r"\bsk-[A-Za-z0-9]{16,}\b", sysmsg), "OpenAI-style key found"
    assert not re.search(r"(mongodb(\+srv)?|postgres(ql)?|mysql|redis)://", sysmsg, re.I), "connection string found"
    assert not re.search(r"(?i)(api[_-]?key|password|secret|access[_-]?token)\s*[=:]\s*\S+", sysmsg), "credential pair found"
    # Also assert env-var NAMES for secrets are not interpolated into the prompt.
    for name in ("CA_AZURE_VECTORSTORE_KEY", "OPENAI_API_KEY", "CA_MONGO_DB_PASS",
                 "CA_MONGO_DB_HOST", "AZURE_OPENAI_ENDPOINT"):
        assert name not in sysmsg


def test_narelle_source_does_not_inject_secret_env_into_prompt():
    """Source-level guard: the sysmsg line in Narelle.py interpolates only
    COURSE_NAME and LAST_CONTENT_UPDATE from os.environ -- never a secret var."""
    sysmsg_line = next((l for l in NARELLE_SRC.splitlines() if "You are a university course assistant" in l), None)
    assert sysmsg_line is not None
    interpolated = set(re.findall(r"os\.environ\['([^']+)'\]", sysmsg_line))
    assert interpolated <= {"COURSE_NAME", "LAST_CONTENT_UPDATE"}, (
        f"system prompt interpolates unexpected env vars: {interpolated}"
    )
    for secret in ("KEY", "PASS", "SECRET", "TOKEN"):
        assert not any(secret in v for v in interpolated)


# ===========================================================================
# FINDING 4 -- ABSENCE OF CONTROLS  (all *.py)
#
# The app has no rate limiting / quota / throttling and no content moderation /
# refusal / blocklist layer. We prove ABSENCE by grepping every .py file for the
# relevant keywords and asserting none appear.  (We deliberately exclude the
# per-user 'blocked_users' membership check in Home.py: that is an account
# allow/deny list keyed on identity, NOT content moderation of prompts/outputs.)
# ===========================================================================

PY_FILES = {
    "Home.py": HOME_SRC,
    "AN_Util.py": AN_UTIL_SRC,
    "Narelle.py": NARELLE_SRC,
}

RATE_LIMIT_PATTERNS = [
    r"rate[\s_-]?limit", r"\bthrottl", r"\bquota\b", r"\bratelimit",
    r"\bcooldown\b", r"requests[\s_-]?per", r"\bbackoff\b", r"\bsemaphore\b",
    r"\bslowapi\b", r"\blimiter\b",
]

MODERATION_PATTERNS = [
    r"\bmoderat", r"\brefus", r"\bblock[\s_-]?list", r"\bblocklist\b",
    r"\ballowlist\b", r"\bprofanit", r"\btoxic", r"\bjailbreak",
    r"\bguardrail", r"\bsafety[\s_-]?filter", r"openai\.moderations",
    r"content[\s_-]?filter", r"\bsanitiz", r"\bnsfw\b",
]


def _matches(source, patterns):
    hits = []
    for pat in patterns:
        for m in re.finditer(pat, source, re.I):
            hits.append((pat, m.group(0)))
    return hits


@pytest.mark.parametrize("fname", sorted(PY_FILES))
def test_no_rate_limiting_controls(fname):
    """PROOF (absence): no rate-limit / quota / throttle mechanism anywhere."""
    hits = _matches(PY_FILES[fname], RATE_LIMIT_PATTERNS)
    assert not hits, f"unexpected rate-limiting construct in {fname}: {hits}"


@pytest.mark.parametrize("fname", sorted(PY_FILES))
def test_no_moderation_or_refusal_controls(fname):
    """PROOF (absence): no content moderation / refusal / content blocklist layer.

    Note: Home.py's identity-based blocked_users check is intentionally not
    matched by these patterns -- it is account gating, not prompt/output
    moderation."""
    hits = _matches(PY_FILES[fname], MODERATION_PATTERNS)
    assert not hits, f"unexpected moderation/refusal construct in {fname}: {hits}"


def test_blocked_users_is_identity_gating_not_content_moderation():
    """Clarify scope: Home.py DOES have a per-account blocked_users list, but it
    keys on the (mutable) email identity -- it is not content moderation and does
    not throttle usage. Documented here so the 'absence' claim is precise."""
    assert "blocked_users" in HOME_SRC
    assert 'find_one({"status":"blocked"})' in HOME_SRC
    # It gates on identity membership, not on message content.
    assert "st.session_state.email in blocked_users" in HOME_SRC
