# Reproduces the EXACT gate from Home.py, line ~162:
#   elif "ntu.edu.sg" in st.session_state.email[-10:] or email in allowed_users:
# No app, no network, no login — just the decision logic.
def is_allowed(email, allowed_users=()):
    return ("ntu.edu.sg" in email[-10:]) or (email in allowed_users)

cases = [
    ("legit NTU student",        "alice@e.ntu.edu.sg"),
    ("legit NTU staff",          "bob@ntu.edu.sg"),
    ("random gmail (should FAIL)","attacker@gmail.com"),
    ("look-alike domain tail",   "attacker@evilntu.edu.sg"),  # ends in 'ntu.edu.sg'
    ("subdomain look-alike",     "mallory@notntu.edu.sg"),
]
print(f"{'ADMITTED?':10} {'case':28} email")
for name, email in cases:
    verdict = "ALLOW" if is_allowed(email) else "deny "
    print(f"{verdict:10} {name:28} {email}   (email[-10:]={email[-10:]!r})")
