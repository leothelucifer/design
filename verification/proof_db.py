# Mirrors AN_Util.DBConnector branch selection + how Home.py calls it.
def DBConnector(DB_HOST, DB_USER=None, DB_PASS=None):
    if DB_USER is not None:
        return f"AUTHENTICATED MongoClient(host, username={DB_USER!r}, password=***)"
    else:
        return "UNAUTHENTICATED MongoClient(host)   <-- credentials NOT applied"

# Home.py reads these from env...
DB_USER = "ca_user"; DB_PASS = "ca_pass"
# ...but calls the connector with ONE argument (exactly as in Home.py):
print("Home.py call ->", DBConnector("mongo-host:27017"))
print("(DB_USER / DB_PASS were loaded but never passed => else-branch runs)")
