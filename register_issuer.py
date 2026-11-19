import json
import base64
import hashlib
import psycopg

p = json.load(open("/var/lib/pqc-keys/demo_issuer_ml_dsa.json"))
pub = base64.b64decode(p["public_key"])
fp = hashlib.sha256(pub).hexdigest()

conn = psycopg.connect("postgresql://verifier:verifier@db:5432/verifier")
cur = conn.cursor()

cur.execute(
    """
    INSERT INTO issuers
        (issuer_id, organization, public_key, key_fingerprint, signing_algorithm, status)
    VALUES
        (%s, %s, %s, %s, %s, %s)
    ON CONFLICT (issuer_id) DO NOTHING
    """,
    (
        "university-issuing-authority-v1",
        "University Issuing Authority",
        pub,
        fp,
        "ML-DSA-65",
        "ACTIVE",
    ),
)

conn.commit()

print("Issuer registered:", fp)

cur.close()
conn.close()
