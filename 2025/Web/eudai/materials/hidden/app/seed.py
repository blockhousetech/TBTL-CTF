\
import os, sqlite3, json, secrets, random, datetime, base64, hashlib
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

DB_PATH = "/ctf/app/eudi.db"
SCHEMA_PATH = "/ctf/app/schema.sql"
PRIVATE_PATH = "/ctf/issuer_private.pem"
PUBLIC_PATH  = "/ctf/issuer_public.pem"

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def connect():
    con = sqlite3.connect(DB_PATH); con.row_factory = sqlite3.Row; return con

def init_db(con):
    con.executescript(open(SCHEMA_PATH).read()); con.commit()

def canonical_encode(value):
    if isinstance(value, bool): return b"true" if value else b"false"
    if isinstance(value, int): return str(value).encode()
    return str(value).encode()

def compute_d(salt_bytes: bytes, claim_value) -> bytes:
    h = hashlib.sha256(); h.update(salt_bytes); h.update(canonical_encode(claim_value)); return h.digest()

def build_m_from_map(digests_map_hex):
    return b"".join(bytes.fromhex(digests_map_hex[k]) for k in sorted(digests_map_hex.keys()))

def load_private_key():
    with open(PRIVATE_PATH,"rb") as f: return serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

def seed_users_planned(con, total=160, decoy_bills=10, decoy_roscoes=10):
    domains = ["example.local", "mail.local", "demo.local"]
    first_names = ["Alex","Sam","Taylor","Jamie","Jordan","Casey","Charlie","Avery","Riley","Drew","Morgan","Quinn","Reese","Parker","Bailey","Hayden","Corey","Logan","Cameron","Rowan","Elliot","Harper","Skyler","Emerson","Sawyer","Phoenix"]
    last_names  = ["Smith","Johnson","Brown","Williams","Jones","Miller","Davis","Wilson","Anderson","Thomas","Jackson","Harris","Martin","Thompson","White","Clark","Lewis","Walker","Young","Allen","Wright","King","Hill","Green","Adams","Baker","Scott","Cooper","Evans","Turner","Parker","Collins","Morgan","Ward","Cook","Price","Murphy","Bell","Bailey","Morris","King"]
    planned=[("Bill","Roscoe")]
    ln_pool=[ln for ln in last_names if ln!="Roscoe"]
    for _ in range(decoy_bills): planned.append(("Bill", random.choice(ln_pool)))
    fn_pool=[fn for fn in first_names if fn!="Bill"]
    for _ in range(decoy_roscoes): planned.append((random.choice(fn_pool), "Roscoe"))
    while len(planned) < total:
        fn=random.choice(fn_pool); ln=random.choice(last_names)
        if (fn,ln)==("Bill","Roscoe"): continue
        planned.append((fn,ln))
    random.shuffle(planned)
    mapping=[]
    for fn,ln in planned:
        local=f"{fn.lower()}.{ln.lower()}{random.randint(10,99)}"; email=f"{local}@{random.choice(domains)}"
        garbage = base64.urlsafe_b64encode(os.urandom(48)).decode().rstrip("=")
        cur = con.execute("INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)", (email, garbage, datetime.datetime.utcnow().isoformat()))
        mapping.append((cur.lastrowid, fn, ln))
    con.commit(); return mapping

def seed_presentations_only(con, mapping):
    priv = load_private_key()
    REAL_FLAG = "FortID{6fce6c5b26c3b226fabea7d76bca7447}"
    def make_claims(g,f,flag):
        today=datetime.date.today()
        return {"family_name":f,"given_name":g,"birth_date":f"{random.randint(1970,2002)}-{random.randint(1,12):02d}-{random.randint(1,28):02d}","age_over_18":True,"issuance_date":today.isoformat(),"expiry_date":datetime.date(today.year+5,today.month,min(today.day,28)).isoformat(),"issuing_authority":"EUDI PID Authority","issuing_country":random.choice(["HR","SI","HU","AT","DE","IT","BA","RS"]),"flag":flag}
    admin_uid = next(uid for uid,fn,ln in mapping if fn=="Bill" and ln=="Roscoe")
    all_pres=[]
    for uid,fn,ln in mapping:
        flag=REAL_FLAG if uid==admin_uid else f"FortID{{{secrets.token_hex(16)}}}"
        claims=make_claims(fn,ln,flag)
        salts={}; digests={}
        for k in sorted(claims.keys()):
            s=secrets.token_bytes(32); d=compute_d(s, claims[k]); salts[k]=s.hex(); digests[k]=d.hex()
        m = build_m_from_map(digests)
        sig = priv.sign(m, ec.ECDSA(hashes.SHA256()))
        for claim_name in claims.keys():
            disclosed={claim_name:claims[claim_name]}
            disclosed_salts={claim_name:salts[claim_name]}
            hidden={k:digests[k] for k in claims.keys() if k!=claim_name}
            pres={"issuer_kid":"pid-issuer-key-1","disclosed":disclosed,"salts":disclosed_salts,"hidden_digests":hidden,"sig":b64url(sig),"verifier":random.choice(["bank","gov","club"]),"created_at":datetime.datetime.utcnow().isoformat()}
            enc=b64url(json.dumps(pres, separators=(",",":")).encode())
            all_pres.append((None, enc))  # owner_user_id=NULL
    random.shuffle(all_pres)
    now=datetime.datetime.utcnow()
    for owner,enc in all_pres:
        delta=datetime.timedelta(days=random.randint(0,7),hours=random.randint(0,23),minutes=random.randint(0,59),seconds=random.randint(0,59))
        ts=(now-delta).isoformat()
        con.execute("INSERT INTO presentations (encoded, owner_user_id, created_at) VALUES (?, ?, ?)", (enc, owner, ts))
    con.commit(); print(f"Seeded {len(all_pres)} presentations (owner_user_id=NULL).")

def main():
    con=connect(); init_db(con)
    mapping=seed_users_planned(con, total=160, decoy_bills=10, decoy_roscoes=10)
    seed_presentations_only(con, mapping)
    con.close(); print("Seed complete.")

if __name__=="__main__":
    main()
