import os
import sqlite3
import json
import base64
import secrets
import hashlib
import datetime
import re
from flask import Flask, render_template, request, redirect, url_for, session, flash, g, abort
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

DB_PATH = "/ctf/app/eudi.db"
SCHEMA_PATH = "/ctf/app/schema.sql"
PRIVATE_PATH = "/ctf/issuer_private.pem"
PUBLIC_PATH = "/ctf/issuer_public.pem"

app = Flask(__name__)
app.secret_key = os.environ.get("EUDI_SECRET", "dev-secret-change-me")


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    with open(SCHEMA_PATH, "r") as f:
        db.executescript(f.read())
    db.commit()


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def unb64url(s: str) -> bytes:
    pad = "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode(s + pad)


def load_private_key():
    with open(PRIVATE_PATH, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())


def load_public_key():
    with open(PUBLIC_PATH, "rb") as f:
        return serialization.load_pem_public_key(f.read(), backend=default_backend())


def canonical_encode(value):
    if isinstance(value, bool):
        return b"true" if value else b"false"
    if isinstance(value, int):
        return str(value).encode()
    return str(value).encode()


def compute_d(salt_bytes: bytes, claim_value) -> bytes:
    h = hashlib.sha256()
    h.update(salt_bytes)
    h.update(canonical_encode(claim_value))
    return h.digest()


def build_m_from_map(digests_map_hex):
    return b"".join(bytes.fromhex(digests_map_hex[k]) for k in sorted(digests_map_hex.keys()))


def current_user():
    return session.get("user")


@app.route("/")
def home():
    return render_template("home.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", username):
            flash("Please use a valid email.")
            return redirect(url_for("register"))
        ph = generate_password_hash(password)
        db = get_db()
        try:
            db.execute("INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
                       (username, ph, datetime.datetime.utcnow().isoformat()))
            db.commit()
            flash("Account created. Please log in.")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Email already exists.")
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    pref_username = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        db = get_db()
        sql = f"SELECT id, username, password_hash FROM users WHERE username = '{username}'"
        try:
            row = db.execute(sql).fetchone()
        except sqlite3.Error:
            flash("Login error.")
            return render_template("login.html", pref_username=username)
        ok = False
        if row:
            try:
                ok = check_password_hash(row["password_hash"], password)
            except Exception:
                ok = False
        if row and ok:
            session["user"] = {"id": row["id"], "username": row["username"]}
            return redirect(url_for("profile"))
        pref_username = row["username"] if row else username
        flash("Invalid credentials")
    return render_template("login.html", pref_username=pref_username)


@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out.")
    return redirect(url_for("home"))


def require_login():
    if not current_user():
        flash("Please login.")
        return redirect(url_for("login"))


@app.route("/profile")
def profile():
    if not current_user():
        return require_login()
    db = get_db()
    user = current_user()
    creds = db.execute(
        "SELECT id, ctype, claims_json, issued_at FROM credentials WHERE owner_user_id = ? ORDER BY id DESC", (user["id"],)).fetchall()
    creds_fmt = [{"id": c["id"], "ctype": c["ctype"], "claims_json": json.loads(
        c["claims_json"]), "issued_at": c["issued_at"]} for c in creds]
    return render_template("profile.html", user=user, credentials=creds_fmt)


@app.route("/issue", methods=["GET", "POST"])
def issue():
    if not current_user():
        return require_login()
    if request.method == "GET":
        today = datetime.date.today()
        return render_template("issue.html", default_issuance=today.isoformat(), default_expiry=datetime.date(today.year+5, today.month, min(today.day, 28)).isoformat())
    family_name = request.form.get("family_name", "").strip()
    given_name = request.form.get("given_name", "").strip()
    birth_date = request.form.get("birth_date", "").strip()
    age_over_18 = bool(request.form.get("age_over_18"))
    nationality = request.form.get("nationality", "").strip() or None
    issuing_authority = request.form.get("issuing_authority", "").strip()
    issuing_country = request.form.get("issuing_country", "").strip()
    issuance_date = request.form.get("issuance_date", "").strip()
    expiry_date = request.form.get("expiry_date", "").strip()
    document_number = request.form.get("document_number", "").strip() or None
    include_flag = request.form.get("include_flag") == "on"
    claims = {"family_name": family_name, "given_name": given_name, "birth_date": birth_date, "age_over_18": age_over_18,
              "issuance_date": issuance_date, "expiry_date": expiry_date, "issuing_authority": issuing_authority, "issuing_country": issuing_country}
    if nationality:
        claims["nationality"] = nationality
    if document_number:
        claims["document_number"] = document_number
    if include_flag:
        claims["flag"] = f"FortID{{{secrets.token_hex(16)}}}"
    salts = {}
    digests = {}
    for k in sorted(claims.keys()):
        s = secrets.token_bytes(32)
        d = hashlib.sha256(s + (str(claims[k]).encode() if not isinstance(
            claims[k], bool) else (b"true" if claims[k] else b"false"))).hexdigest()
        salts[k] = s.hex()
        digests[k] = d
    db = get_db()
    db.execute("""INSERT INTO credentials (ctype, owner_user_id, claims_json, issuer_kid, issued_at, salts_json, digests_json)
                  VALUES (?, ?, ?, ?, ?, ?, ?)""",
               ("PID", current_user()["id"], json.dumps(claims), "pid-issuer-key-1", datetime.datetime.utcnow().isoformat(), json.dumps(salts), json.dumps(digests)))
    db.commit()
    flash("Credential issued to wallet.")
    return redirect(url_for("profile"))


@app.route("/present", methods=["GET", "POST"])
def present():
    if not current_user():
        return require_login()
    db = get_db()
    cred = db.execute("SELECT * FROM credentials WHERE owner_user_id = ? ORDER BY id DESC LIMIT 1",
                      (current_user()["id"],)).fetchone()
    if request.method == "GET":
        if not cred:
            flash("No credential. Please issue one first.")
            return redirect(url_for("issue"))
        return render_template("present.html", credential=cred, claims=json.loads(cred["claims_json"]))
    if not cred or str(cred["id"]) != str(request.form.get("credential_id")):
        abort(400)
    claims = json.loads(cred["claims_json"])
    salts = json.loads(cred["salts_json"])
    digests = json.loads(cred["digests_json"])
    presented = {}
    disclosed_salts = {}
    hidden_digests = {}
    for k in claims.keys():
        if request.form.get(f"claim_{k}"):
            presented[k] = claims[k]
            disclosed_salts[k] = salts[k]
        else:
            hidden_digests[k] = digests[k]
    full_map = dict(hidden_digests)
    for k, v in presented.items():
        s = bytes.fromhex(disclosed_salts[k])
        full_map[k] = hashlib.sha256(
            s + (str(v).encode() if not isinstance(v, bool) else (b"true" if v else b"false"))).hexdigest()
    m = b"".join(bytes.fromhex(full_map[k]) for k in sorted(full_map.keys()))
    with open(PRIVATE_PATH, "rb") as f:
        priv = serialization.load_pem_private_key(
            f.read(), password=None, backend=default_backend())
    signature = priv.sign(m, ec.ECDSA(hashes.SHA256()))
    presentation = {"issuer_kid": "pid-issuer-key-1", "disclosed": presented, "salts": disclosed_salts, "hidden_digests": hidden_digests,
                    "sig": b64url(signature), "verifier": request.form.get("verifier", "bank"), "created_at": datetime.datetime.utcnow().isoformat()}
    encoded = b64url(json.dumps(presentation, separators=(",", ":")).encode())
    db.execute("INSERT INTO presentations (encoded, owner_user_id, created_at) VALUES (?, ?, ?)",
               (encoded, current_user()["id"], presentation["created_at"]))
    db.commit()
    return render_template("present_result.html", encoded=encoded, presented=presented)


@app.route("/verify", methods=["GET", "POST"])
def verify():
    result = None
    if request.method == "POST":
        encoded = request.form.get("encoded", "").strip()
        verifier = request.form.get("verifier", "bank")
        try:
            data = json.loads(unb64url(encoded))
        except Exception:
            flash("Could not decode presentation.")
            return render_template("verify.html", result=None)
        with open(PUBLIC_PATH, "rb") as f:
            public_key = serialization.load_pem_public_key(
                f.read(), backend=default_backend())
        disclosed = data.get("disclosed", {})
        salts = data.get("salts", {})
        hidden = data.get("hidden_digests", {})
        sig = unb64url(data.get("sig", ""))
        recomputed = {}
        for k, v in disclosed.items():
            if k not in salts:
                flash("Missing salt for disclosed claim.")
                return render_template("verify.html", result=None)
            try:
                s = bytes.fromhex(salts[k])
            except ValueError:
                flash("Invalid salt encoding.")
                return render_template("verify.html", result=None)
            recomputed[k] = hashlib.sha256(
                s + (str(v).encode() if not isinstance(v, bool) else (b"true" if v else b"false"))).hexdigest()
        digests_map = dict(hidden)
        digests_map.update(recomputed)
        m = b"".join(bytes.fromhex(digests_map[k])
                     for k in sorted(digests_map.keys()))
        try:
            public_key.verify(sig, m, ec.ECDSA(hashes.SHA256()))
            chains = True
        except Exception:
            chains = False
        result = type("R", (), {"verifier": verifier,
                      "chains": chains, "claims": disclosed})
    return render_template("verify.html", result=result)


if __name__ == "__main__":
    if not os.path.exists(DB_PATH):
        with app.app_context():
            init_db()
    app.run(debug=True)
