#!/usr/bin/env bash
set -euo pipefail

DB_PATH="/ctf/app/eudi.db"
SCHEMA_PATH="/ctf/app/schema.sql"
SEED_PY="/ctf/app/seed.py"

if [ ! -f "$DB_PATH" ]; then
  echo "[*] No database found."
  if [ -f "$SEED_PY" ]; then
    echo "[*] seed.py found -> running seed.py"
    python "$SEED_PY"
  else
    echo "[*] seed.py not found -> applying schema only"
    python - <<'PY'
import sqlite3
db_path = "/ctf/app/eudi.db"
schema_path = "/ctf/app/schema.sql"
con = sqlite3.connect(db_path)
con.executescript(open(schema_path).read())
con.commit()
con.close()
print("[*] Schema applied].")
PY
  fi
fi

export FLASK_APP=app.app:app
export FLASK_ENV=production
flask run --host=0.0.0.0 --port=8000
