from flask import Flask, request, render_template, redirect
import sqlite3

app = Flask(__name__)


@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')


@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')

    query = f'SELECT username, password FROM users WHERE username = "{username}" AND password = "{password}";'

    try:
        con = sqlite3.connect('users.db')
        cur = con.cursor()
        row = cur.execute(query).fetchone()
        cur.close()
        con.close()

        if row is None:
            return redirect("/")

        (db_username, db_password) = row

        if db_username != username or db_password != password:
            return redirect("/")

    except Exception:
        return redirect("/")

    return render_template('flag.html')
