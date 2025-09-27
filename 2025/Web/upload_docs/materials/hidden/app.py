from flask import Flask, request, redirect, render_template, make_response
from threading import Thread
from datetime import datetime, timedelta
import time
from collections import deque
from html import escape
from urllib.parse import urlparse
import uuid
import os
import admin as admin_page

app = Flask(__name__)

submitted_links = deque()

admin_secret = os.getenv("ADMIN_SECRET")

@app.route("/", methods=["GET", "POST"])
def index():
    user_id = request.cookies.get('user_id')
    if request.method == "POST":
        username = escape(request.form.get("username"))
        link = request.form.get("link")
        if username and is_valid_url(link) and len(submitted_links) < 1000:
            submitted_links.append(
                {"username": username.strip()[:200],
                 "link": link.strip()[:200],
                 "time": datetime.now(),
                 "user_id": user_id,
                })
        return redirect("/")

    secret = request.args.get('secret')
    target_user = request.args.get('target_user')

    response = make_response(render_template("index.html", links=(s for s in submitted_links if s["user_id"] == user_id or (secret == admin_secret and s["user_id"] == target_user))))

    if not user_id:
        user_id =  str(uuid.uuid4())
        response.set_cookie('user_id', user_id)

    return response

@app.route("/admin", methods=["GET"])
def admin():
    target_user = request.args.get('target_user')
    admin_page.visit_page(target_user)
    return "The admin is looking at his screen now."


@app.route("/get_flag", methods=["GET"])
def get_flag():
    if request.remote_addr in ("127.0.0.1", "::1"):
        return os.getenv("FLAG")
    else:
        return "No flag for you!"

def is_valid_url(url):
    try:
        parsed = urlparse(url)
        return parsed.scheme in ("https") and parsed.netloc
    except Exception:
        return False

def delete_links():
    while True:
        time.sleep(10)
        now = datetime.now()
        while len(submitted_links) > 0:
            if submitted_links[0]["time"] + timedelta(seconds=60) < now:
                print(f"Link removed: {submitted_links[0]['link']}")
                submitted_links.popleft()
            else:
                break

Thread(target=delete_links, daemon=True).start()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
