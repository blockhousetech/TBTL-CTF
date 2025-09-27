from flask import Flask, request, redirect, render_template
from threading import Thread
from datetime import datetime, timedelta
import time
from collections import deque
from html import escape
from urllib.parse import urlparse

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    print(request.form, request.args)
    return "Hi there"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8888)
