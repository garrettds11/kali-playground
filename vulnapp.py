import os
import sqlite3
from flask import Flask, request, g, render_template_string, redirect, url_for

# -------------------------------------------------
# Basic Flask setup
# -------------------------------------------------
app = Flask(__name__)
DATABASE = os.path.join(os.path.dirname(__file__), "vulnapp.db")


# -------------------------------------------------
# Database helpers
# -------------------------------------------------
def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()


def init_db():
    """Initialize the database and seed some data if empty."""
    if not os.path.exists(DATABASE):
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()

        # Very simple schema
        c.execute("""
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                email TEXT NOT NULL
            );
        """)

        c.execute("""
            CREATE TABLE comments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                content TEXT NOT NULL
            );
        """)

        # Seed some users
        c.executemany("""
            INSERT INTO users (username, email) VALUES (?, ?)
        """, [
            ("alice", "alice@example.com"),
            ("bob", "bob@example.com"),
            ("charlie", "charlie@example.com"),
        ])

        # Seed one comment
        c.execute("""
            INSERT INTO comments (content) VALUES
            ('Welcome to vulnapp! Try posting something…')
        """)

        conn.commit()
        conn.close()
        print("[*] Database initialized at", DATABASE)


# -------------------------------------------------
# Templates (inline for simplicity)
# -------------------------------------------------
BASE_TEMPLATE = """
<!doctype html>
<html>
  <head>
    <meta charset="utf-8">
    <title>VulnApp Lab</title>
    <style>
      body { font-family: Arial, sans-serif; margin: 2rem; }
      header { margin-bottom: 1.5rem; }
      nav a { margin-right: 1rem; }
      .container { max-width: 800px; }
      .card { border: 1px solid #ccc; padding: 1rem; margin-bottom: 1rem; border-radius: 4px; }
      .danger { color: #b00020; font-weight: bold; }
      code { background: #f4f4f4; padding: 0.1rem 0.3rem; border-radius: 3px; }
      textarea { width: 100%; height: 80px; }
      input[type="text"] { width: 100%; }
      input[type="submit"], button { padding: 0.4rem 0.8rem; }
    </style>
  </head>
  <body>
    <header>
      <h1>VulnApp Lab</h1>
      <nav>
        <a href="{{ url_for('index') }}">Home</a>
        <a href="{{ url_for('search') }}">User Search (SQLi)</a>
        <a href="{{ url_for('comments') }}">Comments (Stored XSS)</a>
      </nav>
      <p class="danger">
        This app is intentionally vulnerable. Do NOT expose it to the internet.
      </p>
      <hr>
    </header>
    <div class="container">
      {% block content %}{% endblock %}
    </div>
  </body>
</html>
"""

INDEX_TEMPLATE = """
{% extends "base" %}
{% block content %}
  <div class="card">
    <h2>Welcome</h2>
    <p>
      This is a deliberately vulnerable app for local testing. It includes:
    </p>
    <ul>
      <li><strong>SQL Injection</strong> in the user search feature.</li>
      <li><strong>Stored XSS</strong> in the comments section.</li>
    </ul>
    <p>
      Suggested attacks:
    </p>
    <ul>
      <li>Try SQL injection in <a href="{{ url_for('search') }}">User Search</a>.</li>
      <li>Try inserting HTML/JS in <a href="{{ url_for('comments') }}">Comments</a> such as
        <code>&lt;script&gt;alert('XSS')&lt;/script&gt;</code>.
      </li>
    </ul>
  </div>
{% endblock %}
"""

SEARCH_TEMPLATE = """
{% extends "base" %}
{% block content %}
  <div class="card">
    <h2>User Search (SQL Injection)</h2>
    <p>
      Search for a username. The query is <strong>intentionally vulnerable</strong>:
      user input is concatenated directly into the SQL string.
    </p>
    <p>
      Try payloads like:
      <code>' OR 1=1--</code>
    </p>
    <form method="get">
      <label for="q">Username contains:</label><br>
      <input type="text" id="q" name="q" value="{{ q|default('') }}">
      <br><br>
      <input type="submit" value="Search">
    </form>
  </div>

  {% if query is defined %}
    <div class="card">
      <h3>Raw SQL query (vulnerable):</h3>
      <pre>{{ query }}</pre>
    </div>
  {% endif %}

  {% if results is defined %}
    <div class="card">
      <h3>Results</h3>
      {% if results %}
        <ul>
        {% for row in results %}
          <li>#{{ row.id }} - {{ row.username }} ({{ row.email }})</li>
        {% endfor %}
        </ul>
      {% else %}
        <p>No matches found.</p>
      {% endif %}
    </div>
  {% endif %}
{% endblock %}
"""

COMMENTS_TEMPLATE = """
{% extends "base" %}
{% block content %}
  <div class="card">
    <h2>Comments (Stored XSS)</h2>
    <p>
      Anything you post here is stored and rendered <strong>without HTML escaping</strong>.
      This means you can inject scripts, if the browser allows it.
    </p>
    <p>Example payload: <code>&lt;script&gt;alert('XSS')&lt;/script&gt;</code></p>

    <form method="post">
      <label for="content">New comment:</label><br>
      <textarea id="content" name="content"></textarea><br><br>
      <input type="submit" value="Post comment">
    </form>
  </div>

  <div class="card">
    <h3>All Comments</h3>
    {% if comments %}
      <ul>
        {# NOTE: We intentionally use |safe to disable escaping #}
        {% for c in comments %}
          <li>{{ c.content|safe }}</li>
        {% endfor %}
      </ul>
    {% else %}
      <p>No comments yet.</p>
    {% endif %}
  </div>
{% endblock %}
"""


# -------------------------------------------------
# Template rendering helpers
# -------------------------------------------------
@app.context_processor
def inject_base_template():
    # This lets us use {% extends "base" %} with an inline template
    return {"base": BASE_TEMPLATE}


def render(tpl, **context):
    # render_template_string with base template support
    full_template = "{% extends 'base' %}{% block content %}" + tpl + "{% endblock %}"
    # But since we defined full page templates already extending base,
    # we'll just pass them through directly where needed.
    return render_template_string(tpl, **context)


# -------------------------------------------------
# Routes
# -------------------------------------------------
@app.route("/")
def index():
    return render_template_string(INDEX_TEMPLATE, base=BASE_TEMPLATE)


@app.route("/search")
def search():
    q = request.args.get("q", "")
    results = None
    query = None

    if q:
        db = get_db()

        # ⚠️ INTENTIONALLY VULNERABLE TO SQL INJECTION
        query = f"SELECT id, username, email FROM users WHERE username LIKE '%{q}%'"
        cur = db.execute(query)
        results = cur.fetchall()

    return render_template_string(
        SEARCH_TEMPLATE,
        base=BASE_TEMPLATE,
        q=q,
        query=query,
        results=results,
    )


@app.route("/comments", methods=["GET", "POST"])
def comments():
    db = get_db()

    if request.method == "POST":
        content = request.form.get("content", "")

        # ⚠️ INTENTIONALLY STORED XSS
        # We store raw user input and later render it with |safe
        if content.strip():
            db.execute("INSERT INTO comments (content) VALUES (?)", (content,))
            db.commit()
        return redirect(url_for("comments"))

    cur = db.execute("SELECT id, content FROM comments ORDER BY id DESC")
    comments = cur.fetchall()

    return render_template_string(
        COMMENTS_TEMPLATE,
        base=BASE_TEMPLATE,
        comments=comments,
    )


# -------------------------------------------------
# Entry point
# -------------------------------------------------
if __name__ == "__main__":
    init_db()
    # Listen on all interfaces so you can hit it from Kali / Tailscale
    app.run(host="0.0.0.0", port=5000, debug=True)
