const express = require("express");
const path = require("path");
const fs = require("fs");
const sqlite3 = require("sqlite3").verbose();
const multer = require("multer");

const app = express();
const PORT = 5000;
const DB_PATH = path.join(__dirname, "vulnapp-node.db");
const UPLOAD_DIR = path.join(__dirname, "uploads");

// ---------------------------------------------------------
// Ensure uploads directory exists
// ---------------------------------------------------------
if (!fs.existsSync(UPLOAD_DIR)) {
  fs.mkdirSync(UPLOAD_DIR);
}

// Multer config: store files with original filename (⚠ unsafe)
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, UPLOAD_DIR);
  },
  filename: (req, file, cb) => {
    // ⚠ no sanitization; attacker can upload .html/.js/.php/etc
    cb(null, file.originalname);
  }
});
const upload = multer({ storage });

// ---------------------------------------------------------
// DB INIT
// ---------------------------------------------------------
function initDb() {
  const dbExists = fs.existsSync(DB_PATH);
  const db = new sqlite3.Database(DB_PATH);

  if (!dbExists) {
    console.log("[*] Initializing SQLite database at", DB_PATH);

    db.serialize(() => {
      db.run(`
        CREATE TABLE users (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          username TEXT NOT NULL,
          email TEXT NOT NULL,
          password TEXT NOT NULL
        )
      `);

      db.run(`
        CREATE TABLE comments (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          content TEXT NOT NULL
        )
      `);

      db.run(`
        CREATE TABLE uploads (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          filename TEXT NOT NULL,
          original_name TEXT NOT NULL
        )
      `);

      const userStmt = db.prepare(
        "INSERT INTO users (username, email, password) VALUES (?, ?, ?)"
      );
      userStmt.run("alice", "alice@example.com", "password123");
      userStmt.run("bob", "bob@example.com", "hunter2");
      userStmt.run("charlie", "charlie@example.com", "letmein");
      userStmt.finalize();

      db.run(
        "INSERT INTO comments (content) VALUES (?)",
        ["Welcome to vulnapp-node! Try posting something…"]
      );
    });
  }

  return db;
}

const db = initDb();

// ---------------------------------------------------------
// MIDDLEWARE
// ---------------------------------------------------------
app.use(express.urlencoded({ extended: true }));

// Serve uploaded files directly (⚠ unsafe)
app.use("/uploads", express.static(UPLOAD_DIR));

// ---------------------------------------------------------
// VERY BASIC HTML LAYOUT
// ---------------------------------------------------------
function layout(contentHtml) {
  return `
<!doctype html>
<html>
  <head>
    <meta charset="utf-8">
    <title>VulnApp Node Lab</title>
    <style>
      body { font-family: Arial, sans-serif; margin: 2rem; }
      header { margin-bottom: 1.5rem; }
      nav a { margin-right: 1rem; }
      .container { max-width: 900px; }
      .card { border: 1px solid #ccc; padding: 1rem; margin-bottom: 1rem; border-radius: 4px; }
      .danger { color: #b00020; font-weight: bold; }
      .ok { color: #006400; font-weight: bold; }
      code { background: #f4f4f4; padding: 0.1rem 0.3rem; border-radius: 3px; }
      textarea { width: 100%; height: 80px; }
      input[type="text"], input[type="password"], input[type="file"] { width: 100%; }
      input[type="submit"], button { padding: 0.4rem 0.8rem; margin-top: 0.5rem; }
      table { width: 100%; border-collapse: collapse; }
      th, td { border: 1px solid #ddd; padding: 0.5rem; }
      th { background-color: #f4f4f4; }
    </style>
  </head>
  <body>
    <header>
      <h1>VulnApp Node Lab</h1>
      <nav>
        <a href="/">Home</a>
        <a href="/login">Login (SQLi)</a>
        <a href="/search">User Search (SQLi)</a>
        <a href="/comments">Comments (Stored XSS)</a>
        <a href="/upload">File Upload</a>
      </nav>
      <p class="danger">
        This app is intentionally vulnerable. Do NOT expose it to the internet.
      </p>
      <hr>
    </header>
    <div class="container">
      ${contentHtml}
    </div>
  </body>
</html>
`;
}

// ---------------------------------------------------------
// ROUTES
// ---------------------------------------------------------

// Home
app.get("/", (req, res) => {
  const html = `
  <div class="card">
    <h2>Welcome</h2>
    <p>
      This is a deliberately vulnerable Node/Express app for local testing. It includes:
    </p>
    <ul>
      <li><strong>SQL Injection</strong> in the user search feature.</li>
      <li><strong>SQL Injection</strong> in the login form.</li>
      <li><strong>Stored XSS</strong> in the comments section.</li>
      <li><strong>Unsafe file upload</strong> with web-accessible uploads.</li>
    </ul>
    <p>
      Suggested attacks:
    </p>
    <ul>
      <li>SQLi on <a href="/login">/login</a> (bypass auth).</li>
      <li>SQLi on <a href="/search">/search</a> (dump users).</li>
      <li>Stored XSS on <a href="/comments">/comments</a>.</li>
      <li>Upload a <code>.html</code> or <code>.js</code> file and browse it via <code>/uploads/&lt;filename&gt;</code>.</li>
    </ul>
  </div>
  `;
  res.send(layout(html));
});

// ---------------------------------------------------------
// Insecure LOGIN (SQLi on username+password)
// ---------------------------------------------------------
app.get("/login", (req, res) => {
  const msg = req.query.msg || "";
  const msgClass = req.query.ok === "1" ? "ok" : "danger";
  const html = `
  <div class="card">
    <h2>Login (SQL Injection)</h2>
    <p>
      This login form is <strong>intentionally unsafe</strong>. It:
    </p>
    <ul>
      <li>Stores passwords in plaintext.</li>
      <li>Concatenates username and password directly into the SQL query.</li>
      <li>Has no rate limiting or lockout.</li>
    </ul>
    <p>Try payloads like:</p>
    <ul>
      <li><code>' OR '1'='1</code> (for username or password)</li>
      <li><code>alice' --</code> as username with any password</li>
    </ul>

    <form method="post">
      <label for="username">Username:</label><br>
      <input type="text" name="username" id="username"><br><br>

      <label for="password">Password:</label><br>
      <input type="password" name="password" id="password"><br><br>

      <input type="submit" value="Login">
    </form>
  </div>

  ${
    msg
      ? `<div class="card"><p class="${msgClass}">${escapeHtml(msg)}</p></div>`
      : ""
  }
  `;
  res.send(layout(html));
});

app.post("/login", (req, res) => {
  const username = req.body.username || "";
  const password = req.body.password || "";

  // ⚠️ INTENTIONALLY VULNERABLE:
  // Direct string concatenation with user-supplied username/password.
  const sql =
    "SELECT id, username, email FROM users WHERE username = '" +
    username +
    "' AND password = '" +
    password +
    "'";

  db.all(sql, [], (err, rows) => {
    if (err) {
      console.error("Login error:", err);
      return res.redirect(
        "/login?msg=" + encodeURIComponent("Error executing query") + "&ok=0"
      );
    }

    if (rows && rows.length > 0) {
      const user = rows[0];
      const msg =
        "Login successful as " +
        user.username +
        " (" +
        user.email +
        "). NOTE: This login is NOT actually creating a secure session.";
      return res.redirect("/login?msg=" + encodeURIComponent(msg) + "&ok=1");
    } else {
      return res.redirect(
        "/login?msg=" +
          encodeURIComponent("Invalid username or password (or try SQLi!)") +
          "&ok=0"
      );
    }
  });
});

// ---------------------------------------------------------
// SQL Injection search
// ---------------------------------------------------------
app.get("/search", (req, res) => {
  const q = req.query.q || "";
  let resultsHtml = "";
  let queryShown = "";

  if (q) {
    // ⚠️ INTENTIONALLY VULNERABLE
    const vulnerableQuery =
      "SELECT id, username, email, password FROM users WHERE username LIKE '%" +
      q +
      "%'";

    queryShown = vulnerableQuery;

    db.all(vulnerableQuery, [], (err, rows) => {
      if (err) {
        resultsHtml = `<div class="card"><h3>Error</h3><pre>${escapeHtml(
          err.message
        )}</pre></div>`;
      } else if (rows && rows.length > 0) {
        resultsHtml =
          `<div class="card"><h3>Results (showing plaintext passwords)</h3><table>` +
          `<tr><th>ID</th><th>Username</th><th>Email</th><th>Password</th></tr>` +
          rows
            .map(
              (r) =>
                `<tr><td>${r.id}</td><td>${escapeHtml(
                  r.username
                )}</td><td>${escapeHtml(
                  r.email
                )}</td><td>${escapeHtml(r.password)}</td></tr>`
            )
            .join("") +
          `</table></div>`;
      } else {
        resultsHtml = `<div class="card"><h3>Results</h3><p>No matches found.</p></div>`;
      }

      const html = `
      <div class="card">
        <h2>User Search (SQL Injection)</h2>
        <p>
          Search for a username. The query is <strong>intentionally vulnerable</strong>:
          user input is concatenated directly into the SQL string.
        </p>
        <p>Try payloads like: <code>' OR 1=1--</code></p>
        <form method="get">
          <label for="q">Username contains:</label><br>
          <input type="text" id="q" name="q" value="${escapeHtml(q)}">
          <br><br>
          <input type="submit" value="Search">
        </form>
      </div>

      ${
        queryShown
          ? `<div class="card">
               <h3>Raw SQL query (vulnerable):</h3>
               <pre>${escapeHtml(queryShown)}</pre>
             </div>`
          : ""
      }

      ${resultsHtml}
      `;
      res.send(layout(html));
    });
  } else {
    const html = `
    <div class="card">
      <h2>User Search (SQL Injection)</h2>
      <p>
        Search for a username. The query is <strong>intentionally vulnerable</strong>:
        user input is concatenated directly into the SQL string.
      </p>
      <p>Try payloads like: <code>' OR 1=1--</code></p>
      <form method="get">
        <label for="q">Username contains:</label><br>
        <input type="text" id="q" name="q" value="">
        <br><br>
        <input type="submit" value="Search">
      </form>
    </div>
    `;
    res.send(layout(html));
  }
});

// ---------------------------------------------------------
// Stored XSS comments
// ---------------------------------------------------------
app.get("/comments", (req, res) => {
  db.all("SELECT id, content FROM comments ORDER BY id DESC", [], (err, rows) => {
    if (err) {
      const html = `
      <div class="card">
        <h2>Comments</h2>
        <p>Error reading comments: ${escapeHtml(err.message)}</p>
      </div>
      `;
      return res.send(layout(html));
    }

    // ⚠️ INTENTIONAL XSS: no escaping
    const commentsHtml =
      rows && rows.length > 0
        ? "<ul>" +
          rows.map((r) => `<li>${r.content}</li>`).join("") +
          "</ul>"
        : "<p>No comments yet.</p>";

    const html = `
    <div class="card">
      <h2>Comments (Stored XSS)</h2>
      <p>
        Anything you post here is stored and rendered <strong>without HTML escaping</strong>.
        Example payload: <code>&lt;script&gt;alert('XSS')&lt;/script&gt;</code>
      </p>

      <form method="post">
        <label for="content">New comment:</label><br>
        <textarea id="content" name="content"></textarea><br><br>
        <input type="submit" value="Post comment">
      </form>
    </div>

    <div class="card">
      <h3>All Comments</h3>
      ${commentsHtml}
    </div>
    `;
    res.send(layout(html));
  });
});

app.post("/comments", (req, res) => {
  const content = req.body.content || "";

  if (content.trim().length > 0) {
    // ⚠️ STORED XSS BY DESIGN
    db.run(
      "INSERT INTO comments (content) VALUES (?)",
      [content],
      (err) => {
        if (err) console.error("Error inserting comment:", err);
        res.redirect("/comments");
      }
    );
  } else {
    res.redirect("/comments");
  }
});

// ---------------------------------------------------------
// File upload (unsafe)
// ---------------------------------------------------------
app.get("/upload", (req, res) => {
  db.all("SELECT id, filename, original_name FROM uploads ORDER BY id DESC", [], (err, rows) => {
    if (err) {
      const html = `
      <div class="card">
        <h2>File Upload</h2>
        <p>Error reading uploads: ${escapeHtml(err.message)}</p>
      </div>
      `;
      return res.send(layout(html));
    }

    const listHtml =
      rows && rows.length > 0
        ? "<table><tr><th>ID</th><th>Original Name</th><th>Link</th></tr>" +
          rows
            .map(
              (r) =>
                `<tr>
                   <td>${r.id}</td>
                   <td>${escapeHtml(r.original_name)}</td>
                   <td><a href="/uploads/${encodeURI(
                     r.filename
                   )}" target="_blank">/uploads/${escapeHtml(r.filename)}</a></td>
                 </tr>`
            )
            .join("") +
          "</table>"
        : "<p>No files uploaded yet.</p>";

    const html = `
    <div class="card">
      <h2>File Upload (Unsafe)</h2>
      <p>
        This upload feature is intentionally unsafe:
      </p>
      <ul>
        <li>No file type validation.</li>
        <li>Files are saved with their original filename.</li>
        <li>Uploads are served directly from <code>/uploads/</code>.</li>
      </ul>
      <p>
        Try uploading a <code>.html</code> or <code>.js</code> file and then browsing to it via
        <code>/uploads/&lt;filename&gt;</code>.
      </p>

      <form method="post" enctype="multipart/form-data">
        <label for="file">Choose file:</label><br>
        <input type="file" name="file" id="file"><br><br>
        <input type="submit" value="Upload file">
      </form>
    </div>

    <div class="card">
      <h3>Uploaded Files</h3>
      ${listHtml}
    </div>
    `;
    res.send(layout(html));
  });
});

app.post("/upload", upload.single("file"), (req, res) => {
  if (!req.file) {
    return res.redirect("/upload");
  }

  const filename = req.file.filename;
  const originalName = req.file.originalname;

  db.run(
    "INSERT INTO uploads (filename, original_name) VALUES (?, ?)",
    [filename, originalName],
    (err) => {
      if (err) console.error("Error storing upload record:", err);
      res.redirect("/upload");
    }
  );
});

// ---------------------------------------------------------
// Simple HTML escaper (for safe places only)
// ---------------------------------------------------------
function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

// ---------------------------------------------------------
// START SERVER
// ---------------------------------------------------------
app.listen(PORT, "0.0.0.0", () => {
  console.log(`[*] VulnApp Node listening on http://0.0.0.0:${PORT}`);
  console.log("[*] Do NOT expose this to the internet.");
});
