const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const session = require("express-session");
const sqlite3 = require("sqlite3");
const { open } = require("sqlite");
const cors = require("cors");
const path = require("path");
require("dotenv").config();

const app = express();
const JWT_SECRET = process.env.JWT_SECRET || "supersecretjwtkey";

// Middleware
app.use(express.json());
app.use(cors({ origin: "http://localhost:5000", credentials: true }));
app.use(session({ secret: "supersecret", resave: false, saveUninitialized: true }));

// --- Initialize SQLite ---
let db;
(async () => {
  db = await open({
    filename: "./database.sqlite",
    driver: sqlite3.Database
  });

  // Create tables
  await db.exec(`
  CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE,
      password_hash TEXT,
      google_id TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  
  CREATE TABLE IF NOT EXISTS usage (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      attempts INTEGER DEFAULT 0,
      last_reset DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(user_id) REFERENCES users(id)
  );
  `);
})();

// --- Passport Google OAuth ---
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: "/api/auth/google/callback"
}, async (accessToken, refreshToken, profile, done) => {
  try {
    let user = await db.get("SELECT * FROM users WHERE google_id = ?", profile.id);
    if (!user) {
      const result = await db.run(
        "INSERT INTO users (email, google_id) VALUES (?, ?)",
        profile.emails[0].value,
        profile.id
      );
      user = { id: result.lastID, email: profile.emails[0].value, google_id: profile.id };
    }
    done(null, user);
  } catch (err) {
    done(err, null);
  }
}));

app.use(passport.initialize());
app.use(passport.session());

// --- Serve static files (HTML/JS/CSS in root) ---
app.use(express.static(path.join(__dirname)));

// --- Helper: Authenticate JWT ---
function authenticateJWT(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ message: "Unauthorized" });
  const token = authHeader.split(" ")[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.userId = payload.id;
    next();
  } catch {
    res.status(401).json({ message: "Invalid token" });
  }
}

// --- Register ---
app.post("/api/register", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ message: "Email & password required" });
  try {
    const existing = await db.get("SELECT * FROM users WHERE email = ?", email);
    if (existing) return res.status(400).json({ message: "User already exists" });

    const hash = await bcrypt.hash(password, 10);
    const result = await db.run("INSERT INTO users (email, password_hash) VALUES (?, ?)", email, hash);
    const token = jwt.sign({ id: result.lastID }, JWT_SECRET);
    res.json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

// --- Login ---
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await db.get("SELECT * FROM users WHERE email = ?", email);
    if (!user) return res.status(400).json({ message: "Invalid credentials" });

    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(400).json({ message: "Invalid credentials" });

    const token = jwt.sign({ id: user.id }, JWT_SECRET);
    res.json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

// --- Google OAuth Routes ---
app.get("/api/auth/google", passport.authenticate("google", { scope: ["profile", "email"] }));

app.get("/api/auth/google/callback", passport.authenticate("google", { session: false }),
  async (req, res) => {
    const token = jwt.sign({ id: req.user.id }, JWT_SECRET);
    res.redirect(`http://localhost:5000/index.html?token=${token}`);
  });

// --- Humanize endpoint ---
const MAX_ATTEMPTS = 5;
app.post("/api/humanize", authenticateJWT, async (req, res) => {
  const userId = req.userId;
  const { text } = req.body;
  if (!text) return res.status(400).json({ message: "Text is required" });

  try {
    let usageRecord = await db.get("SELECT * FROM usage WHERE user_id = ?", userId);
    const now = new Date();

    if (!usageRecord) {
      await db.run("INSERT INTO usage (user_id, attempts, last_reset) VALUES (?, ?, ?)",
        userId, 0, now.toISOString());
      usageRecord = { attempts: 0, last_reset: now };
    }

    // Reset daily
    const lastReset = new Date(usageRecord.last_reset);
    if ((now - lastReset) / (1000 * 60 * 60 * 24) >= 1) {
      usageRecord.attempts = 0;
      await db.run("UPDATE usage SET attempts = 0, last_reset = ? WHERE user_id = ?", now.toISOString(), userId);
    }

    if (usageRecord.attempts >= MAX_ATTEMPTS) {
      return res.status(403).json({ message: "Usage limit reached. Please log in or wait for reset." });
    }

    await db.run("UPDATE usage SET attempts = attempts + 1 WHERE user_id = ?", userId);

    // Replace with your real humanizer API if needed
    const humanizedText = `HUMANIZED: ${text}`;

    res.json({ humanizedText });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

// Default route
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

// Start server
app.listen(5000, () => {
  console.log("Server running on http://localhost:5000");
});
