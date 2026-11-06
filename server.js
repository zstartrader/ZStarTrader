require("dotenv").config();
const express = require("express");
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);
const Database = require("better-sqlite3");
const crypto = require("crypto");
const path = require("path");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");

if (!process.env.ADMIN_PASSWORD || !process.env.SESSION_SECRET || !process.env.DATA_ENCRYPTION_KEY) {
  throw new Error("Set ADMIN_PASSWORD, SESSION_SECRET and DATA_ENCRYPTION_KEY in .env");
}

const app = express();
const db = new Database(path.join(__dirname, "database", "zstartrader.sqlite"));
db.pragma("journal_mode = WAL");
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  passkey_hash TEXT NOT NULL UNIQUE,
  passkey_enc TEXT NOT NULL,
  uid TEXT NOT NULL UNIQUE,
  tier TEXT NOT NULL DEFAULT '100',
  status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK(status IN ('ACTIVE','INACTIVE')),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`);

const PORT = Number(process.env.PORT || 3000);
const encryptionKey = crypto.createHash("sha256").update(process.env.DATA_ENCRYPTION_KEY).digest();
const hashPasskey = value => crypto.createHash("sha256").update(String(value)).digest("hex");
function encrypt(value) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", encryptionKey, iv);
  const data = Buffer.concat([cipher.update(value, "utf8"), cipher.final()]);
  return [iv.toString("hex"), cipher.getAuthTag().toString("hex"), data.toString("hex")].join(":");
}
function decrypt(value) {
  const [iv, tag, data] = value.split(":");
  const decipher = crypto.createDecipheriv("aes-256-gcm", encryptionKey, Buffer.from(iv, "hex"));
  decipher.setAuthTag(Buffer.from(tag, "hex"));
  return Buffer.concat([decipher.update(Buffer.from(data, "hex")), decipher.final()]).toString("utf8");
}
const tiers = new Set(["100", "300", "500", "1000"]);
const validPasskey = v => typeof v === "string" && v.length === 18 && !/[\u0000-\u001f]/.test(v);
const safeUser = row => ({
  id: row.id, passkey: decrypt(row.passkey_enc), uid: row.uid,
  tier: row.tier, status: row.status, createdAt: row.created_at, updatedAt: row.updated_at
});

app.disable("x-powered-by");
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "20kb" }));
app.use(session({
  store: new SQLiteStore({ db: "sessions.sqlite", dir: path.join(__dirname, "database") }),
  secret: process.env.SESSION_SECRET,
  resave: false, saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: "strict", secure: process.env.NODE_ENV === "production", maxAge: 8 * 60 * 60 * 1000 }
}));
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 12, standardHeaders: true, legacyHeaders: false });
const adminLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 30, standardHeaders: true, legacyHeaders: false });
const requireAdmin = (req, res, next) => req.session && req.session.isAdmin ? next() : res.status(401).json({ok:false,message:"Admin login required."});

app.post("/api/auth/passkey", authLimiter, (req, res) => {
  const passkey = String(req.body.passkey || "");
  if (!validPasskey(passkey)) return res.status(400).json({ok:false,message:"Passkey must contain exactly 18 characters."});
  const row = db.prepare("SELECT * FROM users WHERE passkey_hash = ?").get(hashPasskey(passkey));
  if (!row || row.status !== "ACTIVE") return res.status(401).json({ok:false,message:"Passkey not found or account is inactive."});
  return res.json({ok:true,user:{uid:row.uid,tier:row.tier}});
});

app.post("/api/admin/login", adminLimiter, (req,res) => {
  const supplied = String(req.body.password || "");
  const a = Buffer.from(supplied), b = Buffer.from(process.env.ADMIN_PASSWORD);
  if (a.length !== b.length || !crypto.timingSafeEqual(a,b)) return res.status(401).json({ok:false,message:"Incorrect admin password."});
  req.session.regenerate(err => {
    if (err) return res.status(500).json({ok:false,message:"Could not create admin session."});
    req.session.isAdmin = true;
    res.json({ok:true});
  });
});
app.post("/api/admin/logout", requireAdmin, (req,res) => req.session.destroy(() => res.json({ok:true})));
app.get("/api/admin/me", (req,res) => res.json({ok:!!(req.session && req.session.isAdmin)}));

app.get("/api/admin/users", requireAdmin, (req,res) => {
  const q = String(req.query.q || "").trim();
  let rows;
  if (q) {
    const exactHash = hashPasskey(q);
    rows = db.prepare(`SELECT * FROM users WHERE passkey_hash = ? OR uid LIKE ? ORDER BY id DESC LIMIT 100`).all(exactHash, `%${q.replace(/[%_\\]/g, "\\$&")}%`);
  } else {
    rows = db.prepare("SELECT * FROM users ORDER BY id DESC LIMIT 100").all();
  }
  res.json({ok:true,users:rows.map(safeUser)});
});
app.post("/api/admin/users", requireAdmin, (req,res) => {
  const passkey = String(req.body.passkey || "");
  const uid = String(req.body.uid || "").trim();
  const tier = String(req.body.tier || "100");
  const status = String(req.body.status || "ACTIVE").toUpperCase();
  if (!validPasskey(passkey)) return res.status(400).json({ok:false,message:"Passkey must be exactly 18 characters."});
  if (!uid || uid.length > 64) return res.status(400).json({ok:false,message:"Enter a valid UID (max 64 characters)."});
  if (!tiers.has(tier) || !["ACTIVE","INACTIVE"].includes(status)) return res.status(400).json({ok:false,message:"Invalid tier or status."});
  try {
    const info = db.prepare("INSERT INTO users(passkey_hash,passkey_enc,uid,tier,status) VALUES(?,?,?,?,?)")
      .run(hashPasskey(passkey), encrypt(passkey), uid, tier, status);
    res.status(201).json({ok:true,id:info.lastInsertRowid});
  } catch(e) {
    res.status(409).json({ok:false,message:"Passkey or UID already exists."});
  }
});
app.put("/api/admin/users/:id", requireAdmin, (req,res) => {
  const id = Number(req.params.id);
  const old = db.prepare("SELECT * FROM users WHERE id=?").get(id);
  if (!old) return res.status(404).json({ok:false,message:"User not found."});
  const passkey = req.body.passkey === undefined ? decrypt(old.passkey_enc) : String(req.body.passkey);
  const uid = req.body.uid === undefined ? old.uid : String(req.body.uid).trim();
  const tier = req.body.tier === undefined ? old.tier : String(req.body.tier);
  const status = req.body.status === undefined ? old.status : String(req.body.status).toUpperCase();
  if (!validPasskey(passkey) || !uid || uid.length > 64 || !tiers.has(tier) || !["ACTIVE","INACTIVE"].includes(status))
    return res.status(400).json({ok:false,message:"Check passkey, UID, tier and status."});
  try {
    db.prepare("UPDATE users SET passkey_hash=?,passkey_enc=?,uid=?,tier=?,status=?,updated_at=CURRENT_TIMESTAMP WHERE id=?")
      .run(hashPasskey(passkey),encrypt(passkey),uid,tier,status,id);
    res.json({ok:true});
  } catch(e) { res.status(409).json({ok:false,message:"That passkey or UID is already assigned."}); }
});
app.delete("/api/admin/users/:id", requireAdmin, (req,res) => {
  const info = db.prepare("DELETE FROM users WHERE id=?").run(Number(req.params.id));
  if (!info.changes) return res.status(404).json({ok:false,message:"User not found."});
  res.json({ok:true});
});

app.use(express.static(path.join(__dirname, "public")));
app.get("/", (req,res) => res.sendFile(path.join(__dirname,"public","Dashboard.html")));
app.listen(PORT, () => console.log(`Z Star Trader server running: http://localhost:${PORT}`));
