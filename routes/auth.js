const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const db = require("../db");
const auth = require("../middleware/auth");

const router = express.Router();

/* ===== 注册 ===== */
router.post("/register", async (req, res) => {
  const { username, password } = req.body;
  if(!username || !password)
    return res.status(400).json({ msg: "Missing fields" });

  const [exist] = await db.query(
    "SELECT id FROM users WHERE username=?",
    [username]
  );
  if(exist.length)
    return res.status(409).json({ msg: "User exists" });

  const hash = await bcrypt.hash(password, 10);
  await db.query(
    "INSERT INTO users (username,password_hash) VALUES (?,?)",
    [username, hash]
  );

  res.json({ success: true });
});

/* ===== 登录 ===== */
router.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const [rows] = await db.query(
    "SELECT * FROM users WHERE username=?",
    [username]
  );
  if(!rows.length)
    return res.status(401).json({ msg: "Invalid login" });

  const user = rows[0];
  const ok = await bcrypt.compare(password, user.password_hash);
  if(!ok)
    return res.status(401).json({ msg: "Invalid login" });

  const token = jwt.sign(
    { id: user.id, username: user.username },
    process.env.JWT_SECRET,
    { expiresIn: "7d" }
  );

  res.json({
    token,
    username: user.username
  });
});

/* ===== 当前用户 ===== */
router.get("/me", auth, async (req, res) => {
  const [rows] = await db.query(
    "SELECT id,username,created_at FROM users WHERE id=?",
    [req.user.id]
  );
  res.json(rows[0]);
});

module.exports = router;
