const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const db = require("../db");
const auth = require("../middleware/auth");

const router = express.Router();

/* ===== 注册 ===== */
router.post("/register", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ msg: "Missing fields" });
    }

    // 查是否已存在
    const exist = await db.query(
      "SELECT id FROM users WHERE username = $1",
      [username]
    );

    if (exist.rows.length > 0) {
      return res.status(409).json({ msg: "User exists" });
    }

    // 加密密码
    const hash = await bcrypt.hash(password, 10);

    // 写入数据库
    await db.query(
      "INSERT INTO users (username, password_hash) VALUES ($1, $2)",
      [username, hash]
    );

    res.json({ success: true });
  } catch (err) {
    console.error("Register error:", err);
    res.status(500).json({ msg: "Server error" });
  }
});

/* ===== 登录 ===== */
router.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    const result = await db.query(
      "SELECT id, username, password_hash FROM users WHERE username = $1",
      [username]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ msg: "Invalid login" });
    }

    const user = result.rows[0];
    const ok = await bcrypt.compare(password, user.password_hash);

    if (!ok) {
      return res.status(401).json({ msg: "Invalid login" });
    }

    const token = jwt.sign(
      { id: user.id, username: user.username },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({
      token,
      username: user.username
    });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ msg: "Server error" });
  }
});

/* ===== 当前用户 ===== */
router.get("/me", auth, async (req, res) => {
  try {
    const result = await db.query(
      "SELECT id, username, created_at FROM users WHERE id = $1",
      [req.user.id]
    );

    res.json(result.rows[0]);
  } catch (err) {
    console.error("/me error:", err);
    res.status(500).json({ msg: "Server error" });
  }
});

module.exports = router;
