const express = require("express");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const db = require("../db");
const { sendMail } = require("../config/mailer");
const { isValidEmail, isValidPassword } = require("../utils/validators");

const router = express.Router();
const APP_URL = process.env.APP_URL || "http://localhost:3000";

function makeToken() {
  return crypto.randomBytes(32).toString("hex");
}

function makeResetCode() {
  return crypto.randomBytes(4).toString("hex").toUpperCase(); // short, human-typeable code
}

// ---------- Register ----------
router.post("/register", async (req, res) => {
  const { register_no, email, password } = req.body;

  if (!register_no || !email || !password) {
    return res.status(400).json({ error: "Register number, email, and password are required" });
  }
  if (!isValidEmail(email)) {
    return res.status(400).json({ error: "Please enter a valid email address" });
  }
  if (!isValidPassword(password)) {
    return res.status(400).json({ error: "Password must be at least 6 characters" });
  }

  const cleanRegisterNo = String(register_no).trim();
  const student = db.prepare("SELECT * FROM students WHERE register_no = ?").get(cleanRegisterNo);
  if (!student) {
    return res.status(404).json({ error: "That register number was not found in the class roster. Please check and try again." });
  }

  const existingByRegNo = db.prepare("SELECT id FROM users WHERE register_no = ?").get(cleanRegisterNo);
  if (existingByRegNo) {
    return res.status(409).json({ error: "An account already exists for this register number." });
  }
  const existingByEmail = db.prepare("SELECT id FROM users WHERE email = ?").get(email);
  if (existingByEmail) {
    return res.status(409).json({ error: "An account with this email already exists" });
  }

  const hash = bcrypt.hashSync(password, 10);
  const verifyToken = makeToken();
  const expires = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();

  const result = db
    .prepare(
      `INSERT INTO users (name, register_no, roll_no, email, password, role, verified, verify_token, verify_token_expires)
       VALUES (?, ?, ?, ?, ?, 'student', 0, ?, ?)`
    )
    .run(student.name, student.register_no, student.roll_no, email, hash, verifyToken, expires);

  const verifyLink = `${APP_URL}/api/auth/verify/${verifyToken}`;
  try {
    await sendMail({
      to: email,
      subject: "Verify your Lost & Found Portal account",
      html: `
        <div style="font-family:sans-serif;max-width:480px;margin:auto">
          <h2>Welcome, ${student.name}!</h2>
          <p>Confirm your email to activate your account:</p>
          <p><a href="${verifyLink}" style="background:#2E86AB;color:#fff;padding:10px 20px;text-decoration:none;border-radius:6px;display:inline-block">Verify my email</a></p>
          <p>Or paste this link into your browser:<br>${verifyLink}</p>
          <p style="color:#888;font-size:12px">This link expires in 24 hours.</p>
        </div>
      `,
    });
  } catch (err) {
    console.error("Failed to send verification email:", err.message);
  }

  res.status(201).json({
    message: "Account created! Check your email for a verification link before logging in.",
    userId: result.lastInsertRowid,
  });
});

// ---------- Verify email ----------
router.get("/verify/:token", (req, res) => {
  const user = db
    .prepare("SELECT * FROM users WHERE verify_token = ? AND verify_token_expires > datetime('now')")
    .get(req.params.token);

  if (!user) {
    return res.send(
      "<h2>This verification link is invalid or has expired.</h2><p>Please request a new one from the app.</p>"
    );
  }

  db.prepare(
    "UPDATE users SET verified = 1, verify_token = NULL, verify_token_expires = NULL WHERE id = ?"
  ).run(user.id);

  res.send("<h2>Email verified!</h2><p>You can now go back to the app and log in.</p>");
});

// ---------- Resend verification ----------
router.post("/resend-verification", async (req, res) => {
  const { email } = req.body;
  const user = db.prepare("SELECT * FROM users WHERE email = ?").get(email);

  const genericMsg = { message: "If that account exists and isn't verified yet, a new email has been sent." };
  if (!user || user.verified) return res.json(genericMsg);

  const verifyToken = makeToken();
  const expires = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
  db.prepare("UPDATE users SET verify_token = ?, verify_token_expires = ? WHERE id = ?").run(
    verifyToken,
    expires,
    user.id
  );

  const verifyLink = `${APP_URL}/api/auth/verify/${verifyToken}`;
  try {
    await sendMail({
      to: email,
      subject: "Verify your Lost & Found Portal account",
      html: `<p>Confirm your email: <a href="${verifyLink}">${verifyLink}</a></p>`,
    });
  } catch (err) {
    console.error("Failed to resend verification email:", err.message);
  }

  res.json(genericMsg);
});

// ---------- Login ----------
router.post("/login", (req, res) => {
  const { email, password } = req.body;
  const user = db.prepare("SELECT * FROM users WHERE email = ?").get(email);

  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.status(401).json({ error: "Invalid email or password" });
  }

  if (!user.verified) {
    return res.status(403).json({
      error: "Please verify your email before logging in.",
      unverified: true,
    });
  }

  const token = jwt.sign(
    { id: user.id, name: user.name, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: "30d" }
  );

  res.json({
    token,
    user: { id: user.id, name: user.name, email: user.email, role: user.role, register_no: user.register_no, roll_no: user.roll_no },
  });
});

// ---------- Forgot password ----------
router.post("/forgot-password", async (req, res) => {
  const { email } = req.body;
  const user = db.prepare("SELECT * FROM users WHERE email = ?").get(email);

  const genericMsg = { message: "If that email is registered, a reset link has been sent." };
  if (!user) return res.json(genericMsg);

  const resetCode = makeResetCode();
  const expires = new Date(Date.now() + 60 * 60 * 1000).toISOString();
  db.prepare("UPDATE users SET reset_token = ?, reset_token_expires = ? WHERE id = ?").run(
    resetCode,
    expires,
    user.id
  );

  try {
    await sendMail({
      to: email,
      subject: "Reset your Lost & Found Portal password",
      html: `
        <div style="font-family:sans-serif;max-width:480px;margin:auto">
          <h2>Password reset</h2>
          <p>Your reset code is:</p>
          <p style="font-size:24px;font-weight:bold;letter-spacing:2px">${resetCode}</p>
          <p style="color:#888;font-size:12px">Enter this code in the app. It expires in 1 hour.</p>
        </div>
      `,
    });
  } catch (err) {
    console.error("Failed to send reset email:", err.message);
  }

  res.json(genericMsg);
});

// ---------- Reset password ----------
router.post("/reset-password", (req, res) => {
  const { token, password } = req.body;

  if (!isValidPassword(password)) {
    return res.status(400).json({ error: "Password must be at least 6 characters" });
  }

  const user = db
    .prepare("SELECT * FROM users WHERE reset_token = ? AND reset_token_expires > datetime('now')")
    .get(token);

  if (!user) {
    return res.status(400).json({ error: "This reset code is invalid or has expired. Please request a new one." });
  }

  const hash = bcrypt.hashSync(password, 10);
  db.prepare(
    "UPDATE users SET password = ?, reset_token = NULL, reset_token_expires = NULL WHERE id = ?"
  ).run(hash, user.id);

  res.json({ message: "Password updated. You can now log in." });
});

module.exports = router;
