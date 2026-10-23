// Email API starter for Node.js / Render
// Sends email through an SMTP provider and stores inbound webhook messages.
// IMPORTANT: This is a starter. Add real user authentication and provider-specific
// webhook signature verification before using it for real users.

require("dotenv").config();

const express = require("express");
const nodemailer = require("nodemailer");
const { Pool } = require("pg");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");

const app = express();
app.disable("x-powered-by");
app.use(helmet());
app.use(express.json({ limit: "256kb" }));

const required = [
  "DATABASE_URL",
  "SMTP_HOST",
  "SMTP_USER",
  "SMTP_PASS",
  "MAIL_DOMAIN",
  "MAIL_FROM",
  "API_KEY",
  "INBOUND_WEBHOOK_SECRET"
];

for (const name of required) {
  if (!process.env[name]) {
    throw new Error(`Missing required environment variable: ${name}`);
  }
}

function secretMatches(actual, expected) {
  if (typeof actual !== "string" || typeof expected !== "string") return false;
  const a = Buffer.from(actual);
  const b = Buffer.from(expected);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  // Use the database provider's recommended TLS configuration.
  ssl: process.env.DATABASE_SSL === "true"
    ? { rejectUnauthorized: true }
    : false
});

const smtpPort = Number(process.env.SMTP_PORT || 587);

const mailer = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: smtpPort,
  secure: smtpPort === 465,
  requireTLS: smtpPort !== 465,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS
  }
});

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 60,
  standardHeaders: true,
  legacyHeaders: false
});

const sendLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false
});

function requireApiKey(req, res, next) {
  if (!secretMatches(req.get("x-api-key"), process.env.API_KEY)) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  next();
}

function validEmail(value) {
  return typeof value === "string" &&
    value.length <= 254 &&
    /^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$/.test(value);
}

function mailboxAllowed(value) {
  return validEmail(value) &&
    value.toLowerCase().endsWith(
      "@" + process.env.MAIL_DOMAIN.toLowerCase()
    );
}

async function start() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS emails (
      id BIGSERIAL PRIMARY KEY,
      direction TEXT NOT NULL
        CHECK (direction IN ('inbound', 'outbound')),
      sender TEXT NOT NULL,
      recipient TEXT NOT NULL,
      subject TEXT NOT NULL DEFAULT '',
      text_body TEXT NOT NULL DEFAULT '',
      html_body TEXT NOT NULL DEFAULT '',
      message_id TEXT UNIQUE,
      received_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  app.get("/health", (req, res) => {
    res.json({ status: "ok" });
  });

  app.use("/api", apiLimiter);

  app.post("/api/send", requireApiKey, sendLimiter, async (req, res) => {
    try {
      const { to, subject, text, html } = req.body || {};

      if (
        !validEmail(to) ||
        typeof subject !== "string" ||
        subject.length > 200 ||
        (text !== undefined &&
          (typeof text !== "string" || text.length > 50000)) ||
        (html !== undefined &&
          (typeof html !== "string" || html.length > 50000)) ||
        (!text && !html)
      ) {
        return res.status(400).json({
          error: "Provide a valid recipient, subject and message body."
        });
      }

      const result = await mailer.sendMail({
        from: process.env.MAIL_FROM,
        to,
        subject,
        text: text || undefined,
        html: html || undefined
      });

      await pool.query(
        `INSERT INTO emails
          (direction, sender, recipient, subject, text_body,
           html_body, message_id)
         VALUES ('outbound', $1, $2, $3, $4, $5, $6)
         ON CONFLICT (message_id) DO NOTHING`,
        [
          process.env.MAIL_FROM,
          to,
          subject,
          text || "",
          html || "",
          result.messageId || null
        ]
      );

      res.status(202).json({
        accepted: true,
        messageId: result.messageId
      });
    } catch (err) {
      console.error("Email send failed:", err.message);
      res.status(502).json({ error: "Email could not be sent." });
    }
  });

  app.get("/api/inbox", requireApiKey, async (req, res) => {
    const to = typeof req.query.to === "string"
      ? req.query.to.toLowerCase()
      : "";

    if (!mailboxAllowed(to)) {
      return res.status(400).json({
        error: "Provide a valid mailbox on your configured domain."
      });
    }

    try {
      const result = await pool.query(
        `SELECT id, sender, recipient, subject, text_body,
                html_body, received_at
         FROM emails
         WHERE direction = 'inbound' AND LOWER(recipient) = $1
         ORDER BY received_at DESC
         LIMIT 50`,
        [to]
      );

      res.json({ messages: result.rows });
    } catch (err) {
      console.error("Inbox query failed:", err.message);
      res.status(500).json({ error: "Could not load inbox." });
    }
  });

  // Configure your inbound email provider to POST this normalized JSON
  // and send X-Inbound-Token. Verify provider signatures too, if supported.
  app.post("/webhooks/inbound", async (req, res) => {
    if (!secretMatches(
      req.get("x-inbound-token"),
      process.env.INBOUND_WEBHOOK_SECRET
    )) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    const { from, to, subject, text, html, messageId } = req.body || {};

    if (
      !validEmail(from) ||
      !mailboxAllowed(typeof to === "string" ? to.toLowerCase() : "") ||
      typeof subject !== "string" ||
      subject.length > 200 ||
      (text !== undefined &&
        (typeof text !== "string" || text.length > 50000)) ||
      (html !== undefined &&
        (typeof html !== "string" || html.length > 50000)) ||
      (!text && !html) ||
      (messageId !== undefined &&
        (typeof messageId !== "string" || messageId.length > 500))
    ) {
      return res.status(400).json({ error: "Invalid message payload." });
    }

    try {
      await pool.query(
        `INSERT INTO emails
          (direction, sender, recipient, subject, text_body,
           html_body, message_id)
         VALUES ('inbound', $1, $2, $3, $4, $5, $6)
         ON CONFLICT (message_id) DO NOTHING`,
        [
          from,
          to.toLowerCase(),
          subject,
          text || "",
          html || "",
          messageId || null
        ]
      );

      res.status(202).json({ received: true });
    } catch (err) {
      console.error("Inbound storage failed:", err.message);
      res.status(500).json({ error: "Could not store message." });
    }
  });

  app.use((err, req, res, next) => {
    if (res.headersSent) return next(err);
    if (err.type === "entity.too.large") {
      return res.status(413).json({ error: "Request too large." });
    }
    return res.status(400).json({ error: "Invalid request." });
  });

  const port = Number(process.env.PORT || 3000);
  const server = app.listen(port, "0.0.0.0", () => {
    console.log(`Email API listening on port ${port}`);
  });

  async function shutdown() {
    server.close();
    await pool.end();
    process.exit(0);
  }

  process.on("SIGTERM", shutdown);
  process.on("SIGINT", shutdown);
}

start().catch(err => {
  console.error("Startup failed:", err.message);
  process.exit(1);
});
