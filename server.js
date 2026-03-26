require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const { Resend } = require('resend');
const crypto = require('crypto');

const app = express();
const resend = new Resend(process.env.RESEND_API_KEY);

const JWT_SECRET = process.env.JWT_SECRET;
const ALLOWED_DOMAIN = process.env.ALLOWED_DOMAIN || 'north-star.network';
const BASE_URL = process.env.BASE_URL || 'https://auth.labnsn.com';
const PORT = process.env.PORT || 3000;

if (!JWT_SECRET) { console.error('JWT_SECRET required'); process.exit(1); }
if (!process.env.RESEND_API_KEY) { console.error('RESEND_API_KEY required'); process.exit(1); }

// In-memory token store (nonce → {email, redirect, expires})
const tokens = new Map();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 5 });

// ── UI ────────────────────────────────────────────────────────────────────────
app.get('/', (req, res) => {
  const redirect = req.query.redirect || '';
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>NSN Lab — Sign in</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
           background: #0f0f0f; color: #e5e5e5; display: flex;
           align-items: center; justify-content: center; min-height: 100vh; }
    .card { background: #1a1a1a; border: 1px solid #2a2a2a; border-radius: 12px;
            padding: 40px; width: 100%; max-width: 380px; }
    .logo { font-size: 13px; font-weight: 600; color: #666; letter-spacing: 0.1em;
            text-transform: uppercase; margin-bottom: 28px; }
    h1 { font-size: 22px; font-weight: 600; margin-bottom: 8px; }
    p { font-size: 14px; color: #888; margin-bottom: 28px; }
    input { width: 100%; padding: 12px 14px; background: #111; border: 1px solid #333;
            border-radius: 8px; color: #e5e5e5; font-size: 14px; outline: none; }
    input:focus { border-color: #555; }
    button { width: 100%; padding: 12px; background: #e5e5e5; color: #111;
             border: none; border-radius: 8px; font-size: 14px; font-weight: 600;
             cursor: pointer; margin-top: 12px; }
    button:hover { background: #fff; }
    .hint { font-size: 12px; color: #555; margin-top: 16px; text-align: center; }
  </style>
</head>
<body>
  <div class="card">
    <div class="logo">NSN Lab</div>
    <h1>Sign in</h1>
    <p>Enter your @north-star.network email to receive a magic link.</p>
    <form action="/request-link" method="POST">
      <input type="hidden" name="redirect" value="${redirect}">
      <input type="email" name="email" placeholder="you@north-star.network" required autofocus>
      <button type="submit">Send magic link</button>
    </form>
    <div class="hint">No password needed.</div>
  </div>
</body>
</html>`);
});

app.get('/sent', (req, res) => {
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Check your email</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
           background: #0f0f0f; color: #e5e5e5; display: flex;
           align-items: center; justify-content: center; min-height: 100vh; }
    .card { background: #1a1a1a; border: 1px solid #2a2a2a; border-radius: 12px;
            padding: 40px; width: 100%; max-width: 380px; text-align: center; }
    .icon { font-size: 40px; margin-bottom: 20px; }
    h1 { font-size: 20px; font-weight: 600; margin-bottom: 10px; }
    p { font-size: 14px; color: #888; }
  </style>
</head>
<body>
  <div class="card">
    <div class="icon">📬</div>
    <h1>Check your email</h1>
    <p>We sent a magic link to your inbox. It expires in 15 minutes.</p>
  </div>
</body>
</html>`);
});

// ── Request magic link ────────────────────────────────────────────────────────
app.post('/request-link', loginLimiter, async (req, res) => {
  const { email, redirect } = req.body;

  if (!email || !email.toLowerCase().endsWith(`@${ALLOWED_DOMAIN}`)) {
    return res.status(403).send('Only @' + ALLOWED_DOMAIN + ' emails are allowed.');
  }

  const nonce = crypto.randomBytes(32).toString('hex');
  const expires = Date.now() + 15 * 60 * 1000; // 15 min
  tokens.set(nonce, { email: email.toLowerCase(), redirect: redirect || '', expires });

  const link = `${BASE_URL}/verify?token=${nonce}`;

  await resend.emails.send({
    from: 'NSN Lab <noreply@labnsn.com>',
    to: email,
    subject: 'Your magic link',
    html: `
      <p>Hi,</p>
      <p>Click the link below to sign in to NSN Lab. It expires in 15 minutes.</p>
      <p><a href="${link}" style="background:#111;color:#fff;padding:12px 24px;border-radius:6px;text-decoration:none;font-weight:600;">Sign in to NSN Lab</a></p>
      <p style="color:#888;font-size:12px;margin-top:20px;">If you didn't request this, ignore this email.</p>
    `
  });

  res.redirect('/sent');
});

// ── Verify token ──────────────────────────────────────────────────────────────
app.get('/verify', (req, res) => {
  const { token } = req.query;
  const entry = tokens.get(token);

  if (!entry || Date.now() > entry.expires) {
    return res.status(401).send('Link expired or invalid. <a href="/">Try again</a>');
  }

  tokens.delete(token);

  const jwt_token = jwt.sign({ email: entry.email }, JWT_SECRET, { expiresIn: '7d' });

  res.cookie('nsn_auth', jwt_token, {
    httpOnly: true,
    secure: true,
    sameSite: 'lax',
    maxAge: 7 * 24 * 60 * 60 * 1000
  });

  const redirectTo = entry.redirect || 'https://labnsn.com';
  res.redirect(redirectTo);
});

// ── Health ────────────────────────────────────────────────────────────────────
app.get('/health', (req, res) => res.json({ ok: true }));

app.listen(PORT, () => console.log(`Auth service running on port ${PORT}`));
