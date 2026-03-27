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

// Trust nginx reverse proxy
app.set('trust proxy', 1);

// In-memory token store (nonce → {email, redirect, expires})
const tokens = new Map();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10 });

// ── UI ────────────────────────────────────────────────────────────────────────
app.get('/', (req, res) => {
  // If already authenticated, redirect
  const token = req.cookies.nsn_auth;
  if (token) {
    try {
      jwt.verify(token, JWT_SECRET);
      const redirect = req.query.redirect || 'https://labnsn.com';
      return res.redirect(redirect);
    } catch(e) {}
  }

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
  const expires = Date.now() + 15 * 60 * 1000;
  tokens.set(nonce, { email: email.toLowerCase(), redirect: redirect || '', expires });

  const link = `${BASE_URL}/verify?token=${nonce}`;

  try {
    await resend.emails.send({
      from: 'NSN Lab <noreply@labnsn.com>',
      to: email,
      subject: 'Your magic link for NSN Lab',
      html: `
        <div style="font-family:-apple-system,sans-serif;max-width:400px;margin:0 auto;padding:40px 20px">
          <p style="color:#666;font-size:12px;font-weight:600;letter-spacing:0.1em;text-transform:uppercase;margin-bottom:24px">NSN Lab</p>
          <h1 style="font-size:22px;margin-bottom:12px;color:#111">Sign in</h1>
          <p style="color:#555;margin-bottom:28px">Click the button below to sign in. This link expires in 15 minutes.</p>
          <a href="${link}" style="display:inline-block;background:#111;color:#fff;padding:14px 28px;border-radius:8px;text-decoration:none;font-weight:600;font-size:14px">Sign in to NSN Lab</a>
          <p style="color:#aaa;font-size:12px;margin-top:28px">If you didn't request this, ignore this email.</p>
        </div>
      `
    });
  } catch(e) {
    console.error('Resend error:', e.message);
    return res.status(500).send('Failed to send email. Try again.');
  }

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

  const jwtToken = jwt.sign({ email: entry.email }, JWT_SECRET, { expiresIn: '7d' });

  // Set cookie on .labnsn.com domain so all subdomains can read it
  res.cookie('nsn_auth', jwtToken, {
    httpOnly: true,
    secure: true,
    sameSite: 'lax',
    domain: '.labnsn.com',
    maxAge: 7 * 24 * 60 * 60 * 1000
  });

  const redirectTo = entry.redirect && entry.redirect.startsWith('https://') 
    ? entry.redirect 
    : 'https://labnsn.com';
  res.redirect(redirectTo);
});

// ── Health ────────────────────────────────────────────────────────────────────
app.get('/health', (req, res) => res.json({ ok: true }));

app.listen(PORT, () => console.log(`Auth service running on port ${PORT}`));

// ── Landing page (labnsn.com) ─────────────────────────────────────────────────
app.get('/landing', (req, res) => {
  let email = null;
  const token = req.cookies.nsn_auth;
  if (token) {
    try { email = jwt.verify(token, JWT_SECRET).email; } catch(e) {}
  }

  // Deploy dates (UTC → human-readable)
  const apps = [
    {
      url: 'https://rankings-app.labnsn.com',
      name: 'Rankings App',
      emoji: '📈',
      desc: 'Track keyword positions across all NSN sites. Spot ranking trends at a glance.',
      deployed: 'Mar 26, 2026'
    },
    {
      url: 'https://bet-writer-pro.labnsn.com',
      name: 'BetWriter Pro',
      emoji: '✍️',
      desc: 'AI-powered content generator for sports betting pages. SEO-optimised in seconds.',
      deployed: 'Mar 26, 2026'
    },
    {
      url: 'https://dmca-report.labnsn.com',
      name: 'DMCA Report',
      emoji: '🛡️',
      desc: 'Monitor copyright takedown requests on our domains via Google Transparency Report.',
      deployed: 'Mar 27, 2026'
    }
  ];

  const appsHtml = apps.map(a => `
    <a class="app" href="${a.url}">
      <div class="app-top">
        <span class="app-emoji">${a.emoji}</span>
        <div class="app-meta">
          <span class="app-name">${a.name}</span>
          <span class="app-date">Deployed ${a.deployed}</span>
        </div>
        <span class="app-arrow">→</span>
      </div>
      <p class="app-desc">${a.desc}</p>
    </a>
  `).join('');

  const bodyHtml = email ? `
    <div class="user"><span class="dot-green"></span>${email}</div>
    <div class="apps">${appsHtml}</div>
    <a class="action" href="/logout">Sign out</a>
  ` : `
    <p class="tagline">Internal tools — NSN team only</p>
    <a class="signin" href="https://auth.labnsn.com?redirect=https://labnsn.com">Sign in →</a>
  `;

  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>NSN Lab</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
           background: #0a0a0a; color: #e5e5e5;
           display: flex; align-items: center; justify-content: center; min-height: 100vh; }
    .wrap { padding: 48px 24px; max-width: 440px; width: 100%; }
    .logo { font-size: 11px; font-weight: 700; color: #333; letter-spacing: 0.2em;
            text-transform: uppercase; margin-bottom: 40px; text-align: center; }
    h1 { font-size: 30px; font-weight: 700; text-align: center; margin-bottom: 4px; letter-spacing: -0.5px; }
    .subtitle { font-size: 13px; color: #444; text-align: center; margin-bottom: 36px; }
    .dot-green { display: inline-block; width: 7px; height: 7px; border-radius: 50%;
                 background: #4ade80; margin-right: 6px; vertical-align: middle; }
    .user { font-size: 13px; color: #4ade80; margin-bottom: 20px; text-align: center; }
    .tagline { font-size: 15px; color: #444; margin-bottom: 28px; text-align: center; }
    .apps { display: flex; flex-direction: column; gap: 10px; margin-bottom: 28px; }
    a.app { display: block; padding: 16px 18px;
            background: #111; border: 1px solid #222;
            border-radius: 10px; color: #e5e5e5; text-decoration: none;
            transition: border-color 0.15s, background 0.15s; }
    a.app:hover { border-color: #444; background: #161616; }
    .app-top { display: flex; align-items: center; gap: 12px; margin-bottom: 8px; }
    .app-emoji { font-size: 20px; flex-shrink: 0; }
    .app-meta { flex: 1; }
    .app-name { display: block; font-size: 14px; font-weight: 600; }
    .app-date { display: block; font-size: 11px; color: #444; margin-top: 1px; }
    .app-arrow { color: #333; font-size: 14px; flex-shrink: 0; transition: color 0.15s; }
    a.app:hover .app-arrow { color: #888; }
    .app-desc { font-size: 12px; color: #555; line-height: 1.6; padding-left: 32px; }
    a.signin { display: block; width: 100%; padding: 14px; background: #111;
               border: 1px solid #222; border-radius: 10px; color: #e5e5e5;
               text-decoration: none; font-size: 14px; text-align: center;
               transition: border-color 0.15s; }
    a.signin:hover { border-color: #444; }
    a.action { display: block; font-size: 12px; color: #333; text-decoration: none; text-align: center; }
    a.action:hover { color: #666; }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="logo">North Star Network</div>
    <h1>AI Builders</h1>
    <p class="subtitle">Internal tooling — ${new Date().getFullYear()}</p>
    ${bodyHtml}
  </div>
</body>
</html>`);
});

// ── Logout ────────────────────────────────────────────────────────────────────
app.get('/logout', (req, res) => {
  res.clearCookie('nsn_auth', { domain: '.labnsn.com', path: '/' });
  res.redirect('https://labnsn.com');
});

// ── Auth validation endpoint (used by nginx auth_request) ─────────────────────
// Returns 200 if valid JWT cookie, 401 if not
app.get('/validate', (req, res) => {
  const token = req.cookies.nsn_auth;
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    jwt.verify(token, JWT_SECRET);
    res.status(200).json({ ok: true });
  } catch(e) {
    res.status(401).json({ error: 'Invalid token' });
  }
});
