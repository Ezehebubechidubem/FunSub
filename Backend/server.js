require('dotenv').config();

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const axios = require('axios');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { createAgentRouter } = require("./agent");
const { createIacafeGateway } = require("./services/vtuGateway");
const {
  applyMarkup,
  getMarkupPercent,
  applyAgentDiscount,
  normalizeServiceType: normalizeMarkupServiceType,
  buildRolePricing
} = require('./markup');

const app = express();
const PORT = process.env.PORT || 3000;

const envNumber = (value, fallback) => {
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
};

const iacafe = createIacafeGateway({
  baseURL: process.env.IACAFE_BASE_URL,
  apiKey: process.env.IACAFE_API_KEY,
  authType: process.env.IACAFE_AUTH_TYPE || "bearer",
});

const JWT_SECRET = process.env.JWT_SECRET || 'change_this_secret';
const FRONTEND_URL = process.env.FRONTEND_URL || '*';
const FLW_SECRET_KEY = process.env.FLW_SECRET_KEY;
const FLW_BASE_URL = String(process.env.FLW_BASE_URL || 'https://api.flutterwave.com/v3').replace(/\/$/, '');
const FLW_WEBHOOK_HASH = process.env.FLW_WEBHOOK_HASH;
const FLW_ACCOUNT_TYPE = String(process.env.FLW_ACCOUNT_TYPE || 'dynamic').toLowerCase();
const FLW_VA_EXPIRY = Number(process.env.FLW_VA_EXPIRY || 3600);

const pendingRequeryTimers = new Map();
const ICAFE_REQUERY_DELAY_MS = Number(process.env.ICAFE_REQUERY_DELAY_MS || 15000);
const ICAFE_REQUERY_MAX_ATTEMPTS = Number(process.env.ICAFE_REQUERY_MAX_ATTEMPTS || 6);

const FLW_CUSTOMER_URL = String(
  process.env.FLW_CUSTOMER_URL || `${FLW_BASE_URL}/customers`
).trim();

const SUCCESS_STATUSES = new Set([
  'successful',
  'success',
  'completed',
  'complete',
  'paid',
  'ok'
]);

const FLW_VA_URL = String(
  process.env.FLW_VA_URL || `${FLW_BASE_URL}/virtual-account-numbers`
).trim();

const ADMIN_API_KEY = process.env.ADMIN_API_KEY || '';
const DEFAULT_MARKUP_PERCENT = envNumber(process.env.DEFAULT_MARKUP_PERCENT, 1);
const FLW_WALLET_FEE_PERCENT = envNumber(process.env.FLW_WALLET_FEE_PERCENT, 0);

const UPLOAD_ROOT = path.join(__dirname, 'uploads');
const AVATAR_DIR = path.join(UPLOAD_ROOT, 'avatars');
const KYC_DIR = path.join(UPLOAD_ROOT, 'kyc');

for (const dir of [UPLOAD_ROOT, AVATAR_DIR, KYC_DIR]) {
  fs.mkdirSync(dir, { recursive: true });
}

app.use(helmet());
app.use(cors({ origin: FRONTEND_URL === '*' ? true : FRONTEND_URL, credentials: true }));
app.use(express.urlencoded({ extended: true }));
app.use('/uploads', express.static(UPLOAD_ROOT));

app.use(express.json({
  limit: '15mb',
  verify: (req, _res, buf) => {
    req.rawBody = buf.toString('utf8');
  }
}));

app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: envNumber(process.env.RATE_LIMIT_MAX, 300),
    standardHeaders: true,
    legacyHeaders: false
  })
);

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

const uid = (prefix = '') => `${prefix}${crypto.randomUUID().replace(/-/g, '')}`;
const normalizeEmail = (v) => String(v || '').trim().toLowerCase();
const normalizePhone = (v) => String(v || '').replace(/\D/g, '');
const toNumber = (v, fallback = 0) => {
  const n = Number(v);
  return Number.isFinite(n) ? n : fallback;
};

app.use(
  "/api/agent",
  createAgentRouter({
    pool,
    requireAuth,
    respondOk,
    respondError,
    uid,
    addNotification,
    verifyFundPin
  })
);

function signToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: '7d' });
}

function authHeader(req) {
  const h = req.headers.authorization || '';
  if (!h) return null;
  if (h.startsWith('Bearer ')) return h.slice(7);
  return h;
}

function respondOk(res, data = {}, message = 'OK') {
  return res.json({ success: true, message, ...data });
}

function respondError(res, status, message) {
  return res.status(status).json({ success: false, message });
}
function normalizeStatusValue(value) {
  return String(value || "").trim().toLowerCase();
}

function normalizeMeta(meta) {
  if (!meta) return {};

  if (typeof meta === "object" && !Array.isArray(meta)) {
    return meta;
  }

  if (typeof meta === "string") {
    try {
      const parsed = JSON.parse(meta);
      return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : {};
    } catch (_) {
      return { rawMeta: meta };
    }
  }

  return {};
}

function clearPendingRequery(requestId) {
  if (!requestId) return;

  const timer = pendingRequeryTimers.get(requestId);
  if (timer) clearTimeout(timer);
  pendingRequeryTimers.delete(requestId);
}

async function verifyFundPin(userId, fundPin) {
  if (!fundPin) return false;

  const result = await query(
    `SELECT fund_pin_hash
     FROM users
     WHERE id = $1
     LIMIT 1`,
    [userId]
  );

  const user = result.rows[0];
  if (!user?.fund_pin_hash) return false;

  return bcrypt.compare(String(fundPin), user.fund_pin_hash);
}

function extractProviderText(response) {
  const payload =
    response?.data &&
    typeof response.data === "object" &&
    !Array.isArray(response.data)
      ? response.data
      : response;

  const parts = [
    response?.message,
    response?.response_description,
    response?.description,
    response?.status,
    response?.state,
    response?.response_status,
    response?.responseState,
    payload?.message,
    payload?.response_description,
    payload?.description,
    payload?.status,
    payload?.state,
    payload?.response_status,
    payload?.responseState,
    response?.error?.message,
    payload?.error?.message,
  ];

  return parts
    .filter((v) => v !== undefined && v !== null && String(v).trim() !== "")
    .map((v) => String(v).trim())
    .join(" ")
    .trim()
    .toLowerCase();
}

function classifyProviderResponse(response) {
  const status = normalizeStatusValue(
    response?.status ||
      response?.state ||
      response?.response_status ||
      response?.responseState ||
      response?.data?.status ||
      response?.data?.state ||
      response?.data?.response_status ||
      response?.data?.responseState ||
      ""
  );

  const text = extractProviderText(response);

  const hasAny = (...tokens) =>
    tokens.some((token) => status.includes(token) || text.includes(token));

  if (hasAny("processing-api", "processing", "pending", "queued", "in-progress", "inprogress")) {
    return "pending";
  }

  if (hasAny("completed-api", "completed", "complete", "success", "successful", "paid", "delivered", "fulfilled", "ok")) {
    return "success";
  }

  if (hasAny("refunded-api", "refunded", "failed", "error", "reversed", "cancelled", "canceled", "declined")) {
    return "failed";
  }

  return "unknown";
}

function providerRequestLooksSuccessful(response) {
  if (response?.success === true) return true;
  if ([response?.code, response?.statusCode].some((v) => Number(v) === 200)) return true;

  const candidates = [
    response?.status,
    response?.message,
    response?.response_description,
    response?.data?.status,
    response?.data?.message,
    response?.data?.response_description,
  ]
    .map((v) => normalizeStatusValue(v))
    .filter(Boolean);

  if (
    candidates.some(
      (v) =>
        v === "success" ||
        v === "successful" ||
        v === "completed" ||
        v === "completed-api" ||
        v === "completed api" ||
        v === "complete" ||
        v === "transaction completed" ||
        v === "order completed" ||
        v === "payment completed" ||
        v === "transaction successful" ||
        v === "purchase successful" ||
        v === "processed successfully" ||
        v === "submitted successfully" ||
        v === "ok" ||
        v === "paid"
    )
  ) {
    return true;
  }

  const responseCode = String(response?.response_code ?? response?.data?.response_code ?? "").trim();
  if (["00", "0", "200"].includes(responseCode)) return true;

  return false;
}

function isSensitiveProviderError(err) {
  const text = String(
    err?.response?.data?.message ||
      err?.response?.data?.error?.message ||
      err?.message ||
      ""
  )
    .trim()
    .toLowerCase();

  return (
    text.includes("insufficient") ||
    text.includes("wallet") ||
    text.includes("balance") ||
    text.includes("fund exhausted") ||
    text.includes("low balance") ||
    text.includes("provider wallet")
  );
}

function withTimeout(promise, timeoutMs, timeoutMessage = "Provider timeout") {
  let timeoutId;

  const timeoutPromise = new Promise((_, reject) => {
    timeoutId = setTimeout(() => reject(new Error(timeoutMessage)), timeoutMs);
  });

  return Promise.race([
    promise.finally(() => clearTimeout(timeoutId)),
    timeoutPromise,
  ]);
}

function buildTxnRef(prefix = "TX") {
  return uid(`${prefix}_`);
}

function mergeMeta(oldMeta, extraMeta) {
  const base = oldMeta && typeof oldMeta === "object" ? oldMeta : {};
  return { ...base, ...extraMeta };
}

function verifyIacafeWebhookSignature(req, secret) {
  if (!secret) return true;

  const signature = String(
    req.headers["x-vtu-signature"] ||
      req.headers["x-iacafe-signature"] ||
      req.headers["x-webhook-signature"] ||
      req.headers["x-signature"] ||
      ""
  ).trim();

  const timestamp = String(
    req.headers["x-vtu-timestamp"] ||
      req.headers["x-iacafe-timestamp"] ||
      req.headers["x-webhook-timestamp"] ||
      ""
  ).trim();

  if (!signature || !timestamp) return false;

  const rawBody =
    typeof req.rawBody === "string"
      ? req.rawBody
      : Buffer.isBuffer(req.body)
        ? req.body.toString("utf8")
        : JSON.stringify(req.body || {});

  const expected = crypto
    .createHmac("sha256", secret)
    .update(`${timestamp}.${rawBody}`)
    .digest("hex");

  const normalizedSignature = signature.replace(/^sha256=/i, "");

  return expected === normalizedSignature || expected === signature;
}

async function query(text, params = []) {
  return pool.query(text, params);
}

function getDefaultMarkupPercent(serviceType) {
  const key = normalizeServiceType(serviceType);
  return Number.isFinite(SERVICE_MARKUP_DEFAULTS[key]) ? SERVICE_MARKUP_DEFAULTS[key] : DEFAULT_MARKUP_PERCENT;
}

function applyWalletFundingFee(grossAmount) {
  const gross = toNumber(grossAmount, 0);
  const feePercent = FLW_WALLET_FEE_PERCENT;
  const feeAmount = (gross * feePercent) / 100;
  const netAmount = gross - feeAmount;

  return {
    grossAmount: Number(gross.toFixed(2)),
    feePercent: Number(feePercent.toFixed(2)),
    feeAmount: Number(feeAmount.toFixed(2)),
    netAmount: Number(netAmount.toFixed(2))
  };
}
function ensureHttpUrl(value, name) {
  if (!/^https?:\/\//i.test(value)) {
    throw new Error(`${name} is invalid: ${value}`);
  }
  return value;
}

async function ensureWallet(userId) {
  const found = await query('SELECT * FROM wallets WHERE user_id = $1 LIMIT 1', [userId]);
  if (found.rows[0]) return found.rows[0];

  const created = await query(
    `INSERT INTO wallets (id, user_id, balance, currency)
     VALUES ($1, $2, 0, 'NGN')
     RETURNING *`,
    [uid('wal_'), userId]
  );
  return created.rows[0];
}

async function addNotification(userId, title, message, meta = {}, isSystem = true) {
  await query(
    `INSERT INTO notifications
     (id, user_id, title, message, meta, is_read, is_system, created_at)
     VALUES ($1, $2, $3, $4, $5, false, $6, NOW())`,
    [uid('not_'), userId, title, message, JSON.stringify(meta), isSystem]
  );
}

async function addTransaction({
  userId,
  type,
  category,
  amount,
  currency = 'NGN',
  status = 'success',
  reference,
  description,
  meta = {}
}) {
  const txRef = reference || uid('ref_');

  const inserted = await query(
    `INSERT INTO transactions
     (id, user_id, type, category, amount, currency, status, reference, description, meta, created_at)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,NOW())
     RETURNING *`,
    [
      uid('tx_'),
      userId,
      type,
      category,
      amount,
      currency,
      status,
      txRef,
      description,
      JSON.stringify(meta)
    ]
  );

  return inserted.rows[0];
}

async function requireAuth(req, res, next) {
  try {
    console.log('================ AUTH DEBUG ================');

    const authHeaderValue = req.headers.authorization;

    console.log('AUTH HEADER:', authHeaderValue);

    if (!authHeaderValue) {
      return res.status(401).json({
        success: false,
        message: 'Authorization header missing'
      });
    }

    if (!authHeaderValue.startsWith('Bearer ')) {
      return res.status(401).json({
        success: false,
        message: 'Invalid authorization format'
      });
    }

    const token = authHeaderValue.split(' ')[1];

    console.log('TOKEN:', token);

    const decoded = jwt.verify(token, JWT_SECRET);

    console.log('DECODED TOKEN USER:', decoded);

    const userResult = await query(
      `SELECT
         id,
         role,
         full_name,
         email,
         phone,
         state,
         avatar_url,
         kyc_status,
         profile_complete,
         online,
         last_login_at,
         created_at,
         updated_at,
         fund_pin_hash,
         fund_pin_set,
         fund_pin_failed_attempts,
         fund_pin_locked_until
       FROM users
       WHERE id = $1
       LIMIT 1`,
      [decoded.id]
    );

    const dbUser = userResult.rows[0];

    if (!dbUser) {
      return res.status(401).json({
        success: false,
        message: 'User not found'
      });
    }

    req.user = {
      ...decoded,
      ...dbUser
    };

    console.log('AUTH SUCCESS');
    console.log('CURRENT USER FROM DB:', req.user);
    console.log('============================================');

    next();
  } catch (err) {
    console.log('AUTH FAILED');
    console.log('ERROR MESSAGE:', err.message);
    console.log('============================================');

    return res.status(401).json({
      success: false,
      message: err.message || 'Unauthorized'
    });
  }
}

function requireAdmin(req, res, next) {
  try {
    const token = authHeader(req);
    if (!token) return respondError(res, 401, 'Unauthorized');

    const decoded = jwt.verify(token, JWT_SECRET);
    if (decoded.role !== 'admin') return respondError(res, 403, 'Admin access required');

    if (ADMIN_API_KEY) {
      const got = req.headers['x-admin-key'] || req.query.admin_key;
      if (got !== ADMIN_API_KEY) return respondError(res, 403, 'Invalid admin key');
    }

    req.user = decoded;
    next();
  } catch (err) {
    return respondError(res, 401, 'Unauthorized');
  }
}

const avatarUpload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => cb(null, AVATAR_DIR),
    filename: (req, file, cb) => {
      const safe = file.originalname.replace(/\s+/g, '_').replace(/[^a-zA-Z0-9_.-]/g, '');
      cb(null, `avatar-${Date.now()}-${safe}`);
    }
  }),
  limits: { fileSize: 5 * 1024 * 1024 }
});

const kycUpload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => cb(null, KYC_DIR),
    filename: (req, file, cb) => {
      const safe = file.originalname.replace(/\s+/g, '_').replace(/[^a-zA-Z0-9_.-]/g, '');
      cb(null, `kyc-${Date.now()}-${safe}`);
    }
  }),
  limits: { fileSize: 12 * 1024 * 1024 }
});
async function initDb() {
  await query(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      role TEXT NOT NULL DEFAULT 'user',
      full_name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      phone TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      state TEXT,
      avatar_url TEXT,
      kyc_status TEXT NOT NULL DEFAULT 'unverified',
      profile_complete BOOLEAN NOT NULL DEFAULT FALSE,
      online BOOLEAN NOT NULL DEFAULT FALSE,
      last_login_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      fund_pin_hash TEXT,
      fund_pin_set BOOLEAN NOT NULL DEFAULT FALSE,
      fund_pin_failed_attempts INTEGER NOT NULL DEFAULT 0,
      fund_pin_locked_until TIMESTAMPTZ
    );

    CREATE TABLE IF NOT EXISTS wallets (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
      balance NUMERIC(14,2) NOT NULL DEFAULT 0,
      currency TEXT NOT NULL DEFAULT 'NGN',
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS transactions (
      id TEXT PRIMARY KEY,
      user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
      type TEXT NOT NULL,
      category TEXT NOT NULL,
      amount NUMERIC(14,2) NOT NULL DEFAULT 0,
      currency TEXT NOT NULL DEFAULT 'NGN',
      status TEXT NOT NULL DEFAULT 'success',
      reference TEXT NOT NULL UNIQUE,
      description TEXT,
      meta JSONB DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS notifications (
      id TEXT PRIMARY KEY,
      user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
      title TEXT NOT NULL,
      message TEXT NOT NULL,
      meta JSONB DEFAULT '{}'::jsonb,
      is_read BOOLEAN NOT NULL DEFAULT FALSE,
      is_system BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS kyc_requests (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      id_type TEXT NOT NULL,
      id_number TEXT NOT NULL,
      selfie_url TEXT,
      id_front_url TEXT,
      id_back_url TEXT,
      utility_bill_url TEXT,
      address TEXT,
      status TEXT NOT NULL DEFAULT 'pending',
      admin_note TEXT,
      submitted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      reviewed_at TIMESTAMPTZ
    );

    CREATE TABLE IF NOT EXISTS payment_intents (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      tx_ref TEXT NOT NULL UNIQUE,
      amount NUMERIC(14,2) NOT NULL,
      currency TEXT NOT NULL DEFAULT 'NGN',
      provider TEXT NOT NULL DEFAULT 'flutterwave',
      status TEXT NOT NULL DEFAULT 'initiated',
      meta JSONB DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      verified_at TIMESTAMPTZ,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS admin_logs (
      id TEXT PRIMARY KEY,
      admin_id TEXT REFERENCES users(id) ON DELETE SET NULL,
      action TEXT NOT NULL,
      meta JSONB DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS pricing_rules (
      id TEXT PRIMARY KEY,
      service_type TEXT NOT NULL UNIQUE,
      markup_percent NUMERIC(5,2) NOT NULL DEFAULT 2,
      is_active BOOLEAN NOT NULL DEFAULT TRUE,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await query(`
    ALTER TABLE users
      ADD COLUMN IF NOT EXISTS fund_pin_hash TEXT,
      ADD COLUMN IF NOT EXISTS fund_pin_set BOOLEAN NOT NULL DEFAULT FALSE,
      ADD COLUMN IF NOT EXISTS fund_pin_failed_attempts INTEGER NOT NULL DEFAULT 0,
      ADD COLUMN IF NOT EXISTS fund_pin_locked_until TIMESTAMPTZ;
  `);

  await query(`
    ALTER TABLE transactions
      ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
  `);

  await query(`
    ALTER TABLE payment_intents
      ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
  `);
}
