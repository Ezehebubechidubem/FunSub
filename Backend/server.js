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

function flutterwaveHeaders() {
  if (!FLW_SECRET_KEY) {
    throw new Error('FLW_SECRET_KEY is missing');
  }

  return {
    Authorization: `Bearer ${FLW_SECRET_KEY}`,
    'Content-Type': 'application/json',
    Accept: 'application/json'
  };
}

function flutterwaveTxRef(prefix = 'PS') {
  return `${prefix}-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
}

function splitFullName(fullName = '') {
  const parts = String(fullName).trim().split(/\s+/).filter(Boolean);
  const first = parts.shift() || 'User';
  const last = parts.join(' ') || first;
  return { first, last };
}

function isValidFlutterwaveWebhook(req) {
  if (!process.env.FLW_WEBHOOK_HASH) return true;

  const got =
    String(req.headers['verif-hash'] || req.headers['x-flw-secret-hash'] || '').trim();

  return got && got === process.env.FLW_WEBHOOK_HASH;
}

async function flutterwaveCreateCustomer(user) {
  if (!user?.email) {
    throw new Error('User email is required to create Flutterwave customer');
  }

  const { first, last } = splitFullName(
    user.full_name || user.fullName || user.name || 'User'
  );

  const customerPayload = {
    email: user.email,
    name: {
      first,
      last
    },
    phone: user.phone
      ? { number: String(user.phone) }
      : undefined,
    meta: {
      user_id: user.id,
      purpose: 'wallet_funding'
    }
  };

  const cleanedPayload = Object.fromEntries(
    Object.entries(customerPayload).filter(([, value]) =>
      value !== undefined && value !== null && value !== ''
    )
  );

  const customerRes = await axios.post(FLW_CUSTOMER_URL, cleanedPayload, {
    headers: flutterwaveHeaders(),
    timeout: 30000
  });

  return customerRes.data?.data || customerRes.data;
}
async function pollFundingStatus(reference, amount) {
  stopPolling();
  fundingPollTimer = setInterval(async () => {
    const res = await fetch(
      `${API_ROOT}/api/wallet/fund/status/${encodeURIComponent(reference)}`,
      {
        headers: { Authorization: `Bearer ${localStorage.getItem('funsub_token') || ''}` }
      }
    );

    const data = await res.json().catch(() => ({}));
    const intentStatus = String(data?.intent?.status || '').toLowerCase();
    const txStatus = String(data?.transaction?.status || '').toLowerCase();

    if (intentStatus === 'successful' || txStatus === 'success') {
      stopPolling();
      showToast('Success', `₦${Number(amount).toLocaleString('en-NG')} funded successfully`);
      setStatus(`₦${Number(amount).toLocaleString('en-NG')} funded successfully`, 'success');
      setTimeout(() => window.location.href = 'dashboard.html', 1800);
    }
  }, 3000);
}

function providerAuthPayload() {
  return {};
}

function normalizeStatus(value) {
  return normalizeStatusValue(value);
}

function normalizeServiceType(v) {
  const s = String(v || '').toLowerCase().trim();

  const map = {
    cable: 'cable_tv',
    'cable-tv': 'cable_tv',
    cabletv: 'cable_tv',
    'cable_tv': 'cable_tv',

    'recharge-pin': 'recharge_pin',
    rechargepin: 'recharge_pin',
    recharge_pin: 'recharge_pin',

    'data-pin': 'data_pin',
    datapin: 'data_pin',
    data_pin: 'data_pin',

    'exam-pin': 'exam_pin',
    exampin: 'exam_pin',
    exam_pin: 'exam_pin'
  };

  return map[s] || s;
}

function getProviderConfig(serviceType) {
  const normalized = normalizeServiceType(serviceType);
  return {
    serviceType: normalized,
    ...PROVIDER_ENDPOINTS[normalized]
  };
}

function compactObject(obj) {
  const out = {};
  for (const [k, v] of Object.entries(obj || {})) {
    if (v !== undefined && v !== null && v !== '') out[k] = v;
  }
  return out;
}

function extractArrayFromProviderResponse(data) {
  if (Array.isArray(data)) return data;
  if (Array.isArray(data?.content?.variations)) return data.content.variations;
  if (Array.isArray(data?.data?.content?.variations)) return data.data.content.variations;
  if (Array.isArray(data?.data?.variations)) return data.data.variations;
  if (Array.isArray(data?.variations)) return data.variations;
  if (Array.isArray(data?.data)) return data.data;
  if (Array.isArray(data?.plans)) return data.plans;
  if (Array.isArray(data?.result)) return data.result;
  if (Array.isArray(data?.items)) return data.items;
  if (Array.isArray(data?.response)) return data.response;
  return [];
}

function normalizeProviderPlan(plan) {
  const rawPrice = plan.variation_amount ?? plan.price ?? plan.amount ?? plan.cost ?? plan.value ?? 0;

  return {
    id: plan.variation_code || plan.id || plan.plan_id || plan.code || plan.slug || plan.bundle_id || uid('plan_'),
    name: plan.name || plan.variation_name || plan.title || plan.network || plan.bundle || plan.description || 'Plan',
    rawPrice: Number(rawPrice),
    meta: plan
  };
}
async function processServicePayment(req, res, serviceType, serviceName) {
  const normalizedServiceType = normalizeServiceType(serviceType);
  const PROVIDER_TIMEOUT_MS = 60_000;
  const PIN_MAX_ATTEMPTS = 4;
  const PIN_LOCK_MS = 60 * 60 * 1000; // 1 hour

  async function reverseAndRefund(txRow, userId, purchaseAmount, reason, extraMeta = {}) {
    if (!txRow?.id) return;

    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      const txCheck = await client.query(
        `SELECT status, meta
         FROM transactions
         WHERE id = $1
         FOR UPDATE`,
        [txRow.id]
      );

      if (!txCheck.rows.length) {
        await client.query('ROLLBACK');
        return;
      }

      const currentStatus = String(txCheck.rows[0].status || '').toLowerCase();
      if (currentStatus !== 'pending') {
        await client.query('ROLLBACK');
        return;
      }

      const currentMeta = normalizeMeta(txCheck.rows[0].meta);
      const mergedMeta = mergeMeta(currentMeta, {
        reverseReason: reason,
        ...extraMeta,
        updatedAt: new Date().toISOString(),
      });

      await client.query(
        `UPDATE wallets
         SET balance = balance + $2,
             updated_at = NOW()
         WHERE user_id = $1`,
        [userId, purchaseAmount]
      );

      await client.query(
        `UPDATE transactions
         SET status = 'reversed',
             description = $2,
             meta = $3
         WHERE id = $1`,
        [txRow.id, reason, JSON.stringify(mergedMeta)]
      );

      await client.query('COMMIT');
    } catch (err) {
      try {
        await client.query('ROLLBACK');
      } catch (_) {}
      throw err;
    } finally {
      client.release();
    }
  }

  async function verifyAndTrackPin(userId, fundPin) {
    const client = await pool.connect();

    try {
      await client.query('BEGIN');

      const stateResult = await client.query(
        `SELECT
           COALESCE(fund_pin_failed_attempts, 0) AS failed_attempts,
           fund_pin_locked_until
         FROM users
         WHERE id = $1
         FOR UPDATE`,
        [userId]
      );

      const row = stateResult.rows[0];
      if (!row) {
        await client.query('ROLLBACK');
        return { ok: false, status: 404, message: 'User not found' };
      }

      let failedAttempts = Number(row.failed_attempts || 0);
      const lockedUntil = row.fund_pin_locked_until ? new Date(row.fund_pin_locked_until) : null;
      const now = Date.now();

      if (lockedUntil && lockedUntil.getTime() <= now) {
        await client.query(
          `UPDATE users
           SET fund_pin_failed_attempts = 0,
               fund_pin_locked_until = NULL,
               updated_at = NOW()
           WHERE id = $1`,
          [userId]
        );
        failedAttempts = 0;
      }

      if (lockedUntil && lockedUntil.getTime() > now) {
        const minutesLeft = Math.max(1, Math.ceil((lockedUntil.getTime() - now) / 60000));
        await client.query('ROLLBACK');
        return {
          ok: false,
          status: 423,
          message: `Too many invalid PIN attempts. Try again in ${minutesLeft} minute(s).`,
          locked: true,
          minutesLeft
        };
      }

      const pinOk = await verifyFundPin(userId, fundPin);

      if (!pinOk) {
        const nextAttempts = failedAttempts + 1;
        const shouldLock = nextAttempts >= PIN_MAX_ATTEMPTS;
        const lockUntil = shouldLock ? new Date(Date.now() + PIN_LOCK_MS) : null;

        await client.query(
          `UPDATE users
           SET fund_pin_failed_attempts = $2,
               fund_pin_locked_until = $3,
               updated_at = NOW()
           WHERE id = $1`,
          [userId, shouldLock ? PIN_MAX_ATTEMPTS : nextAttempts, lockUntil]
        );

        await client.query('COMMIT');

        return {
          ok: false,
          status: shouldLock ? 423 : 401,
          message: shouldLock
            ? 'Invalid PIN. Your account has been locked for 1 hour after 4 failed attempts.'
            : `Invalid fund PIN. ${PIN_MAX_ATTEMPTS - nextAttempts} attempt(s) left before lock.`,
          attemptsLeft: Math.max(0, PIN_MAX_ATTEMPTS - nextAttempts),
          locked: shouldLock,
          minutesLeft: shouldLock ? 60 : 0
        };
      }

      await client.query(
        `UPDATE users
         SET fund_pin_failed_attempts = 0,
             fund_pin_locked_until = NULL,
             updated_at = NOW()
         WHERE id = $1`,
        [userId]
      );

      await client.query('COMMIT');
      return { ok: true };
    } catch (err) {
      try {
        await client.query('ROLLBACK');
      } catch (_) {}
      throw err;
    } finally {
      client.release();
    }
  }

  try {
    const body = req.body || {};
    const userId = req.user?.id || req.user?.userId;

    if (!userId) {
      return respondError(res, 401, 'Unauthorized');
    }

    const fundPin = String(body.fundPin || body.fund_pin || '').trim();
    if (!fundPin) {
      return respondError(res, 400, 'Transaction PIN is required');
    }

    const pinCheck = await verifyAndTrackPin(userId, fundPin);
    if (!pinCheck.ok) {
      return respondError(res, pinCheck.status || 401, pinCheck.message || 'Invalid fund PIN');
    }

    let pricing = null;
    let selectedPlan = null;
    let description = `${serviceName} purchase`;

    const rawDestination =
      body.phone ||
      body.smartcard_number ||
      body.meter_number ||
      body.customer_id ||
      body.accountNumber ||
      body.billersCode ||
      '';

    const destination = normalizePhone(rawDestination) || String(rawDestination).trim();

    let providerAmount = 0;
    let purchaseAmount = 0;
    const role = req.user?.role;
    const requestId = String(body.request_id || body.requestId || body.reference || buildTxnRef(normalizedServiceType.toUpperCase())).trim();

    if (normalizedServiceType === 'airtime') {
      providerAmount = toNumber(body.amount, 0);

      if (providerAmount <= 0 || !destination) {
        return respondError(res, 400, 'amount and phone are required');
      }

      pricing = buildRolePricing('airtime', providerAmount, role);
      purchaseAmount = pricing.finalPrice;

      if (purchaseAmount <= 0) {
        purchaseAmount = providerAmount;
      }
    } else {
      const variationCode = String(
        body.variation_code ||
        body.planId ||
        body.plan_id ||
        body.planCode ||
        body.code ||
        ''
      ).trim();

      providerAmount = toNumber(
        body.base_price ||
        body.rawPrice ||
        body.raw_price ||
        body.amount,
        0
      );

      if (!variationCode) {
        return respondError(res, 400, 'variation_code is required');
      }

      if (providerAmount <= 0) {
        return respondError(res, 400, 'base_price is required');
      }

      const pricingOptions = {
        network: body.network || body.service_id || body.serviceId,
        provider: body.provider,
        service_id: body.service_id || body.serviceId
      };

      pricing = buildRolePricing(normalizedServiceType, providerAmount, role, pricingOptions);
      purchaseAmount = pricing.finalPrice;

      selectedPlan = {
        id: variationCode,
        name: body.plan_name || `${serviceName} Plan`,
        rawPrice: providerAmount,
        purchase_amount: purchaseAmount,
        purchase_route:
          String(body.purchase_route || body.plan_source || body.source || '').toLowerCase() === 'budget-data'
            ? '/budget-data'
            : '/data',
        purchase_key: variationCode,
        meta: {
          service_id: body.service_id || body.serviceId,
          provider: body.provider,
          network: body.network
        }
      };

      description = `${serviceName} - ${selectedPlan.name}`;
    }

    if (!pricing) {
      return respondError(res, 400, 'Unable to prepare purchase');
    }

    const client = await pool.connect();
    let txRow = null;

    try {
      await client.query('BEGIN');

      const walletResult = await client.query(
        'SELECT * FROM wallets WHERE user_id = $1 FOR UPDATE',
        [userId]
      );

      const wallet = walletResult.rows[0];
      if (!wallet) {
        await client.query('ROLLBACK');
        return respondError(res, 404, 'Wallet not found');
      }

      const currentBalance = Number(wallet.balance || 0);
      if (currentBalance < purchaseAmount) {
        await client.query('ROLLBACK');
        return respondError(res, 400, 'Insufficient wallet balance');
      }

      await client.query(
        `UPDATE wallets
         SET balance = balance - $2,
             updated_at = NOW()
         WHERE user_id = $1`,
        [userId, purchaseAmount]
      );

      const inserted = await client.query(
        `INSERT INTO transactions
         (id, user_id, type, category, amount, currency, status, reference, description, meta, created_at)
         VALUES
         ($1, $2, $3, $4, $5, 'NGN', 'pending', $6, $7, $8, NOW())
         RETURNING *`,
        [
          uid('tx_'),
          userId,
          'purchase',
          normalizedServiceType,
          purchaseAmount,
          requestId,
          description,
          JSON.stringify({
            requestId,
            serviceType: normalizedServiceType,
            serviceName,
            selectedPlan,
            pricing,
            providerAmount,
            purchaseAmount,
            status: 'pending',
            expiresAt: new Date(Date.now() + PROVIDER_TIMEOUT_MS).toISOString()
          })
        ]
      );

      txRow = inserted.rows[0];

      await client.query('COMMIT');
    } catch (err) {
      try {
        await client.query('ROLLBACK');
      } catch (_) {}
      throw err;
    } finally {
      client.release();
    }

    const providerBody = {
      ...body,
      request_id: requestId,
      amount: providerAmount,
      plan_amount: providerAmount,
      base_price: providerAmount,
      final_amount: purchaseAmount
    };

    let providerResponse;

    try {
      providerResponse = await withTimeout(
        buyServiceThroughGateway({
          serviceType: normalizedServiceType,
          body: providerBody,
          selectedPlan,
          requestId
        }),
        PROVIDER_TIMEOUT_MS,
        'Provider timeout'
      );
    } catch (err) {
      console.error('PROVIDER CALL TIMEOUT/ERROR:', err?.message);

      await pool.query(
        `UPDATE transactions
         SET status = 'pending',
             description = $2,
             meta = $3
         WHERE id = $1`,
        [
          txRow.id,
          `${description} pending`,
          JSON.stringify({
            requestId,
            serviceType: normalizedServiceType,
            serviceName,
            selectedPlan,
            pricing,
            providerAmount,
            purchaseAmount,
            providerError: err?.message || 'Provider timeout',
            status: 'pending',
            expiresAt: new Date(Date.now() + PROVIDER_TIMEOUT_MS).toISOString()
          })
        ]
      );

      scheduleIacafeRequery(requestId, { delayMs: ICAFE_REQUERY_DELAY_MS, attempt: 1 });

      return res.status(202).json({
        success: true,
        pending: true,
        message: err?.message || 'Provider timeout. Transaction is pending.',
        transaction: {
          ...txRow,
          status: 'pending'
        },
        pricing,
        requestId
      });
    }

    console.log('PROVIDER RESPONSE:', JSON.stringify(providerResponse, null, 2));

    const providerState = classifyProviderResponse(providerResponse);
    const providerText = extractProviderText(providerResponse);

    if (providerState === 'pending' || providerState === 'unknown') {
      await pool.query(
        `UPDATE transactions
         SET status = 'pending',
             description = $2,
             meta = $3
         WHERE id = $1`,
        [
          txRow.id,
          `${description} pending`,
          JSON.stringify({
            requestId,
            serviceType: normalizedServiceType,
            serviceName,
            selectedPlan,
            pricing,
            providerAmount,
            purchaseAmount,
            providerResponse,
            status: 'pending',
            expiresAt: new Date(Date.now() + PROVIDER_TIMEOUT_MS).toISOString()
          })
        ]
      );

      scheduleIacafeRequery(requestId, { delayMs: ICAFE_REQUERY_DELAY_MS, attempt: 1 });

      return res.status(202).json({
        success: true,
        pending: true,
        message: providerText || 'Purchase pending',
        transaction: {
          ...txRow,
          status: 'pending'
        },
        pricing,
        requestId,
        providerResponse
      });
    }

    if (providerState === 'failed') {
      await reverseAndRefund(
        txRow,
        userId,
        purchaseAmount,
        `${description} failed`,
        {
          requestId,
          serviceType: normalizedServiceType,
          serviceName,
          selectedPlan,
          pricing,
          providerAmount,
          purchaseAmount,
          providerResponse
        }
      );

      return respondError(
        res,
        400,
        providerText || providerResponse?.response_description || providerResponse?.message || 'Purchase failed'
      );
    }

    await pool.query(
      `UPDATE transactions
       SET status = 'success',
           description = $2,
           meta = $3
       WHERE id = $1`,
      [
        txRow.id,
        description,
        JSON.stringify({
          requestId,
          serviceType: normalizedServiceType,
          serviceName,
          selectedPlan,
          pricing,
          providerAmount,
          purchaseAmount,
          providerResponse,
          status: 'success'
        })
      ]
    );

    clearPendingRequery(requestId);

    await addNotification(
      userId,
      `${serviceName} purchased`,
      `${description} was successful`,
      {
        transactionId: txRow.id,
        requestId,
        serviceType: normalizedServiceType,
        pricing,
        providerAmount,
        purchaseAmount,
        providerResponse
      },
      true
    );

    return respondOk(
      res,
      {
        transaction: {
          ...txRow,
          status: 'success',
          amount: purchaseAmount
        },
        pricing,
        requestId,
        providerResponse
      },
      `${serviceName} purchased successfully`
    );
  } catch (err) {
    console.error('PROCESS SERVICE PAYMENT ERROR:', err);
    console.error('ERROR MESSAGE:', err?.message);
    console.error('ERROR STACK:', err?.stack);
    console.error('ERROR RESPONSE DATA:', err?.response?.data);

    return respondError(
      res,
      500,
      err?.message || `Unable to process ${serviceName.toLowerCase()} purchase`
    );
  }
}
async function requeryTransactionByRequestId(requestId, { source = 'requery' } = {}) {
  if (!requestId) return { found: false, state: 'unknown' };

  const providerResponse = await iacafe.requery(requestId);
  return applyProviderOutcomeByReference({
    requestId,
    providerResponse,
    source,
  });
}

function scheduleIacafeRequery(
  requestId,
  {
    delayMs = ICAFE_REQUERY_DELAY_MS,
    attempt = 1,
    maxAttempts = ICAFE_REQUERY_MAX_ATTEMPTS,
  } = {}
) {
  if (!requestId) return;

  const existing = pendingRequeryTimers.get(requestId);
  if (existing) clearTimeout(existing);

  const timer = setTimeout(async () => {
    pendingRequeryTimers.delete(requestId);

    try {
      const result = await requeryTransactionByRequestId(requestId, {
        source: `timer_${attempt}`,
      });

      if (
        (result?.state === 'pending' || result?.state === 'unknown') &&
        attempt < maxAttempts
      ) {
        scheduleIacafeRequery(requestId, {
          delayMs: delayMs * 2,
          attempt: attempt + 1,
          maxAttempts,
        });
      }
    } catch (err) {
      console.error('Scheduled requery failed:', requestId, err?.message);

      if (attempt < maxAttempts) {
        scheduleIacafeRequery(requestId, {
          delayMs: delayMs * 2,
          attempt: attempt + 1,
          maxAttempts,
        });
      }
    }
  }, delayMs);

  pendingRequeryTimers.set(requestId, timer);
}

async function requeryPendingServiceTransactions() {
  const client = await pool.connect();

  function safeMeta(meta) {
    if (!meta) return {};

    if (typeof meta === 'object' && !Array.isArray(meta)) {
      return meta;
    }

    if (typeof meta === 'string') {
      try {
        const parsed = JSON.parse(meta);
        return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : {};
      } catch (_) {
        return { rawMeta: meta };
      }
    }

    return {};
  }

  try {
    const result = await client.query(
      `SELECT id, user_id, reference, amount, category, meta, status
       FROM transactions
       WHERE status = 'pending'
         AND created_at <= NOW() - INTERVAL '20 seconds'
       ORDER BY created_at ASC
       LIMIT 50`
    );

    for (const tx of result.rows) {
      const meta = safeMeta(tx.meta);
      const requestId = tx.reference;

      if (!requestId) continue;

      let providerResponse;
      try {
        providerResponse = await iacafe.requery(requestId);
      } catch (err) {
        console.error('Requery failed for:', requestId, err?.message);
        continue;
      }

      const state = classifyProviderResponse(providerResponse);

      if (state === 'pending' || state === 'unknown') {
        await client.query(
          `UPDATE transactions
           SET meta = $2
           WHERE id = $1`,
          [
            tx.id,
            JSON.stringify({
              ...meta,
              providerResponse,
              requeryResult: 'pending',
              updatedAt: new Date().toISOString(),
            }),
          ]
        );
        continue;
      }

      if (state === 'success') {
        await client.query(
          `UPDATE transactions
           SET status = 'success',
               meta = $2
           WHERE id = $1`,
          [
            tx.id,
            JSON.stringify({
              ...meta,
              providerResponse,
              requeryResult: 'success',
              updatedAt: new Date().toISOString(),
            }),
          ]
        );
        clearPendingRequery(requestId);
        continue;
      }

      if (state === 'failed') {
        await client.query('BEGIN');
        try {
          const check = await client.query(
            `SELECT status, user_id, amount, meta
             FROM transactions
             WHERE id = $1
             FOR UPDATE`,
            [tx.id]
          );

          if (!check.rows.length) {
            await client.query('ROLLBACK');
            continue;
          }

          const currentStatus = String(check.rows[0].status || '').toLowerCase();
          if (currentStatus !== 'pending') {
            await client.query('ROLLBACK');
            continue;
          }

          await client.query(
            `UPDATE wallets
             SET balance = balance + $2,
                 updated_at = NOW()
             WHERE user_id = $1`,
            [tx.user_id, tx.amount]
          );

          await client.query(
            `UPDATE transactions
             SET status = 'reversed',
                 meta = $2
             WHERE id = $1`,
            [
              tx.id,
              JSON.stringify({
                ...meta,
                providerResponse,
                requeryResult: 'failed',
                updatedAt: new Date().toISOString(),
              }),
            ]
          );

          await client.query('COMMIT');
          clearPendingRequery(requestId);
        } catch (err) {
          try {
            await client.query('ROLLBACK');
          } catch (_) {}
          console.error('Requery reverse failed:', tx.id, err?.message);
        }
      }
    }
  } finally {
    client.release();
  }
}

setInterval(() => {
  requeryPendingServiceTransactions().catch((err) => {
    console.error('Pending requery worker error:', err?.message);
  });
}, 60_000);
async function processBettingPayment(req, res) {
  const PROVIDER_TIMEOUT_MS = 60_000;
  const PIN_MAX_ATTEMPTS = 4;
  const PIN_LOCK_MS = 60 * 60 * 1000; // 1 hour

  async function verifyAndTrackPin(userId, fundPin) {
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const stateResult = await client.query(
        `SELECT COALESCE(fund_pin_failed_attempts, 0) AS failed_attempts, fund_pin_locked_until FROM users WHERE id = $1 FOR UPDATE`,
        [userId]
      );
      const row = stateResult.rows[0];
      if (!row) { await client.query('ROLLBACK'); return { ok: false, status: 404, message: 'User not found' }; }

      let failedAttempts = Number(row.failed_attempts || 0);
      const lockedUntil = row.fund_pin_locked_until ? new Date(row.fund_pin_locked_until) : null;
      const now = Date.now();
      if (lockedUntil && lockedUntil.getTime() <= now) {
        await client.query(`UPDATE users SET fund_pin_failed_attempts = 0, fund_pin_locked_until = NULL, updated_at = NOW() WHERE id = $1`, [userId]);
        failedAttempts = 0;
      }
      if (lockedUntil && lockedUntil.getTime() > now) {
        const minutesLeft = Math.max(1, Math.ceil((lockedUntil.getTime() - now) / 60000));
        await client.query('ROLLBACK');
        return { ok: false, status: 423, message: `Too many invalid PIN attempts. Try again in ${minutesLeft} minute(s).`, locked: true };
      }
      const pinOk = await verifyFundPin(userId, fundPin);
      if (!pinOk) {
        const nextAttempts = failedAttempts + 1; const shouldLock = nextAttempts >= PIN_MAX_ATTEMPTS;
        const lockUntil = shouldLock ? new Date(Date.now() + PIN_LOCK_MS) : null;
        await client.query(`UPDATE users SET fund_pin_failed_attempts = $2, fund_pin_locked_until = $3, updated_at = NOW() WHERE id = $1`, [userId, shouldLock ? PIN_MAX_ATTEMPTS : nextAttempts, lockUntil]);
        await client.query('COMMIT');
        return { ok: false, status: shouldLock ? 423 : 401, message: shouldLock ? 'Invalid PIN. Locked for 1 hour.' : `Invalid fund PIN. ${PIN_MAX_ATTEMPTS - nextAttempts} attempt(s) left`, locked: shouldLock };
      }
      await client.query(`UPDATE users SET fund_pin_failed_attempts = 0, fund_pin_locked_until = NULL, updated_at = NOW() WHERE id = $1`, [userId]);
      await client.query('COMMIT');
      return { ok: true };
    } catch (err) { try { await client.query('ROLLBACK'); } catch (_) {} throw err; } finally { client.release(); }
  }

  try {
    const body = req.body || {};
    const userId = req.user?.id || req.user?.userId;
    if (!userId) return respondError(res, 401, 'Unauthorized');

    const fundPin = String(body.fundPin || '').trim();
    if (!fundPin) return respondError(res, 400, 'Transaction PIN is required');

    const pinCheck = await verifyAndTrackPin(userId, fundPin);
    if (!pinCheck.ok) return respondError(res, pinCheck.status || 401, pinCheck.message || 'Invalid fund PIN');

    const customer_id = String(body.customer_id || '').trim();
    const service_id = String(body.service_id || '').trim();
    const amount = toNumber(body.amount, 0);
    const request_id = String(body.request_id || body.requestId || body.reference || buildTxnRef('BET')).trim();

    if (!customer_id || !service_id) return respondError(res, 400, 'customer_id and service_id are required');
    if (amount < 100) return respondError(res, 400, 'Minimum betting amount is ₦100');

    const description = `Betting Funding - ${service_id}`;

    const client = await pool.connect();
    let txRow = null;
    try {
      await client.query('BEGIN');
      const walletResult = await client.query('SELECT * FROM wallets WHERE user_id = $1 FOR UPDATE', [userId]);
      const wallet = walletResult.rows[0];
      if (!wallet) { await client.query('ROLLBACK'); return respondError(res, 404, 'Wallet not found'); }
      const currentBalance = Number(wallet.balance || 0);
      if (currentBalance < amount) { await client.query('ROLLBACK'); return respondError(res, 400, 'Insufficient wallet balance'); }

      await client.query(`UPDATE wallets SET balance = balance - $2, updated_at = NOW() WHERE user_id = $1`, [userId, amount]);

      const inserted = await client.query(
        `INSERT INTO transactions (id, user_id, type, category, amount, currency, status, reference, description, meta, created_at)
         VALUES ($1, $2, 'purchase', 'betting', $3, 'NGN', 'pending', $4, $5, $6, NOW()) RETURNING *`,
        [uid('tx_'), userId, amount, request_id, description, JSON.stringify({ customer_id, service_id, amount, request_id, status: 'pending' })]
      );
      txRow = inserted.rows[0];
      await client.query('COMMIT');
    } catch (err) { try { await client.query('ROLLBACK'); } catch (_) {} throw err; } finally { client.release(); }

    let providerResponse;
    try {
      providerResponse = await withTimeout(
        iacafe.buyBetting({
          request_id,
          customer_id,
          service_id,
          amount,
          skip_verify: true
        }),
        PROVIDER_TIMEOUT_MS,
        'Provider timeout'
      );
    } catch (err) {
      console.error('BETTING PROVIDER CALL TIMEOUT/ERROR:', err?.message);

      await pool.query(
        `UPDATE transactions
         SET status = 'pending',
             description = $2,
             meta = $3
         WHERE id = $1`,
        [
          txRow.id,
          `${description} pending`,
          JSON.stringify({
            customer_id,
            service_id,
            amount,
            request_id,
            providerError: err?.message || 'Provider timeout',
            status: 'pending'
          })
        ]
      );

      scheduleIacafeRequery(request_id, { delayMs: ICAFE_REQUERY_DELAY_MS, attempt: 1 });

      return res.status(202).json({
        success: true,
        pending: true,
        message: err?.message || 'Provider timeout. Transaction is pending.',
        transaction: { ...txRow, status: 'pending' },
        request_id
      });
    }

    const providerState = classifyProviderResponse(providerResponse);
    const providerText = extractProviderText(providerResponse);

    if (providerState === 'pending' || providerState === 'unknown') {
      await pool.query(
        `UPDATE transactions
         SET status = 'pending',
             description = $2,
             meta = $3
         WHERE id = $1`,
        [
          txRow.id,
          description,
          JSON.stringify({
            customer_id,
            service_id,
            amount,
            request_id,
            providerResponse,
            status: 'pending'
          })
        ]
      );

      scheduleIacafeRequery(request_id, { delayMs: ICAFE_REQUERY_DELAY_MS, attempt: 1 });

      return res.status(202).json({
        success: true,
        pending: true,
        message: providerText || 'Betting funding pending',
        transaction: { ...txRow, status: 'pending' },
        providerResponse,
        request_id
      });
    }

    if (providerState === 'failed') {
      await pool.query(`UPDATE wallets SET balance = balance + $2, updated_at = NOW() WHERE user_id = $1`, [userId, amount]);
      await pool.query(
        `UPDATE transactions
         SET status = 'failed',
             description = $2,
             meta = $3
         WHERE id = $1`,
        [
          txRow.id,
          `${description} failed`,
          JSON.stringify({ customer_id, service_id, amount, request_id, providerResponse })
        ]
      );

      return respondError(res, 400, providerText || providerResponse?.message || 'Betting funding failed');
    }

    await pool.query(
      `UPDATE transactions
       SET status = 'success',
           description = $2,
           meta = $3
       WHERE id = $1`,
      [
        txRow.id,
        description,
        JSON.stringify({
          customer_id,
          service_id,
          amount,
          request_id,
          providerResponse,
          status: 'success'
        })
      ]
    );

    clearPendingRequery(request_id);

    await addNotification(
      userId,
      'Betting Funded',
      `${description} of ₦${amount.toLocaleString('en-NG')} was successful`,
      { transactionId: txRow.id, request_id, providerResponse },
      true
    );

    return respondOk(
      res,
      { transaction: { ...txRow, status: 'success' }, providerResponse, request_id },
      'Betting funded successfully'
    );
  } catch (err) {
    console.error('PROCESS BETTING PAYMENT ERROR:', err);
    return respondError(res, 500, err?.message || 'Unable to process betting purchase');
  }
}
function requireDebugAccess(req, res, next) {
  const got = req.headers['x-debug-key'] || req.query.debug_key;
  const expected = process.env.DEBUG_KEY;

  if (!expected || got !== expected) {
    return respondError(res, 403, 'Debug access denied');
  }

  next();
}

async function applyWalletCreditWithFee(userId, grossAmount) {
  const fee = applyWalletFundingFee(grossAmount);

  await query(
    `UPDATE wallets
     SET balance = balance + $2, updated_at = NOW()
     WHERE user_id = $1`,
    [userId, Number(fee.netAmount).toFixed(2)]
  );

  return fee;
}

async function processFundingSuccess({ reference, amount, flutterwaveData = {}, rawWebhook = null }) {
  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    const intentResult = await client.query(
      `SELECT * FROM payment_intents
       WHERE tx_ref = $1
       FOR UPDATE`,
      [reference]
    );

    const intent = intentResult.rows[0];
    if (!intent) {
      await client.query('ROLLBACK');
      return { ok: false, reason: 'Payment intent not found' };
    }

    if (String(intent.status).toLowerCase() === 'successful') {
      await client.query('COMMIT');
      return { ok: true, alreadyProcessed: true };
    }

    const expectedAmount = Number(intent.amount || 0);
    const paidAmount = Number(amount || 0);

    if (expectedAmount && paidAmount && expectedAmount !== paidAmount) {
      await client.query(
        `UPDATE payment_intents
         SET status = 'failed',
             meta = $2
         WHERE tx_ref = $1`,
        [
          reference,
          JSON.stringify({
            reason: 'amount_mismatch',
            expectedAmount,
            paidAmount,
            flutterwaveData,
            rawWebhook
          })
        ]
      );

      await client.query('COMMIT');
      return { ok: false, reason: 'Amount mismatch' };
    }

    const fee = applyWalletFundingFee(paidAmount || expectedAmount);
    const creditedAmount = Number(fee.netAmount || 0);

    await client.query(
      `UPDATE wallets
       SET balance = balance + $2,
           updated_at = NOW()
       WHERE user_id = $1`,
      [intent.user_id, creditedAmount]
    );

    await client.query(
      `UPDATE payment_intents
       SET status = 'successful',
           verified_at = NOW(),
           meta = $2
       WHERE tx_ref = $1`,
      [
        reference,
        JSON.stringify({
          flutterwaveData,
          rawWebhook,
          creditedAmount,
          fee
        })
      ]
    );

    await client.query(
      `UPDATE transactions
       SET status = 'success',
           meta = $2
       WHERE reference = $1
         AND user_id = $3`,
      [
        reference,
        JSON.stringify({
          flutterwaveData,
          rawWebhook,
          creditedAmount,
          fee
        }),
        intent.user_id
      ]
    );

    await addNotification(
      intent.user_id,
      'Wallet funded',
      `₦${Number(creditedAmount).toFixed(2)} has been added to your wallet`,
      {
        reference,
        creditedAmount
      },
      true
    );

    await client.query('COMMIT');
    return { ok: true, creditedAmount };
  } catch (err) {
    try {
      await client.query('ROLLBACK');
    } catch (_) {}
    throw err;
  } finally {
    client.release();
  }
}

async function flutterwaveCreateVirtualAccount({ amount, user, reference }) {
  const { first, last } = splitFullName(
    user.full_name || user.fullName || user.name || 'User'
  );

  const isStatic = String(FLW_ACCOUNT_TYPE || 'dynamic').toLowerCase() === 'static';

  const vaPayload = {
    email: user.email,
    amount: isStatic ? 0 : Number(amount),
    tx_ref: reference,
    firstname: first,
    lastname: last,
    phonenumber: user.phone ? String(user.phone) : undefined,
    narration: user.full_name || user.fullName || user.name || 'Wallet funding',
    expiry: isStatic ? undefined : Number(FLW_VA_EXPIRY || 3600),
    is_permanent: isStatic,
    meta: {
      user_id: user.id,
      purpose: 'wallet_funding',
      reference
    }
  };

  const cleanedPayload = Object.fromEntries(
    Object.entries(vaPayload).filter(([, value]) => value !== undefined && value !== null && value !== '')
  );

  console.log('FLW_VA_URL:', FLW_VA_URL);
  console.log('VA PAYLOAD:', cleanedPayload);

  const vaRes = await axios.post(FLW_VA_URL, cleanedPayload, {
    headers: flutterwaveHeaders(),
    timeout: 30000
  });

  return vaRes.data?.data || vaRes.data;
}

async function flutterwaveInitialize({ amount, user, description = 'Wallet funding' }) {
  if (!FLW_SECRET_KEY) {
    throw new Error('Flutterwave secret key not set');
  }
  if (!FLW_BASE_URL) {
    throw new Error('FLW_BASE_URL is missing');
  }

  const tx_ref = flutterwaveTxRef();

  const payload = {
    tx_ref,
    amount: Number(amount).toFixed(2),
    currency: 'NGN',
    redirect_url: process.env.FLW_REDIRECT_URL || '',
    customer: {
      email: user.email,
      phonenumber: user.phone,
      name: user.full_name
    },
    customizations: {
      title: 'PhoneStop',
      description
    },
    meta: {
      user_id: user.id,
      purpose: 'wallet_funding'
    }
  };

  const response = await axios.post(`${FLW_BASE_URL}/payments`, payload, {
    headers: flutterwaveHeaders(),
    timeout: 30000
  });

  return {
    tx_ref,
    payment_link: response.data?.data?.link || null,
    raw: response.data
  };
}

async function flutterwaveVerify(transactionId) {
  if (!FLW_SECRET_KEY) {
    throw new Error('Flutterwave secret key not set');
  }
  if (!FLW_BASE_URL) {
    throw new Error('FLW_BASE_URL is missing');
  }

  const response = await axios.get(`${FLW_BASE_URL}/transactions/${transactionId}/verify`, {
    headers: flutterwaveHeaders(),
    timeout: 30000
  });

  return response.data?.data || null;
}

async function ensurePricingRule(serviceType) {
  const normalized = normalizeServiceType(serviceType);

  const found = await query(
    `SELECT * FROM pricing_rules WHERE service_type = $1 LIMIT 1`,
    [normalized]
  );

  if (found.rows[0]) return found.rows[0];

  const created = await query(
    `INSERT INTO pricing_rules (id, service_type, markup_percent, is_active, created_at, updated_at)
     VALUES ($1, $2, $3, true, NOW(), NOW())
     RETURNING *`,
    [uid('prc_'), normalized, getDefaultMarkupPercent(normalized)]
  );

  return created.rows[0];
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
app.post('/api/auth/register', async (req, res) => {
  try {
    const {
      fullName,
      email,
      phone,
      password,
      confirmPassword,
      state,
      fundPin
    } = req.body || {};

    if (!fullName || !email || !phone || !password || !confirmPassword || !state || !fundPin) {
      return respondError(res, 400, 'All fields are required');
    }

    if (String(password).length < 6) {
      return respondError(res, 400, 'Password must be at least 6 characters');
    }

    if (String(password) !== String(confirmPassword)) {
      return respondError(res, 400, 'Passwords do not match');
    }

    const cleanFundPin = String(fundPin).trim();
    if (!/^\d{4}$/.test(cleanFundPin)) {
      return respondError(res, 400, 'Fund PIN must be exactly 4 digits');
    }

    const normalizedEmail = normalizeEmail(email);
    const normalizedPhone = normalizePhone(phone);

    const exists = await query(
      'SELECT id FROM users WHERE email = $1 OR phone = $2 LIMIT 1',
      [normalizedEmail, normalizedPhone]
    );

    if (exists.rows[0]) {
      return respondError(res, 409, 'User already exists');
    }

    const password_hash = await bcrypt.hash(String(password), 10);
    const fund_pin_hash = await bcrypt.hash(cleanFundPin, 10);
    const userId = uid('usr_');

    const inserted = await query(
      `INSERT INTO users
       (id, role, full_name, email, phone, password_hash, fund_pin_hash, fund_pin_set, state, avatar_url, kyc_status, profile_complete, online, created_at, updated_at)
       VALUES
       ($1, 'user', $2, $3, $4, $5, $6, true, $7, NULL, 'unverified', false, false, NOW(), NOW())
       RETURNING id, role, full_name, email, phone, state, avatar_url, kyc_status, profile_complete, online, created_at, fund_pin_set`,
      [
        userId,
        fullName.trim(),
        normalizedEmail,
        normalizedPhone,
        password_hash,
        fund_pin_hash,
        state.trim()
      ]
    );

    await ensureWallet(userId);
    await addNotification(userId, 'Welcome to PhoneStop', 'Registration successful', { type: 'auth' }, true);

    const token = signToken({ id: userId, role: 'user', fundPinSet: true });

    return respondOk(res, {
      token,
      user: inserted.rows[0]
    }, 'Registration successful');
  } catch (err) {
    console.error(err);
    return respondError(res, 500, 'Server error');
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { identifier, email, phone, password } = req.body || {};
    const raw = identifier || email || phone || '';
    const cleanEmail = normalizeEmail(raw);
    const cleanPhone = normalizePhone(raw);

    if (!raw || !password) {
      return respondError(res, 400, 'Identifier and password are required');
    }

    const result = await query(
      `SELECT id, role, full_name, email, phone, password_hash, state, avatar_url, kyc_status, profile_complete, online, created_at
       FROM users
       WHERE email = $1 OR phone = $2
       LIMIT 1`,
      [cleanEmail, cleanPhone]
    );

    const user = result.rows[0];
    if (!user) return respondError(res, 401, 'Invalid credentials');

    const ok = await bcrypt.compare(String(password), user.password_hash);
    if (!ok) return respondError(res, 401, 'Invalid credentials');

    await query(
      `UPDATE users
       SET online = true, last_login_at = NOW(), updated_at = NOW()
       WHERE id = $1`,
      [user.id]
    );

    const wallet = await ensureWallet(user.id);
    const token = signToken({ id: user.id, role: user.role });

    await addNotification(user.id, 'Login successful', 'You are now logged in', { type: 'auth' }, true);

    return respondOk(res, {
      token,
      user: { ...user, password_hash: undefined },
      wallet: {
        id: wallet.id,
        balance: Number(wallet.balance).toFixed(2),
        currency: wallet.currency
      }
    }, 'Login successful');
  } catch (err) {
    console.error(err);
    return respondError(res, 500, 'Server error');
  }
});

app.post('/api/auth/fund-pin', requireAuth, async (req, res) => {
  try {
    const { oldPin, newPin } = req.body || {};

    if (!oldPin || !newPin) {
      return respondError(res, 400, 'oldPin and newPin are required');
    }

    if (!/^\d{4}$/.test(String(newPin))) {
      return respondError(res, 400, 'New fund PIN must be exactly 4 digits');
    }

    const ok = await verifyFundPin(req.user.id, oldPin);
    if (!ok) {
      return respondError(res, 400, 'Invalid current fund PIN');
    }

    const newHash = await bcrypt.hash(String(newPin), 10);

    await query(
      `UPDATE users
       SET fund_pin_hash = $2,
           fund_pin_set = true,
           updated_at = NOW()
       WHERE id = $1`,
      [req.user.id, newHash]
    );

    return respondOk(res, {}, 'Fund PIN updated');
  } catch (err) {
    console.error(err);
    return respondError(res, 500, 'Unable to update fund PIN');
  }
});

app.get('/api/auth/me', requireAuth, async (req, res) => {
  const userId = req.user.id;
  const result = await query(
    `SELECT id, role, full_name, email, phone, state, avatar_url, kyc_status, profile_complete, online, created_at, updated_at, last_login_at
     FROM users
     WHERE id = $1
     LIMIT 1`,
    [userId]
  );

  const wallet = await ensureWallet(userId);

  return respondOk(res, {
    user: result.rows[0],
    wallet: {
      id: wallet.id,
      balance: Number(wallet.balance).toFixed(2),
      currency: wallet.currency
    }
  });
});

app.patch('/api/auth/profile', requireAuth, async (req, res) => {
  try {
    const { fullName, state } = req.body || {};

    const result = await query(
      `UPDATE users
       SET full_name = COALESCE($2, full_name),
           state = COALESCE($3, state),
           profile_complete = true,
           updated_at = NOW()
       WHERE id = $1
       RETURNING id, role, full_name, email, phone, state, avatar_url, kyc_status, profile_complete`,
      [req.user.id, fullName ? String(fullName).trim() : null, state ? String(state).trim() : null]
    );

    return respondOk(res, { user: result.rows[0] }, 'Profile updated');
  } catch (err) {
    console.error(err);
    return respondError(res, 500, 'Server error');
  }
});

app.post('/api/auth/avatar', requireAuth, avatarUpload.single('avatar'), async (req, res) => {
  try {
    if (!req.file) return respondError(res, 400, 'Avatar file is required');

    const avatar_url = `/uploads/avatars/${req.file.filename}`;

    const result = await query(
      `UPDATE users
       SET avatar_url = $2, updated_at = NOW()
       WHERE id = $1
       RETURNING id, full_name, email, phone, avatar_url`,
      [req.user.id, avatar_url]
    );

    await addNotification(req.user.id, 'Profile image updated', 'Your profile picture was updated', { avatar_url }, true);

    return respondOk(res, { user: result.rows[0], avatar_url }, 'Avatar updated');
  } catch (err) {
    console.error(err);
    return respondError(res, 500, 'Server error');
  }
});

app.post('/api/auth/password', requireAuth, async (req, res) => {
  try {
    const { currentPassword, newPassword, confirmPassword } = req.body || {};

    if (!currentPassword || !newPassword || !confirmPassword) {
      return respondError(res, 400, 'All password fields are required');
    }

    if (String(newPassword).length < 6) {
      return respondError(res, 400, 'New password must be at least 6 characters');
    }

    if (String(newPassword) !== String(confirmPassword)) {
      return respondError(res, 400, 'Passwords do not match');
    }

    const result = await query('SELECT password_hash FROM users WHERE id = $1 LIMIT 1', [req.user.id]);
    const user = result.rows[0];
    if (!user) return respondError(res, 404, 'User not found');

    const ok = await bcrypt.compare(String(currentPassword), user.password_hash);
    if (!ok) return respondError(res, 400, 'Current password is incorrect');

    const password_hash = await bcrypt.hash(String(newPassword), 10);

    await query(
      `UPDATE users
       SET password_hash = $2, updated_at = NOW()
       WHERE id = $1`,
      [req.user.id, password_hash]
    );

    await addNotification(req.user.id, 'Password changed', 'Your password was updated successfully', { type: 'security' }, true);

    return respondOk(res, {}, 'Password updated');
  } catch (err) {
    console.error(err);
    return respondError(res, 500, 'Server error');
  }
});

app.get('/api/wallet/balance', requireAuth, async (req, res) => {
  try {
    const wallet = await ensureWallet(req.user.id);
    return respondOk(res, {
      wallet: {
        id: wallet.id,
        balance: Number(wallet.balance).toFixed(2),
        currency: wallet.currency
      }
    });
  } catch (err) {
    console.error(err);
    return respondError(res, 500, 'Server error');
  }
});
app.post('/api/wallet/fund/initiate', requireAuth, async (req, res) => {
  try {
    const { amount } = req.body || {};
    const amt = toNumber(amount, 0);

    if (amt < 100) {
      return respondError(res, 400, 'Minimum funding amount is 100');
    }

    const userResult = await query(
      `SELECT id, full_name, email, phone
       FROM users
       WHERE id = $1
       LIMIT 1`,
      [req.user.id]
    );

    const user = userResult.rows[0];
    if (!user) {
      return respondError(res, 404, 'User not found');
    }

    const reference = flutterwaveTxRef('fund');

    const virtualAccount = await flutterwaveCreateVirtualAccount({
      amount: amt,
      user,
      reference
    });

    const accountNumber =
      virtualAccount?.account_number ||
      virtualAccount?.data?.account_number ||
      null;

    const bankName =
      virtualAccount?.bank_name ||
      virtualAccount?.data?.bank_name ||
      null;

    const accountName =
      virtualAccount?.account_name ||
      virtualAccount?.data?.account_name ||
      user.full_name ||
      user.email ||
      'Wallet funding';

    const expiryDate =
      virtualAccount?.expiry_date ||
      virtualAccount?.data?.expiry_date ||
      null;

    const intentMeta = {
      purpose: 'wallet_funding',
      accountType: FLW_ACCOUNT_TYPE === 'static' ? 'static' : 'dynamic',
      virtualAccount
    };

    await query(
      `INSERT INTO payment_intents
       (id, user_id, tx_ref, amount, currency, provider, status, meta, created_at)
       VALUES ($1, $2, $3, $4, 'NGN', 'flutterwave', 'initiated', $5, NOW())`,
      [
        uid('pit_'),
        user.id,
        reference,
        Number(amt).toFixed(2),
        JSON.stringify(intentMeta)
      ]
    );

    await addTransaction({
      userId: user.id,
      type: 'funding',
      category: 'wallet',
      amount: Number(amt).toFixed(2),
      status: 'pending',
      reference,
      description: 'Wallet funding initiated',
      meta: {
        provider: 'flutterwave',
        accountType: FLW_ACCOUNT_TYPE === 'static' ? 'static' : 'dynamic',
        virtualAccount
      }
    });

    return respondOk(res, {
      reference,
      amount: Number(amt).toFixed(2),
      account_number: accountNumber,
      bank_name: bankName,
      account_name: accountName,
      expiry_date: expiryDate,
      account_type: FLW_ACCOUNT_TYPE === 'static' ? 'static' : 'dynamic'
    }, 'Funding details generated');
  } catch (err) {
    console.error('FUND INITIATE ERROR:', err?.response?.data || err?.message || err);
    return respondError(res, 500, err?.message || 'Unable to initiate funding');
  }
});

/**
 * Optional: frontend can poll this route to know whether the transfer has been matched.
 */
app.get('/api/wallet/fund/status/:reference', requireAuth, async (req, res) => {
  try {
    const reference = String(req.params.reference || '').trim();
    if (!reference) {
      return respondError(res, 400, 'reference is required');
    }

    const intentResult = await query(
      `SELECT * FROM payment_intents
       WHERE tx_ref = $1 AND user_id = $2
       LIMIT 1`,
      [reference, req.user.id]
    );

    const transactionResult = await query(
      `SELECT * FROM transactions
       WHERE reference = $1 AND user_id = $2
       LIMIT 1`,
      [reference, req.user.id]
    );

    const wallet = await ensureWallet(req.user.id);

    const intent = intentResult.rows[0] || null;
    const transaction = transactionResult.rows[0] || null;

    return respondOk(
      res,
      {
        reference,
        intent,
        transaction,
        wallet: {
          id: wallet.id,
          balance: Number(wallet.balance).toFixed(2),
          currency: wallet.currency
        }
      },
      'Funding status loaded'
    );
  } catch (err) {
    console.error(err);
    return respondError(res, 500, 'Unable to load funding status');
  }
});

/**
 * Flutterwave webhook for virtual account payments.
 */

app.get('/api/wallet/fund/verify/:transactionId', requireAuth, async (req, res) => {
  try {
    const transactionId = String(req.params.transactionId || '').trim();
    if (!transactionId) {
      return respondError(res, 400, 'transactionId is required');
    }

    const data = await flutterwaveVerify(transactionId);
    if (!data) return respondError(res, 400, 'Unable to verify payment');

    const providerStatus = normalizeStatusValue(data.status || data.tx_status || '');
    const amount = toNumber(data.amount, 0);
    const txRef = String(data.tx_ref || data.reference || '').trim();

    if (!txRef) {
      return respondError(res, 400, 'Missing transaction reference');
    }

    const intentResult = await query(
      `SELECT * FROM payment_intents
       WHERE tx_ref = $1 AND user_id = $2
       LIMIT 1`,
      [txRef, req.user.id]
    );

    const intent = intentResult.rows[0];
    if (!intent) return respondError(res, 404, 'Payment intent not found');

    if (SUCCESS_STATUSES.has(providerStatus) || providerStatus === 'completed' || providerStatus === 'successful') {
      const result = await processFundingSuccess({
        reference: txRef,
        amount,
        flutterwaveData: data,
        rawWebhook: { source: 'manual_verify' }
      });

      if (!result.ok) {
        return respondError(res, 400, result.reason || 'Unable to complete funding');
      }

      return respondOk(res, { verified: true, amount, reference: txRef }, 'Payment verified and wallet funded');
    }

    return respondError(res, 400, `Payment status is ${providerStatus || 'unknown'}`);
  } catch (err) {
    console.error('FLW VERIFY ERROR:', err?.response?.data || err?.message || err);
    return respondError(res, 500, err?.message || 'Unable to verify payment');
  }
});

/* SERVICES LIST */

app.get('/api/services', requireAuth, async (req, res) => {
  try {
    return respondOk(res, {
      services: SERVICE_CATALOG
    }, 'Services loaded');
  } catch (err) {
    console.error(err);
    return respondError(res, 500, 'Server error');
  }
});

function toNetworkId(value) {
  const n = Number(value);
  return Number.isInteger(n) && n > 0 ? n : null;
}

function getNetworkServiceId(networkId) {
  const map = {
    1: 'mtn',
    2: 'glo',
    3: '9mobile',
    4: 'airtel'
  };
  return map[networkId] || null;
}

function extractArray(payload) {
  if (Array.isArray(payload)) return payload;
  if (Array.isArray(payload?.data)) return payload.data;
  if (Array.isArray(payload?.plans)) return payload.plans;
  return [];
}

/* BILLS / SERVICES */

app.get('/api/services/:serviceType/plans', requireAuth, async (req, res) => {
  try {
    const serviceType = normalizeServiceType(req.params.serviceType);

    const allowed = new Set([
      'airtime',
      'data',
      'cable_tv',
      'electricity',
      'betting',
      'recharge_pin',
      'data_pin',
      'exam_pin'
    ]);

    if (!allowed.has(serviceType)) {
      return respondError(res, 400, 'Unsupported service type');
    }

    if (serviceType === 'data' || serviceType === 'cable_tv') {
      const service_id = String(
        req.query.service_id ||
        req.query.network ||
        req.query.provider ||
        ''
      ).trim();

      if (!service_id) {
        return respondError(res, 400, 'service_id is required');
      }

      const product = serviceType === 'data' ? 'data' : 'cable';
      const raw = await iacafe.getVariations({ product, service_id });

      const list = extractArrayFromProviderResponse(raw).map((plan) => {
        const normalized = normalizeProviderPlan(plan);
        const pricing = buildRolePricing(serviceType, normalized.rawPrice, req.user.role, {
          service_id
        });

        return {
          ...normalized,
          price: normalized.rawPrice,
          pricing: {
            basePrice: pricing.basePrice,
            markupPercent: pricing.markupPercent,
            markupFee: pricing.markupFee,
            finalPriceBeforeAgentDiscount: pricing.finalPriceBeforeAgentDiscount,
            agentDiscountPercent: pricing.agentDiscountPercent,
            agentDiscountAmount: pricing.agentDiscountAmount,
            finalPrice: pricing.finalPrice
          }
        };
      });

      return respondOk(res, {
        serviceType: serviceType === 'data' ? 'data' : 'cable_tv',
        service_id,
        plans: list
      }, `${serviceType === 'data' ? 'Data' : 'Cable'} plans loaded`);
    }

    const providersRes = await iacafe.getProviders().catch((err) => {
      console.error('PROVIDERS ERROR:', err?.response?.data || err?.message);
      return null;
    });

    const providers = providersRes?.data || {};
    let options = [];

    switch (serviceType) {
      case 'airtime':
        options = (providers.airtime || []).map((x) => ({
          id: x,
          name: String(x).toUpperCase()
        }));
        break;

      case 'electricity':
        options = (providers.electricity || []).map((x) => ({
          id: x,
          name: String(x).replace(/-/g, ' ').toUpperCase()
        }));
        break;

      case 'betting':
        options = (providers.betting || []).map((x) => ({
          id: x,
          name: x
        }));
        break;

      case 'recharge_pin':
      case 'data_pin':
      case 'exam_pin':
        options = (providers.epins || []).map((x) => ({
          id: x,
          name: String(x).toUpperCase()
        }));
        break;

      default:
        options = [];
        break;
    }

    return respondOk(res, {
      serviceType,
      options
    }, 'Service options loaded');
  } catch (err) {
    console.error('LOAD PLANS ERROR:', err);
    console.error('MESSAGE:', err?.message);
    console.error('STACK:', err?.stack);
    console.error('RESPONSE DATA:', err?.response?.data);

    return respondError(
      res,
      err?.response?.status || 500,
      err?.response?.data?.error?.message || err?.message || 'Unable to load plans'
    );
  }
});

app.post('/api/services/data', requireAuth, async (req, res) => {
  return processServicePayment(req, res, 'data', 'Data');
});

app.post('/api/services/airtime', requireAuth, async (req, res) => {
  return processServicePayment(req, res, 'airtime', 'Airtime');
});
/* WEBHOOK */

app.get('/api/webhooks/flutterwave', (req, res) => {
  return res.status(200).send('Flutterwave webhook endpoint is live');
});

app.post('/api/webhooks/flutterwave', async (req, res) => {
  try {
    console.log('========== FLW WEBHOOK HIT ==========');
    console.log('Expected Hash:', process.env.FLW_WEBHOOK_HASH);
    console.log('Received Hash:', req.headers['verif-hash']);
    console.log('Received x-flw-secret-hash:', req.headers['x-flw-secret-hash']);
    console.log('Headers:', req.headers);
    console.log('Raw Body:', req.rawBody);
    console.log('Parsed Body:', req.body);

    if (!isValidFlutterwaveWebhook(req)) {
      console.log('INVALID FLW SIGNATURE');
      return res.status(401).json({ success: false, message: 'Invalid webhook signature' });
    }

    console.log('SIGNATURE VERIFIED');

    const body = req.body || {};
    const eventType = String(body.event || body.event_type || body.type || '').trim().toLowerCase();

    if (eventType && eventType !== 'charge.completed' && eventType !== 'transfer.completed' && eventType !== 'wallet.funding') {
      return res.status(200).json({ received: true });
    }

    const data = body.data || body;
    const amount = Number(data.amount || data.amount_charged || 0);
    const reference = String(
      data.tx_ref ||
      data.reference ||
      data.meta?.reference ||
      body.tx_ref ||
      body.reference ||
      ''
    ).trim();

    if (!reference) {
      console.log('NO REFERENCE IN WEBHOOK');
      return res.status(200).json({ received: true });
    }

    const intentResult = await query(
      `SELECT * FROM payment_intents
       WHERE tx_ref = $1
       LIMIT 1`,
      [reference]
    );

    const intent = intentResult.rows[0];
    if (!intent) {
      console.log('NO PAYMENT INTENT FOUND FOR', reference);
      return res.status(200).json({ received: true });
    }

    const providerStatus = normalizeStatusValue(data.status || data.tx_status || body.status || '');

    if (
      providerStatus &&
      !SUCCESS_STATUSES.has(providerStatus) &&
      providerStatus !== 'successful' &&
      providerStatus !== 'completed'
    ) {
      return res.status(200).json({ received: true });
    }

    const result = await processFundingSuccess({
      reference,
      amount,
      flutterwaveData: data,
      rawWebhook: body
    });

    if (!result.ok) {
      console.log('FUNDING PROCESSING FAILED:', result.reason);
      return res.status(200).json({ received: true });
    }

    clearPendingRequery(reference);

    return res.status(200).json({ received: true, processed: true });
  } catch (err) {
    console.error('WEBHOOK ERROR:', err?.response?.data || err?.message || err);
    return res.status(500).json({ success: false, message: 'Webhook error' });
  }
});

app.post('/api/webhooks/iacafe', async (req, res) => {
  try {
    const payload = req.body || {};

    const webhookSecret =
      process.env.IACAFE_WEBHOOK_SECRET ||
      process.env.ICAFE_WEBHOOK_SECRET ||
      process.env.IACAFE_SECRET;

    if (!verifyIacafeWebhookSignature(req, webhookSecret)) {
      return res.status(401).json({
        success: false,
        message: "Invalid webhook signature",
      });
    }

    const event =
      payload?.data && typeof payload.data === "object"
        ? payload.data
        : payload;

    const requestId =
      event.request_id ||
      event.reference ||
      event.tx_ref ||
      event.transaction_id ||
      event.id;

    if (!requestId) {
      return res.status(400).json({
        success: false,
        message: "Missing request reference",
      });
    }

    const providerResponse = {
      ...payload,
      ...event,
    };

    const result = await applyProviderOutcomeByReference({
      requestId,
      providerResponse,
      source: "webhook",
      webhookPayload: payload,
    });

    if (!result.found) {
      return res.status(404).json({
        success: false,
        message: "Transaction not found",
      });
    }

    if (result.state === "pending" || result.state === "unknown") {
      scheduleIacafeRequery(requestId, { delayMs: ICAFE_REQUERY_DELAY_MS, attempt: 1 });
    }

    if (result.state === "success" || result.state === "failed") {
      clearPendingRequery(requestId);
    }

    return res.json({
      success: true,
      message: "Webhook processed",
      status: result.state,
    });
  } catch (err) {
    console.error("ICAFE WEBHOOK ERROR:", err);
    return res.status(500).json({
      success: false,
      message: err?.message || "Webhook error",
    });
  }
});

/* BETTING */

app.get('/api/services/betting/options', requireAuth, async (req, res) => {
  try {
    const providersRes = await iacafe.getProviders().catch((err) => {
      console.error('BETTING PROVIDERS ERROR:', err?.response?.data || err?.message);
      return null;
    });

    const providers = providersRes?.data || {};
    const options = (providers.betting || []).map((x) => ({
      id: x,
      name: String(x).trim(),
    }));

    return respondOk(
      res,
      {
        serviceType: 'betting',
        options,
      },
      'Betting options loaded'
    );
  } catch (err) {
    console.error('LOAD BETTING OPTIONS ERROR:', err);
    return respondError(
      res,
      err?.response?.status || 500,
      err?.response?.data?.error?.message || err?.message || 'Unable to load betting options'
    );
  }
});

/**
 * Step 2: Verify betting customer before funding
 * If customer_not_found, stop here.
 */
app.post('/api/services/betting/verify', requireAuth, async (req, res) => {
  try {
    const body = req.body || {};

    const customer_id = String(
      body.customer_id ||
      body.customerId ||
      body.user_id ||
      body.account_id ||
      body.betting_id ||
      ''
    ).trim();

    const service_id = String(
      body.service_id ||
      body.serviceId ||
      body.provider ||
      body.platform ||
      ''
    ).trim();

    if (!customer_id || !service_id) {
      return respondError(res, 400, 'customer_id and service_id are required');
    }

    const result = await iacafe.verifyBettingCustomer({
      customer_id,
      service_id,
    });

    const customerName =
      result?.customer_name ||
      result?.data?.customer_name ||
      result?.name ||
      result?.data?.name ||
      result?.customer?.name ||
      result?.data?.customer?.name ||
      null;

    return respondOk(
      res,
      {
        verified: true,
        customer_name: customerName,
        customer_id,
        service_id,
        raw: result,
      },
      'Customer verified'
    );
  } catch (err) {
    const code = String(
      err?.code ||
      err?.response?.data?.error?.code ||
      err?.response?.data?.code ||
      ''
    ).trim().toLowerCase();

    const message =
      err?.response?.data?.error?.message ||
      err?.response?.data?.message ||
      err?.message ||
      'Unable to verify customer';

    return respondError(
      res,
      code === 'customer_not_found' ? 404 : 400,
      message
    );
  }
});

/**
 * Step 3: Fund betting account only after verification succeeds
 */
app.post('/api/services/betting', requireAuth, async (req, res) => {
  return processBettingPayment(req, res);
});

/* PROVIDER DEBUG */

app.get('/api/provider/vtpass/debug', requireAuth, async (req, res) => {
  try {
    return respondOk(res, {
      provider: SERVICE_PROVIDER,
      baseUrlSet: Boolean(VTPASS_BASE_URL),
      hasApiKey: Boolean(VTPASS_API_KEY),
      hasPublicKey: Boolean(VTPASS_PUBLIC_KEY),
      hasSecretKey: Boolean(VTPASS_SECRET_KEY),
      variationsPathSet: Boolean(VTPASS_VARIATIONS_PATH),
      payPathSet: Boolean(VTPASS_PAY_PATH),
      requeryPathSet: Boolean(VTPASS_REQUERY_PATH),
      services: PROVIDER_ENDPOINTS
    }, 'Provider config loaded');
  } catch (err) {
    console.error(err);
    return respondError(res, 500, 'Server error');
  }
});

app.post('/api/provider/vtpass/requery', requireAuth, async (req, res) => {
  try {
    const { requestId } = req.body || {};
    if (!requestId) return respondError(res, 400, 'requestId is required');

    const result = await requeryVtpassTransaction(requestId);
    return respondOk(res, { result }, 'Transaction status loaded');
  } catch (err) {
    console.error(err.response?.data || err.message || err);
    return respondError(res, 500, 'Unable to query transaction status');
  }
});

/* LOGOUT */

app.post('/api/auth/logout', requireAuth, async (req, res) => {
  try {
    await query(
      `UPDATE users
       SET online = false, updated_at = NOW()
       WHERE id = $1`,
      [req.user.id]
    );
    return respondOk(res, {}, 'Logged out');
  } catch (err) {
    console.error(err);
    return respondError(res, 500, 'Server error');
  }
});

/* ERRORS */

app.use((err, req, res, next) => {
  console.error(err);
  return respondError(res, 500, 'Internal server error');
});

/* START */

(async () => {
  try {
    await query('SELECT 1');
    await initDb();

    if (process.env.ADMIN_EMAIL && process.env.ADMIN_PASSWORD) {
      const adminEmail = normalizeEmail(process.env.ADMIN_EMAIL);
      const existing = await query('SELECT id FROM users WHERE email = $1 LIMIT 1', [adminEmail]);

      if (!existing.rows[0]) {
        const password_hash = await bcrypt.hash(String(process.env.ADMIN_PASSWORD), 10);
        const adminId = uid('usr_');

        await query(
          `INSERT INTO users
           (id, role, full_name, email, phone, password_hash, state, kyc_status, profile_complete, online, created_at, updated_at)
           VALUES ($1, 'admin', $2, $3, $4, $5, $6, 'verified', true, false, NOW(), NOW())`,
          [
            adminId,
            process.env.ADMIN_NAME || 'Super Admin',
            adminEmail,
            process.env.ADMIN_PHONE || '0000000000',
            password_hash,
            process.env.ADMIN_STATE || 'Admin'
          ]
        );

        await ensureWallet(adminId);
      }
    }

    app.listen(PORT, () => {
      console.log(`PhoneStop backend running on port ${PORT}`);
    });
  } catch (err) {
    console.error('Startup error:', err);
    process.exit(1);
  }
})();