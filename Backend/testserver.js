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
function pickBettingInputs(body = {}) {
  const customer_id = String(
    body.customer_id ||
    body.customerId ||
    body.user_id ||
    body.account_id ||
    body.betting_id ||
    ""
  ).trim();

  const service_id = String(
    body.service_id ||
    body.serviceId ||
    body.provider ||
    body.platform ||
    ""
  ).trim();

  return { customer_id, service_id };
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

function safeJsonParse(value, fallback = {}) {
  if (!value) return fallback;
  if (typeof value === 'object') return value;
  try {
    return JSON.parse(value);
  } catch (_) {
    return fallback;
  }
}

function normalizeBettingServiceId(value) {
  const s = String(value || '').trim().toLowerCase();

  const map = {
    '1xbet': '1xBet',
    'bangbet': 'BangBet',
    'bet9ja': 'Bet9ja',
    'betking': 'BetKing',
    'betland': 'BetLand',
    'betlion': 'BetLion',
    'betway': 'BetWay',
    'cloudbet': 'CloudBet',
    'livescorebet': 'LiveScoreBet',
    'merrybet': 'MerryBet',
    'naijabet': 'NaijaBet',
    'nairabet': 'NairaBet',
    'supabet': 'SupaBet'
  };

  return map[s] || String(value || '').trim();
}

function getBettingProviderState(payload) {
  const status = String(
    payload?.status ||
    payload?.data?.status ||
    payload?.result?.status ||
    payload?.error?.status ||
    ''
  ).trim().toLowerCase();

  if (status === 'completed-api' || status === 'completed' || status === 'success') {
    return 'success';
  }

  if (status === 'refunded-api' || status === 'failed' || status === 'refund' || status === 'declined') {
    return 'failed';
  }

  if (status === 'processing-api' || status === 'processing' || status === 'pending' || status === 'unknown') {
    return 'pending';
  }

  if (Boolean(payload?.success)) {
    return 'pending';
  }

  return 'pending';
}

function getBettingWebhookReference(payload) {
  return String(
    payload?.request_id ||
    payload?.requestId ||
    payload?.reference ||
    payload?.ref ||
    payload?.data?.request_id ||
    payload?.data?.requestId ||
    payload?.data?.reference ||
    ''
  ).trim();
}

function extractBettingProviderText(payload) {
  return (
    payload?.message ||
    payload?.data?.message ||
    payload?.error?.message ||
    payload?.response_description ||
    payload?.data?.response_description ||
    ''
  );
}

async function applyBettingOutcomeByReference(reference, payload = {}, extraMeta = {}) {
  const ref = String(reference || getBettingWebhookReference(payload)).trim();
  if (!ref) {
    throw new Error('Reference is required');
  }

  const state = getBettingProviderState(payload);
  const webhookStatus = String(
    payload?.status ||
    payload?.data?.status ||
    payload?.result?.status ||
    ''
  ).trim().toLowerCase();

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const txResult = await client.query(
      `SELECT *
       FROM transactions
       WHERE reference = $1
          OR (meta::jsonb ->> 'request_id') = $1
          OR (meta::jsonb ->> 'requestId') = $1
       FOR UPDATE`,
      [ref]
    );

    const txRow = txResult.rows[0];
    if (!txRow) {
      await client.query('ROLLBACK');
      return { found: false, applied: false, state: 'unknown', status: 'unknown', message: 'Transaction not found' };
    }

    const currentStatus = String(txRow.status || '').toLowerCase();
    if (currentStatus === 'success' || currentStatus === 'failed' || currentStatus === 'reversed') {
      await client.query('ROLLBACK');
      return {
        found: true,
        applied: false,
        state: currentStatus,
        status: currentStatus,
        message: `Transaction already ${currentStatus}`
      };
    }

    const meta = safeJsonParse(txRow.meta, {});
    const amount = Number(txRow.amount || 0);

    if (state === 'success') {
      await client.query(
        `UPDATE transactions
         SET status = 'success',
             description = COALESCE(description, $2),
             meta = $3
         WHERE id = $1`,
        [
          txRow.id,
          txRow.description || 'Betting funded successfully',
          JSON.stringify({
            ...meta,
            ...extraMeta,
            webhookPayload: payload,
            webhookStatus,
            settledAt: new Date().toISOString()
          })
        ]
      );

      await client.query('COMMIT');
      return {
        found: true,
        applied: true,
        state: 'success',
        status: 'success',
        transactionId: txRow.id
      };
    }

    if (state === 'failed') {
      await client.query(
        `UPDATE wallets
         SET balance = balance + $2,
             updated_at = NOW()
         WHERE user_id = $1`,
        [txRow.user_id, amount]
      );

      await client.query(
        `UPDATE transactions
         SET status = 'failed',
             description = COALESCE(description, $2),
             meta = $3
         WHERE id = $1`,
        [
          txRow.id,
          txRow.description || 'Betting refunded',
          JSON.stringify({
            ...meta,
            ...extraMeta,
            webhookPayload: payload,
            webhookStatus,
            refundedAmount: amount,
            settledAt: new Date().toISOString()
          })
        ]
      );

      await client.query('COMMIT');
      return {
        found: true,
        applied: true,
        state: 'failed',
        status: 'failed',
        transactionId: txRow.id
      };
    }

    await client.query(
      `UPDATE transactions
       SET status = 'pending',
           meta = $2
       WHERE id = $1`,
      [
        txRow.id,
        JSON.stringify({
          ...meta,
          ...extraMeta,
          webhookPayload: payload,
          webhookStatus,
          updatedAt: new Date().toISOString()
        })
      ]
    );

    await client.query('COMMIT');
    return {
      found: true,
      applied: true,
      state: 'pending',
      status: 'pending',
      transactionId: txRow.id
    };
  } catch (err) {
    try {
      await client.query('ROLLBACK');
    } catch (_) {}
    throw err;
  } finally {
    client.release();
  }
}

async function requeryBettingTransactionByRequestId(requestId, { source = 'requery' } = {}) {
  if (!requestId) return { found: false, state: 'unknown', status: 'unknown' };

  const providerResponse = await iacafe.requery(requestId);
  return applyBettingOutcomeByReference(requestId, providerResponse, { source });
}

function scheduleIacafeBettingRequery(
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
      const result = await requeryBettingTransactionByRequestId(requestId, {
        source: `timer_${attempt}`,
      });

      if (
        (result?.state === 'pending' || result?.state === 'unknown') &&
        attempt < maxAttempts
      ) {
        scheduleIacafeBettingRequery(requestId, {
          delayMs: delayMs * 2,
          attempt: attempt + 1,
          maxAttempts,
        });
      }
    } catch (err) {
      console.error('Scheduled betting requery failed:', requestId, err?.message);

      if (attempt < maxAttempts) {
        scheduleIacafeBettingRequery(requestId, {
          delayMs: delayMs * 2,
          attempt: attempt + 1,
          maxAttempts,
        });
      }
    }
  }, delayMs);

  pendingRequeryTimers.set(requestId, timer);
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