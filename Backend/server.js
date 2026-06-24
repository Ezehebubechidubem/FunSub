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
const { createIacafeGateway } = require("./services/vtuGateway");
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
const FLW_ACCOUNT_TYPE = String(process.env.FLW_ACCOUNT_TYPE || 'dynamic').toLowerCase(); // dynamic | static
const FLW_VA_EXPIRY = Number(process.env.FLW_VA_EXPIRY || 3600);

// These are configurable in case Flutterwave changes the route you are using.
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
const FLW_WALLET_FEE_PERCENT = envNumber(process.env.FLW_WALLET_FEE_PERCENT, 1.7);

const SERVICE_MARKUP_DEFAULTS = {
  airtime: envNumber(process.env.AIRTIME_MARKUP_PERCENT, 1),
  data: envNumber(process.env.DATA_MARKUP_PERCENT, 1.5),
  cable_tv: envNumber(process.env.CABLE_TV_MARKUP_PERCENT, DEFAULT_MARKUP_PERCENT),
  electricity: envNumber(process.env.ELECTRICITY_MARKUP_PERCENT, DEFAULT_MARKUP_PERCENT),
  betting: envNumber(process.env.BETTING_MARKUP_PERCENT, DEFAULT_MARKUP_PERCENT),
  recharge_pin: envNumber(process.env.RECHARGE_PIN_MARKUP_PERCENT, DEFAULT_MARKUP_PERCENT),
  data_pin: envNumber(process.env.DATA_PIN_MARKUP_PERCENT, DEFAULT_MARKUP_PERCENT),
  exam_pin: envNumber(process.env.EXAM_PIN_MARKUP_PERCENT, DEFAULT_MARKUP_PERCENT)
};


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

// Changed for Render: always use SSL for Postgres
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
function normalizeStatus(value) {
  return String(value || '').trim().toLowerCase();
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
  const parts = [];

  const push = (v) => {
    const text = normalizeStatus(v);
    if (text) parts.push(text);
  };

  push(response?.status);
  push(response?.message);
  push(response?.response_description);
  push(response?.responseCode);
  push(response?.response_code);
  push(response?.code);
  push(response?.statusCode);

  push(response?.data?.status);
  push(response?.data?.message);
  push(response?.data?.response_description);
  push(response?.data?.response_code);
  push(response?.data?.responseCode);

  push(response?.transaction?.status);
  push(response?.transaction?.message);
  push(response?.transaction?.response_description);
  push(response?.transaction?.order_status);

  push(response?.content?.transactions?.status);
  push(response?.content?.transactions?.message);
  push(response?.content?.transactions?.response_description);
  push(response?.content?.transactions?.order_status);

  push(response?.data?.content?.transactions?.status);
  push(response?.data?.content?.transactions?.message);
  push(response?.data?.content?.transactions?.response_description);
  push(response?.data?.content?.transactions?.order_status);

  push(response?.data?.transactions?.status);
  push(response?.data?.transactions?.message);
  push(response?.data?.transactions?.response_description);
  push(response?.data?.transactions?.order_status);

  return parts.join(' | ');
}
async function cleanupExpiredFundingIntents() {
  try {
    const expiredResult = await pool.query(
      `
      SELECT tx_ref, user_id, amount
      FROM payment_intents
      WHERE status IN ('initiated', 'pending')
        AND COALESCE(meta->>'purpose', '') = 'wallet_funding'
        AND created_at < NOW() - INTERVAL '1 hour'
      ORDER BY created_at ASC
      `
    );

    if (!expiredResult.rows.length) return;

    for (const intent of expiredResult.rows) {
      const client = await pool.connect();

      try {
        await client.query('BEGIN');

        const lockedIntent = await client.query(
          `
          SELECT tx_ref, user_id, amount, status, meta
          FROM payment_intents
          WHERE tx_ref = $1
          FOR UPDATE
          `,
          [intent.tx_ref]
        );

        if (!lockedIntent.rows.length) {
          await client.query('ROLLBACK');
          continue;
        }

        const currentIntent = lockedIntent.rows[0];
        const currentStatus = String(currentIntent.status || '').toLowerCase();
        const purpose = String(currentIntent.meta?.purpose || '').toLowerCase();

        if (!['initiated', 'pending'].includes(currentStatus)) {
          await client.query('ROLLBACK');
          continue;
        }

        if (purpose !== 'wallet_funding') {
          await client.query('ROLLBACK');
          continue;
        }

        const expiryMeta = {
          expiredAt: new Date().toISOString(),
          reason: 'funding_not_completed_within_1_hour'
        };

        await client.query(
          `
          UPDATE payment_intents
          SET status = 'expired',
              verified_at = NOW(),
              meta = COALESCE(meta, '{}'::jsonb) || $2::jsonb
          WHERE tx_ref = $1
          `,
          [
            currentIntent.tx_ref,
            JSON.stringify(expiryMeta)
          ]
        );

        await client.query(
          `
          UPDATE transactions
          SET status = 'expired',
              updated_at = NOW(),
              meta = $2
          WHERE reference = $1
            AND user_id = $3
            AND category = 'wallet'
            AND status IN ('initiated', 'pending')
          `,
          [
            currentIntent.tx_ref,
            JSON.stringify(expiryMeta),
            currentIntent.user_id
          ]
        );

        await client.query('COMMIT');

        console.log(`Expired funding intent ${currentIntent.tx_ref}`);
      } catch (err) {
        try {
          await client.query('ROLLBACK');
        } catch (_) {}
        console.error('FUNDING EXPIRE ERROR:', err?.message || err);
      } finally {
        client.release();
      }
    }
  } catch (err) {
    console.error('FUNDING CLEANUP ERROR:', err?.message || err);
  }
}

cleanupExpiredFundingIntents().catch((err) => {
  console.error('INITIAL FUNDING EXPIRE ERROR:', err?.message || err);
});

setInterval(() => {
  cleanupExpiredFundingIntents().catch((err) => {
    console.error('INTERVAL FUNDING EXPIRE ERROR:', err?.message || err);
  });
}, 60_000);
function providerResponseState(response) {
  if (!response) return 'failed';

  if (response.success === true) return 'success';

  const code = String(
    response.code ??
    response.statusCode ??
    response.response_code ??
    response.responseCode ??
    response.data?.code ??
    response.data?.statusCode ??
    response.data?.response_code ??
    response.data?.responseCode ??
    ''
  ).trim();

  if (['00', '0', '200'].includes(code)) return 'success';

  const text = extractProviderText(response);

  if (!text) return 'failed';

  if (
    text.includes('failed') ||
    text.includes('failure') ||
    text.includes('declined') ||
    text.includes('rejected') ||
    text.includes('cancelled') ||
    text.includes('canceled') ||
    text.includes('error') ||
    text.includes('invalid')
  ) {
    return 'failed';
  }

  if (
    text.includes('order completed') ||
    text.includes('transaction successful') ||
    text.includes('purchase successful') ||
    text.includes('success') ||
    text.includes('successful') ||
    text.includes('completed') ||
    text.includes('complete') ||
    text.includes('paid') ||
    text.includes('ok') ||
    text.includes('completed-api') ||
    text.includes('submitted successfully') ||
    text.includes('processed successfully')
  ) {
    return 'success';
  }

  if (
    text.includes('pending') ||
    text.includes('processing') ||
    text.includes('queued') ||
    text.includes('in progress') ||
    text.includes('awaiting') ||
    text.includes('submitted')
  ) {
    return 'pending';
  }

  return 'failed';
}

function isSuccessStatus(value) {
  return SUCCESS_STATUSES.has(normalizeStatus(value));
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
    response?.data?.response_description
  ]
    .map((v) => normalizeStatus(v))
    .filter(Boolean);

  if (
    candidates.some(
      (v) =>
        SUCCESS_STATUSES.has(v) ||
        v === 'completed-api' ||
        v === 'completed api' ||
        v === 'complete' ||
        v === 'completed' ||
        v === 'transaction completed' ||
        v === 'order completed' ||
        v === 'payment completed' ||
        v === 'transaction successful' ||
        v === 'purchase successful' ||
        v === 'processed successfully' ||
        v === 'submitted successfully'
    )
  ) {
    return true;
  }

  const responseCode = String(response?.response_code ?? response?.data?.response_code ?? '').trim();
  if (['00', '0', '200'].includes(responseCode)) return true;

  return false;
}
async function buyServiceThroughGateway({
  serviceType,
  body,
  selectedPlan,
  requestId
}) {
  const normalizedServiceType = normalizeServiceType(serviceType);

  switch (normalizedServiceType) {
    case 'airtime':
      return iacafe.buyAirtime({
        request_id: requestId,
        phone: body.phone,
        service_id: body.service_id || body.serviceId,
        amount: body.amount
      });

    case 'data':
      return iacafe.buyData({
        request_id: requestId,
        phone: body.phone,
        plan: selectedPlan,
        service_id: body.service_id || body.serviceId
      });

    case 'cable_tv':
      return iacafe.buyCable({
        request_id: requestId,
        customer_id: body.smartcard_number || body.customer_id || body.accountNumber || body.billersCode,
        service_id: body.service_id || body.serviceId,
        plan: selectedPlan
      });

    case 'electricity':
      return iacafe.buyElectricity({
        request_id: requestId,
        customer_id: body.meter_number || body.meterNumber || body.customer_id || body.billersCode,
        service_id: body.service_id || body.serviceId,
        meter_number: body.meter_number || body.meterNumber,
        account_number: body.accountNumber,
        amount: body.amount
      });

    case 'betting':
      return iacafe.buyBetting({
        request_id: requestId,
        customer_id: body.customer_id || body.accountNumber || body.phone,
        service_id: body.service_id || body.serviceId,
        amount: body.amount
      });

    default:
      throw new Error(`${normalizedServiceType} is not supported yet`);
  }
}
async function verifyFlutterwaveByReference(reference) {
  const url = 'https://api.flutterwave.com/v3/transactions/verify_by_reference';

  const response = await axios.get(url, {
    params: { tx_ref: reference },
    headers: {
      Authorization: `Bearer ${process.env.FLW_SECRET_KEY}`,
      'Content-Type': 'application/json'
    },
    timeout: 30000
  });

  return response.data;
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

function requireAuth(req, res, next) {
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

    console.log('DECODED USER:', decoded);

    req.user = decoded;

    console.log('AUTH SUCCESS');
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
    fund_pin_hash TEXT,
    fund_pin_set BOOLEAN NOT NULL DEFAULT FALSE,
    state TEXT,
    avatar_url TEXT,
    kyc_status TEXT NOT NULL DEFAULT 'unverified',
    profile_complete BOOLEAN NOT NULL DEFAULT FALSE,
    online BOOLEAN NOT NULL DEFAULT FALSE,
    last_login_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
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
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
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
      verified_at TIMESTAMPTZ
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
    const res = await fetch(`${API_ROOT}/api/wallet/fund/status/${encodeURIComponent(reference)}`, {
      headers: { Authorization: `Bearer ${localStorage.getItem('funsub_token') || ''}` }
    });

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

async function getMarkupPercent(serviceType) {
  const normalized = normalizeServiceType(serviceType);

  const envMap = {
    airtime: process.env.AIRTIME_MARKUP_PERCENT,
    data: process.env.DATA_MARKUP_PERCENT,
    cable_tv: process.env.CABLE_TV_MARKUP_PERCENT,
    electricity: process.env.ELECTRICITY_MARKUP_PERCENT,
    betting: process.env.BETTING_MARKUP_PERCENT,
    recharge_pin: process.env.RECHARGE_PIN_MARKUP_PERCENT,
    data_pin: process.env.DATA_PIN_MARKUP_PERCENT,
    exam_pin: process.env.EXAM_PIN_MARKUP_PERCENT
  };

  const rawEnv = envMap[normalized];
  const envValue = Number(rawEnv);

  if (rawEnv !== undefined && rawEnv !== null && String(rawEnv).trim() !== '' && Number.isFinite(envValue)) {
    return envValue;
  }

  const rule = await ensurePricingRule(normalized);
  return Number(rule.markup_percent ?? getDefaultMarkupPercent(normalized));
}

async function applyMarkup(serviceType, baseAmount) {
  const markupPercent = await getMarkupPercent(serviceType);
  const base = Number(baseAmount);
  const fee = (base * markupPercent) / 100;
  const finalPrice = base + fee;

  return {
    serviceType,
    basePrice: Number(base.toFixed(2)),
    markupPercent: Number(markupPercent.toFixed(2)),
    markupFee: Number(fee.toFixed(2)),
    finalPrice: Number(finalPrice.toFixed(2))
  };
}

function providerAuthPayload() {
  return {};
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

  async function reverseAndRefund(txRow, userId, purchaseAmount, reason, extraMeta = {}) {
    if (!txRow?.id) return;

    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      const txCheck = await client.query(
        `SELECT status
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
        [
          txRow.id,
          reason,
          JSON.stringify(extraMeta)
        ]
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

  function withTimeout(promise, timeoutMs, timeoutMessage = 'Provider timeout') {
    let timeoutId;

    const timeoutPromise = new Promise((_, reject) => {
      timeoutId = setTimeout(() => {
        reject(new Error(timeoutMessage));
      }, timeoutMs);
    });

    return Promise.race([
      promise.finally(() => clearTimeout(timeoutId)),
      timeoutPromise
    ]);
  }

  try {
    const body = req.body || {};
    const userId = req.user?.id || req.user?.userId;

    if (!userId) {
      return respondError(res, 401, 'Unauthorized');
    }

    const fundPin = String(body.fundPin || body.fund_pin || '').trim();
    const pinOk = await verifyFundPin(userId, fundPin);

    if (!pinOk) {
      return respondError(res, 401, 'Invalid fund PIN');
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

    if (normalizedServiceType === 'airtime') {
      const amount = toNumber(body.amount, 0);

      if (amount <= 0 || !destination) {
        return respondError(res, 400, 'amount and phone are required');
      }

      pricing = await applyMarkup('airtime', amount);
    } else {
      const variationCode = String(
        body.variation_code ||
        body.planId ||
        body.plan_id ||
        body.planCode ||
        body.code ||
        ''
      ).trim();

      const planAmount = toNumber(body.plan_amount || body.amount, 0);

      if (!variationCode) {
        return respondError(res, 400, 'variation_code is required');
      }

      if (planAmount <= 0) {
        return respondError(res, 400, 'plan_amount is required');
      }

      selectedPlan = {
        id: variationCode,
        name: body.plan_name || `${serviceName} Plan`,
        rawPrice: planAmount,
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

      pricing = await applyMarkup(normalizedServiceType, selectedPlan.rawPrice);
      description = `${serviceName} - ${selectedPlan.name}`;
    }

    if (!pricing) {
      return respondError(res, 400, 'Unable to prepare purchase');
    }

    const purchaseAmount = Number(pricing.finalPrice);

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
          uid('ref_'),
          description,
          JSON.stringify({
            serviceType: normalizedServiceType,
            serviceName,
            selectedPlan,
            pricing,
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

    let providerResponse;

    try {
      providerResponse = await withTimeout(
        buyServiceThroughGateway({
          serviceType: normalizedServiceType,
          body,
          selectedPlan,
          requestId: txRow.reference
        }),
        PROVIDER_TIMEOUT_MS,
        'Provider timeout'
      );
    } catch (err) {
      console.error('PROVIDER CALL TIMEOUT/ERROR:', err?.message);

      await reverseAndRefund(
        txRow,
        userId,
        purchaseAmount,
        `${description} reversed`,
        {
          serviceType: normalizedServiceType,
          serviceName,
          selectedPlan,
          pricing,
          reverseReason: err?.message || 'Provider timeout'
        }
      );

      return respondError(
        res,
        504,
        err?.message || 'Provider timeout. Wallet reversed.'
      );
    }

    console.log('PROVIDER RESPONSE:', JSON.stringify(providerResponse, null, 2));

    const providerState = providerRequestLooksSuccessful(providerResponse);
    const providerText = extractProviderText(providerResponse);

    if (providerState === 'pending') {
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
            serviceType: normalizedServiceType,
            serviceName,
            selectedPlan,
            pricing,
            providerResponse,
            expiresAt: new Date(Date.now() + PROVIDER_TIMEOUT_MS).toISOString()
          })
        ]
      );

      return res.status(202).json({
        success: true,
        message: providerText || 'Purchase pending',
        transaction: {
          ...txRow,
          status: 'pending'
        },
        pricing,
        providerResponse
      });
    }

    if (!providerState) {
      await pool.query(
        `UPDATE wallets
         SET balance = balance + $2,
             updated_at = NOW()
         WHERE user_id = $1`,
        [userId, purchaseAmount]
      );

      await pool.query(
        `UPDATE transactions
         SET status = 'failed',
             description = $2,
             meta = $3
         WHERE id = $1`,
        [
          txRow.id,
          `${description} failed`,
          JSON.stringify({
            serviceType: normalizedServiceType,
            serviceName,
            selectedPlan,
            pricing,
            providerResponse
          })
        ]
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
          serviceType: normalizedServiceType,
          serviceName,
          selectedPlan,
          pricing,
          providerResponse
        })
      ]
    );

    await addNotification(
      userId,
      `${serviceName} purchased`,
      `${description} was successful`,
      {
        transactionId: txRow.id,
        serviceType: normalizedServiceType,
        pricing,
        providerResponse
      },
      true
    );

    return respondOk(
      res,
      {
        transaction: {
          ...txRow,
          status: 'success'
        },
        pricing,
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

const SERVICE_CATALOG = [
  { key: 'recharge_pin', label: 'Recharge Pin', route: '/api/services/recharge-pin' },
  { key: 'data_pin', label: 'Data Pin', route: '/api/services/data-pin' },
  { key: 'exam_pin', label: 'Exam PIN', route: '/api/services/exam-pin' },
  { key: 'electricity', label: 'Electricity', route: '/api/services/electricity' },
  { key: 'cable_tv', label: 'Cable TV', route: '/api/services/cable' },
  { key: 'airtime', label: 'Airtime', route: '/api/services/airtime' },
  { key: 'data', label: 'Data', route: '/api/services/data' },
  { key: 'betting', label: 'Betting', route: '/api/services/betting' }
];

app.get('/', (req, res) => {
  res.json({ success: true, message: 'PhoneStop backend is running' });
});

app.get('/health', async (req, res) => {
  try {
    await query('SELECT 1');
    return respondOk(res, { db: 'ok' }, 'Healthy');
  } catch (e) {
    return respondError(res, 500, 'Database error');
  }
});

app.post('/api/temp/topup-wallet', requireAuth, async (req, res) => {
  const client = await pool.connect();

  try {
    const { amount } = req.body || {};
    const amt = Number(amount || 0);

    if (!Number.isFinite(amt) || amt <= 0) {
      return respondError(res, 400, 'amount must be greater than 0');
    }

    await client.query('BEGIN');

    await client.query(
      `INSERT INTO wallets (id, user_id, balance, currency)
       VALUES ($1, $2, 0, 'NGN')
       ON CONFLICT (user_id) DO NOTHING`,
      [uid('wal_'), req.user.id]
    );

    await client.query(
      `UPDATE wallets
       SET balance = balance + $2,
           updated_at = NOW()
       WHERE user_id = $1`,
      [req.user.id, amt]
    );

    await client.query(
      `INSERT INTO transactions
       (id, user_id, type, category, amount, currency, status, reference, description, meta, created_at)
       VALUES ($1, $2, $3, $4, $5, 'NGN', 'success', $6, $7, $8, NOW())`,
      [
        uid('tx_'),
        req.user.id,
        'funding',
        'wallet',
        amt,
        `temp-topup-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`,
        'Temporary wallet top up',
        JSON.stringify({
          source: 'temporary_topup',
          amount: amt
        })
      ]
    );

    await client.query('COMMIT');

    return respondOk(res, {
      amount: amt,
      message: 'Wallet topped up successfully'
    }, 'Wallet topped up');
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    console.error('TEMP TOPUP ERROR:', err?.message || err);
    return respondError(res, 500, 'Unable to top up wallet');
  } finally {
    client.release();
  }
});
/* AUTH */
app.post('/api/auth/register', async (req, res) => {
  try {
    const { fullName, email, phone, password, confirmPassword, state, fundPin } = req.body || {};

    if (!fullName || !email || !phone || !password || !confirmPassword || !state || !fundPin) {
      return respondError(res, 400, 'All fields are required');
    }

    if (String(password).length < 6) {
      return respondError(res, 400, 'Password must be at least 6 characters');
    }

    if (String(password) !== String(confirmPassword)) {
      return respondError(res, 400, 'Passwords do not match');
    }

    if (!/^\d{4}$/.test(String(fundPin).trim())) {
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
    const fund_pin_hash = await bcrypt.hash(String(fundPin), 10);
    const userId = uid('usr_');

    const inserted = await query(
      `INSERT INTO users
       (id, role, full_name, email, phone, password_hash, fund_pin_hash, fund_pin_set, state, avatar_url, kyc_status, profile_complete, online, created_at, updated_at)
       VALUES
       ($1, 'user', $2, $3, $4, $5, $6, true, $7, NULL, 'unverified', false, false, NOW(), NOW())
       RETURNING id, role, full_name, email, phone, state, avatar_url, kyc_status, profile_complete, online, created_at, fund_pin_set`,
      [userId, fullName.trim(), normalizedEmail, normalizedPhone, password_hash, fund_pin_hash, state.trim()]
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
/* WALLET */

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
 * Flutterwave recommends verifying the webhook with the secret hash, using the
 * flutterwave-signature header and HMAC-SHA256 of the raw body.
 */

app.get('/api/wallet/fund/verify/:transactionId', requireAuth, async (req, res) => {
  try {
    const transactionId = String(req.params.transactionId || '').trim();
    if (!transactionId) {
      return respondError(res, 400, 'transactionId is required');
    }

    const data = await flutterwaveVerify(transactionId);
    if (!data) return respondError(res, 400, 'Unable to verify payment');

    const providerStatus = normalizeStatus(data.status || data.tx_status || '');
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

    const existingTransactionResult = await query(
      `SELECT * FROM transactions
       WHERE reference = $1 AND user_id = $2
       LIMIT 1`,
      [txRef, req.user.id]
    );

    const existingTransaction = existingTransactionResult.rows[0] || null;

    if (isSuccessStatus(intent.status) || (existingTransaction && isSuccessStatus(existingTransaction.status))) {
      const wallet = await ensureWallet(req.user.id);

      return respondOk(res, {
        alreadyProcessed: true,
        wallet: {
          balance: Number(wallet.balance).toFixed(2),
          currency: wallet.currency
        }
      }, 'Payment already processed');
    }

    if (!isSuccessStatus(providerStatus)) {
      await query(
        `UPDATE payment_intents
         SET status = $1, verified_at = NOW()
         WHERE tx_ref = $2 AND user_id = $3`,
        [providerStatus || 'failed', txRef, req.user.id]
      );

      if (existingTransaction) {
        await query(
          `UPDATE transactions
           SET status = $1, updated_at = NOW()
           WHERE reference = $2 AND user_id = $3`,
          [providerStatus || 'failed', txRef, req.user.id]
        );
      }

      return respondError(res, 400, 'Payment not successful');
    }

    const fee = applyWalletFundingFee(amount);
    const creditAmount = Number(fee.netAmount);

    if (!Number.isFinite(creditAmount) || creditAmount <= 0) {
      return respondError(res, 400, 'Invalid credited amount');
    }

    await query(
      `UPDATE wallets
       SET balance = balance + $2, updated_at = NOW()
       WHERE user_id = $1`,
      [req.user.id, creditAmount]
    );

    await query(
      `UPDATE payment_intents
       SET status = 'successful', verified_at = NOW()
       WHERE tx_ref = $1 AND user_id = $2`,
      [txRef, req.user.id]
    );

    let tx = existingTransaction;

    if (tx) {
      await query(
        `UPDATE transactions
         SET status = 'success',
             amount = $1,
             updated_at = NOW()
         WHERE reference = $2 AND user_id = $3`,
        [creditAmount, txRef, req.user.id]
      );

      tx = {
        ...tx,
        status: 'success',
        amount: creditAmount
      };
    } else {
      tx = await addTransaction({
        userId: req.user.id,
        type: 'funding',
        category: 'wallet',
        amount: creditAmount,
        status: 'success',
        reference: txRef,
        description: 'Wallet funded successfully',
        meta: {
          transaction_id: transactionId,
          provider: 'flutterwave',
          grossAmount: fee.grossAmount,
          feePercent: fee.feePercent,
          feeAmount: fee.feeAmount,
          creditedAmount: fee.netAmount,
          providerStatus
        }
      });
    }

    await addNotification(
      req.user.id,
      'Wallet funded',
      `₦${creditAmount.toFixed(2)} has been added to your wallet`,
      { tx_id: tx.id, txRef, fee },
      true
    );

    const wallet = await ensureWallet(req.user.id);

    return respondOk(res, {
      wallet: {
        balance: Number(wallet.balance).toFixed(2),
        currency: wallet.currency
      },
      fee,
      transaction: tx
    }, 'Wallet funded successfully');
  } catch (err) {
    console.error(err.response?.data || err.message || err);
    return respondError(res, 500, 'Unable to verify payment');
  }
});

/* TRANSACTIONS */

app.get('/api/wallet/transactions', requireAuth, async (req, res) => {
  try {
    const limit = Math.min(Number(req.query.limit || 20), 100);

    const result = await query(
      `SELECT * FROM transactions
       WHERE user_id = $1
       ORDER BY created_at DESC
       LIMIT $2`,
      [req.user.id, limit]
    );

    return respondOk(res, { transactions: result.rows });
  } catch (err) {
    console.error(err);
    return respondError(res, 500, 'Server error');
  }
});

/* NOTIFICATIONS */

app.get('/api/notifications', requireAuth, async (req, res) => {
  try {
    const result = await query(
      `SELECT * FROM notifications
       WHERE user_id = $1
       ORDER BY created_at DESC
       LIMIT 100`,
      [req.user.id]
    );

    return respondOk(res, { notifications: result.rows });
  } catch (err) {
    console.error(err);
    return respondError(res, 500, 'Server error');
  }
});

app.get('/api/notifications/unread-count', requireAuth, async (req, res) => {
  try {
    const result = await query(
      `SELECT COUNT(*)::int AS count
       FROM notifications
       WHERE user_id = $1 AND is_read = false`,
      [req.user.id]
    );

    return respondOk(res, { count: result.rows[0]?.count || 0 });
  } catch (err) {
    console.error(err);
    return respondError(res, 500, 'Server error');
  }
});

app.patch('/api/notifications/:id/read', requireAuth, async (req, res) => {
  try {
    const result = await query(
      `UPDATE notifications
       SET is_read = true
       WHERE id = $1 AND user_id = $2
       RETURNING *`,
      [req.params.id, req.user.id]
    );

    if (!result.rows[0]) return respondError(res, 404, 'Notification not found');

    return respondOk(res, { notification: result.rows[0] }, 'Notification marked read');
  } catch (err) {
    console.error(err);
    return respondError(res, 500, 'Server error');
  }
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
      return respondError(res, 400, 'Invalid service type');
    }

    const includeUnavailable =
      String(req.query.include_unavailable || '').toLowerCase() === 'true';

    // DATA PLANS
    if (serviceType === 'data') {
      const networkId = toNetworkId(req.query.network_id || req.query.networkId);
      const provider = req.query.provider || undefined;

      const explicitServiceId = String(
        req.query.service_id ||
        req.query.serviceId ||
        ''
      ).trim().toLowerCase();

      const mappedServiceId = networkId ? getNetworkServiceId(networkId) : null;
      const service_id = explicitServiceId || mappedServiceId;

      if (!service_id) {
        return respondError(
          res,
          400,
          'service_id or network_id is required for data plans'
        );
      }

      const regularRes = await iacafe.getVariations({
        product: 'data',
        service_id
      }).catch((err) => {
        console.error('REGULAR DATA PLANS ERROR:', err?.response?.data || err?.message);
        return null;
      });

      const budgetRes = await iacafe.getBudgetPlans({
        network_id: networkId || undefined,
        provider
      }).catch((err) => {
        console.error('BUDGET DATA PLANS ERROR:', err?.response?.data || err?.message);
        return null;
      });

      const regularPlansRaw = extractArray(regularRes);
      const budgetPlansRaw = extractArray(budgetRes);

      const regularPlans = regularPlansRaw.map((plan) => ({
        id: plan.variation_id ?? plan.id ?? plan.code,
        name: plan.name ?? plan.variation_name ?? plan.data_plan ?? 'Data Plan',
        rawPrice: Number(plan.reseller_price ?? plan.price ?? plan.amount ?? 0),
        availability: plan.availability ?? 'Available',
        source: 'regular',
        meta: plan
      }));

      const budgetPlans = budgetPlansRaw.map((plan) => ({
        id: plan.data_plan ?? plan.id ?? plan.code,
        name: plan.name ?? 'Data Plan',
        rawPrice: Number(plan.api_user_price ?? plan.price ?? 0),
        availability: plan.availability ?? 'Available',
        source: 'budget-data',
        meta: plan
      }));

      const allPlans = [...regularPlans, ...budgetPlans].filter((plan) => {
        const available = String(plan.availability).toLowerCase() === 'available';
        return available || includeUnavailable;
      });

      const withPricing = [];
      for (const plan of allPlans) {
        const pricing = await applyMarkup('data', plan.rawPrice);
        withPricing.push({
          ...plan,
          pricing: {
            basePrice: pricing.basePrice,
            markupPercent: pricing.markupPercent,
            markupFee: pricing.markupFee,
            finalPrice: pricing.finalPrice
          }
        });
      }

      return respondOk(res, {
        serviceType: 'data',
        network_id: networkId,
        service_id,
        plans: withPricing
      }, 'Data plans loaded');
    }

    // CABLE TV PLANS
    if (serviceType === 'cable_tv') {
      const service_id = String(
        req.query.service_id ||
        req.query.serviceId ||
        req.query.provider ||
        ''
      ).trim().toLowerCase();

      if (!service_id) {
        return respondError(res, 400, 'service_id is required for cable plans');
      }

      const cableRes = await iacafe.getVariations({
        product: 'cable',
        service_id
      }).catch((err) => {
        console.error('CABLE PLANS ERROR:', err?.response?.data || err?.message);
        return null;
      });

      const cablePlansRaw = extractArray(cableRes);

      const plans = cablePlansRaw
        .map((plan) => ({
          id: plan.variation_id ?? plan.id ?? plan.code,
          name: plan.name ?? plan.variation_name ?? 'Cable Plan',
          rawPrice: Number(plan.reseller_price ?? plan.price ?? plan.amount ?? 0),
          availability: plan.availability ?? 'Available',
          source: 'cable',
          meta: plan
        }))
        .filter((plan) => {
          const available = String(plan.availability).toLowerCase() === 'available';
          return available || includeUnavailable;
        });

      const withPricing = [];
      for (const plan of plans) {
        const pricing = await applyMarkup('cable_tv', plan.rawPrice);
        withPricing.push({
          ...plan,
          pricing: {
            basePrice: pricing.basePrice,
            markupPercent: pricing.markupPercent,
            markupFee: pricing.markupFee,
            finalPrice: pricing.finalPrice
          }
        });
      }

      return respondOk(res, {
        serviceType: 'cable_tv',
        service_id,
        plans: withPricing
      }, 'Cable plans loaded');
    }

    // OTHER SERVICES: RETURN SUPPORTED OPTIONS
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
    const event = String(body.event || '').toLowerCase();
    const data = body.data || {};

    const isRelevant =
      event === 'charge.completed' ||
      event === 'transfer.completed' ||
      event === 'transfer.successful' ||
      String(body['event.type'] || '').toUpperCase() === 'BANK_TRANSFER_TRANSACTION';

    if (!isRelevant) {
      console.log('NOT A RELEVANT EVENT:', event);
      return res.status(200).json({ received: true });
    }

    const reference =
      data.tx_ref ||
      body.tx_ref ||
      body.meta_data?.tx_ref ||
      body.meta_data?.reference ||
      null;

    const status = String(data.status || body.status || '').toLowerCase();
    const amount = Number(data.amount ?? body.amount ?? 0);

    console.log('EVENT:', event);
    console.log('REFERENCE:', reference);
    console.log('STATUS:', status);
    console.log('AMOUNT:', amount);

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

    console.log('FOUND INTENT:', intent);

    if (String(intent.status).toLowerCase() === 'successful') {
      console.log('ALREADY PROCESSED', reference);
      return res.status(200).json({ received: true });
    }

    if (status && status !== 'successful' && status !== 'completed') {
      console.log('PAYMENT NOT SUCCESSFUL YET');

      await query(
        `UPDATE payment_intents
         SET status = 'failed',
             meta = $2
         WHERE tx_ref = $1`,
        [
          reference,
          JSON.stringify({
            webhook: body,
            reason: 'flutterwave_not_successful'
          })
        ]
      );

      return res.status(200).json({ received: true });
    }

    const expectedAmount = Number(intent.amount || 0);
    if (expectedAmount && amount && expectedAmount !== amount) {
      console.log('AMOUNT MISMATCH');

      await query(
        `UPDATE payment_intents
         SET status = 'failed',
             meta = $2
         WHERE tx_ref = $1`,
        [
          reference,
          JSON.stringify({
            webhook: body,
            reason: 'amount_mismatch',
            expectedAmount,
            paidAmount: amount
          })
        ]
      );

      return res.status(200).json({ received: true });
    }

    const fee =
      typeof applyWalletFundingFee === 'function'
        ? applyWalletFundingFee(amount || expectedAmount)
        : {
            grossAmount: amount || expectedAmount,
            feePercent: 0,
            feeAmount: 0,
            netAmount: amount || expectedAmount
          };

    const creditedAmount = Number(fee.netAmount || 0);

    console.log('CREDITED AMOUNT:', creditedAmount);

    await query(
      `UPDATE wallets
       SET balance = balance + $2,
           updated_at = NOW()
       WHERE user_id = $1`,
      [intent.user_id, creditedAmount]
    );

    await query(
      `UPDATE payment_intents
       SET status = 'successful',
           verified_at = NOW(),
           meta = $2
       WHERE tx_ref = $1`,
      [
        reference,
        JSON.stringify({
          webhook: body,
          creditedAmount,
          fee
        })
      ]
    );

    const txUpdate = await query(
      `UPDATE transactions
       SET status = 'success',
           meta = $2,
           updated_at = NOW()
       WHERE reference = $1
         AND user_id = $3
       RETURNING *`,
      [
        reference,
        JSON.stringify({
          webhook: body,
          creditedAmount,
          fee
        }),
        intent.user_id
      ]
    );

    const tx = txUpdate.rows[0];
    if (!tx) {
      console.log('NO EXISTING TRANSACTION FOUND TO UPDATE FOR', reference);
      return res.status(200).json({ received: true });
    }

    await addNotification(
      intent.user_id,
      'Wallet funded',
      `₦${Number(creditedAmount).toFixed(2)} has been added to your wallet`,
      { tx_id: tx.id, reference, creditedAmount },
      true
    );

    console.log('WEBHOOK PROCESSED SUCCESSFULLY FOR', reference);
    return res.status(200).json({ received: true, processed: true });
  } catch (err) {
    console.error('WEBHOOK ERROR:', err?.response?.data || err?.message || err);
    return res.status(500).json({ success: false, message: 'Webhook error' });
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
    // Added for Render: confirm DB connectivity before initialization
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