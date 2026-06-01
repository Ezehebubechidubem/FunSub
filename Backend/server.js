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

const app = express();
const PORT = process.env.PORT || 3000;

const envNumber = (value, fallback) => {
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
};

const JWT_SECRET = process.env.JWT_SECRET || 'change_this_secret';
const FRONTEND_URL = process.env.FRONTEND_URL || '*';
const FLW_SECRET_KEY = process.env.FLW_SECRET_KEY || '';
const FLW_BASE_URL = process.env.FLW_BASE_URL || '';
const ADMIN_API_KEY = process.env.ADMIN_API_KEY || '';

const SERVICE_PROVIDER = String(process.env.SERVICE_PROVIDER || 'vtpass').toLowerCase();

const DEFAULT_MARKUP_PERCENT = envNumber(process.env.DEFAULT_MARKUP_PERCENT, 2);
const FLW_WALLET_FEE_PERCENT = envNumber(process.env.FLW_WALLET_FEE_PERCENT, 1.7);

const SERVICE_MARKUP_DEFAULTS = {
  airtime: envNumber(process.env.AIRTIME_MARKUP_PERCENT, 2),
  data: envNumber(process.env.DATA_MARKUP_PERCENT, 3),
  cable_tv: envNumber(process.env.CABLE_TV_MARKUP_PERCENT, DEFAULT_MARKUP_PERCENT),
  electricity: envNumber(process.env.ELECTRICITY_MARKUP_PERCENT, DEFAULT_MARKUP_PERCENT),
  betting: envNumber(process.env.BETTING_MARKUP_PERCENT, DEFAULT_MARKUP_PERCENT),
  recharge_pin: envNumber(process.env.RECHARGE_PIN_MARKUP_PERCENT, DEFAULT_MARKUP_PERCENT),
  data_pin: envNumber(process.env.DATA_PIN_MARKUP_PERCENT, DEFAULT_MARKUP_PERCENT),
  exam_pin: envNumber(process.env.EXAM_PIN_MARKUP_PERCENT, DEFAULT_MARKUP_PERCENT)
};

const VTPASS_BASE_URL = String(process.env.VTPASS_BASE_URL || '').replace(/\/$/, '');
const VTPASS_PAY_PATH = String(process.env.VTPASS_PAY_PATH || '');
const VTPASS_REQUERY_PATH = String(process.env.VTPASS_REQUERY_PATH || '');
const VTPASS_USERNAME = process.env.VTPASS_USERNAME || '';
const VTPASS_PASSWORD = process.env.VTPASS_PASSWORD || '';

const VTPASS_VARIATIONS_PATH =
  process.env.VTPASS_VARIATIONS_PATH || '/service-variations';


const VTPASS_API_KEY = process.env.VTPASS_API_KEY || '';
const VTPASS_PUBLIC_KEY = process.env.VTPASS_PUBLIC_KEY || '';
const VTPASS_SECRET_KEY = process.env.VTPASS_SECRET_KEY || '';
const PROVIDER_TIMEOUT_MS = envNumber(process.env.PROVIDER_TIMEOUT_MS, 30000);

const PROVIDER_ENDPOINTS = {
  airtime: {
    plansPath: process.env.VTPASS_AIRTIME_PLANS_PATH || '',
    buyPath: process.env.VTPASS_AIRTIME_BUY_PATH || ''
  },
  data: {
    plansPath: process.env.VTPASS_DATA_PLANS_PATH || '',
    buyPath: process.env.VTPASS_DATA_BUY_PATH || ''
  },
  cable_tv: {
    plansPath: process.env.VTPASS_CABLE_PLANS_PATH || '',
    buyPath: process.env.VTPASS_CABLE_BUY_PATH || ''
  },
  electricity: {
    plansPath: process.env.VTPASS_ELECTRICITY_PLANS_PATH || '',
    buyPath: process.env.VTPASS_ELECTRICITY_BUY_PATH || ''
  },
  betting: {
    plansPath: process.env.VTPASS_BETTING_PLANS_PATH || '',
    buyPath: process.env.VTPASS_BETTING_BUY_PATH || ''
  },
  recharge_pin: {
    plansPath: process.env.VTPASS_RECHARGE_PIN_PLANS_PATH || '',
    buyPath: process.env.VTPASS_RECHARGE_PIN_BUY_PATH || ''
  },
  data_pin: {
    plansPath: process.env.VTPASS_DATA_PIN_PLANS_PATH || '',
    buyPath: process.env.VTPASS_DATA_PIN_BUY_PATH || ''
  },
  exam_pin: {
    plansPath: process.env.VTPASS_EXAM_PIN_PLANS_PATH || '',
    buyPath: process.env.VTPASS_EXAM_PIN_BUY_PATH || ''
  }
};

// Added for Render: fail fast if DATABASE_URL is missing
if (!process.env.DATABASE_URL) {
  throw new Error('DATABASE_URL is missing on Render');
}

const UPLOAD_ROOT = path.join(__dirname, 'uploads');
const AVATAR_DIR = path.join(UPLOAD_ROOT, 'avatars');
const KYC_DIR = path.join(UPLOAD_ROOT, 'kyc');

for (const dir of [UPLOAD_ROOT, AVATAR_DIR, KYC_DIR]) {
  fs.mkdirSync(dir, { recursive: true });
}

app.use(helmet());
app.use(cors({ origin: FRONTEND_URL === '*' ? true : FRONTEND_URL, credentials: true }));
app.use(express.json({ limit: '15mb' }));
app.use(express.urlencoded({ extended: true }));
app.use('/uploads', express.static(UPLOAD_ROOT));

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
    const token = authHeader(req);
    if (!token) return respondError(res, 401, 'Unauthorized');

    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return respondError(res, 401, 'Unauthorized');
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
  return {
    Authorization: `Bearer ${FLW_SECRET_KEY}`,
    'Content-Type': 'application/json'
  };
}

function flutterwaveTxRef() {
  return `PS-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
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
  const rule = await ensurePricingRule(serviceType);
  return Number(rule.markup_percent ?? getDefaultMarkupPercent(serviceType));
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

function providerHeaders(kind = 'get') {
  const headers = {
    'Content-Type': 'application/json'
  };

  if (VTPASS_API_KEY) {
    headers['api-key'] = VTPASS_API_KEY;
  }

  if (kind === 'get') {
    if (VTPASS_PUBLIC_KEY) headers['public-key'] = VTPASS_PUBLIC_KEY;
  } else if (kind === 'post') {
    if (VTPASS_SECRET_KEY) headers['secret-key'] = VTPASS_SECRET_KEY;
  }

  return headers;
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

function resolveVtpassServiceId(serviceType, source = {}) {
  const explicit = source.serviceID || source.serviceId || source.service_id;
  if (explicit) return String(explicit).trim();

  const network = String(source.network || '').trim().toLowerCase();

  const envMap = {
    airtime: process.env.VTPASS_AIRTIME_SERVICE_ID || '',
    data: process.env.VTPASS_DATA_SERVICE_ID || '',
    cable_tv: process.env.VTPASS_CABLE_SERVICE_ID || '',
    electricity: process.env.VTPASS_ELECTRICITY_SERVICE_ID || '',
    betting: process.env.VTPASS_BETTING_SERVICE_ID || '',
    recharge_pin: process.env.VTPASS_RECHARGE_PIN_SERVICE_ID || '',
    data_pin: process.env.VTPASS_DATA_PIN_SERVICE_ID || '',
    exam_pin: process.env.VTPASS_EXAM_PIN_SERVICE_ID || ''
  };

  if (envMap[serviceType]) return envMap[serviceType];

  switch (serviceType) {
    case 'airtime':
      if (network === 'mtn') return 'mtn';
      if (network === 'airtel') return 'airtel';
      if (network === 'glo') return 'glo';
      if (network === '9mobile') return 'etisalat';
      return '';
    case 'data':
      if (network === 'mtn') return 'mtn-data';
      if (network === 'airtel') return 'airtel-data';
      if (network === 'glo') return 'glo-data';
      if (network === '9mobile') return 'etisalat-data';
      return '';
    case 'cable_tv':
    case 'electricity':
    case 'betting':
    case 'recharge_pin':
    case 'data_pin':
    case 'exam_pin':
      return network || '';
    default:
      return network || serviceType;
  }
}

function resolveVtpassVariationCode(serviceType, { selectedPlan, planId, planName, extra = {} } = {}) {
  return (
    extra.variation_code ||
    extra.variationCode ||
    selectedPlan?.id ||
    planId ||
    planName ||
    ''
  );
}

async function callProvider(serviceType, action, payload = {}, params = {}) {
  const normalizedServiceType = normalizeServiceType(serviceType);

  if (!VTPASS_BASE_URL) {
    throw new Error('VTPASS_BASE_URL is missing');
  }

  if (action === 'plans') {
    if (!VTPASS_VARIATIONS_PATH) {
      throw new Error('VTPASS_VARIATIONS_PATH is missing');
    }

    const serviceID = params.serviceID || resolveVtpassServiceId(normalizedServiceType, params);
    if (!serviceID) {
      throw new Error(`Missing serviceID for ${normalizedServiceType}`);
    }

    const response = await axios.get(`${VTPASS_BASE_URL}${VTPASS_VARIATIONS_PATH}`, {
      params: { serviceID },
      headers: providerHeaders('get'),
      timeout: PROVIDER_TIMEOUT_MS
    });

    return response.data;
  }

  if (action === 'buy') {
    if (!VTPASS_PAY_PATH) {
      throw new Error('VTPASS_PAY_PATH is missing');
    }

    const response = await axios.post(
      `${VTPASS_BASE_URL}${VTPASS_PAY_PATH}`,
      compactObject(payload),
      {
        headers: providerHeaders('post'),
        timeout: PROVIDER_TIMEOUT_MS
      }
    );

    return response.data;
  }

  throw new Error(`Unsupported provider action: ${action}`);
}

function providerRequestLooksSuccessful(data) {
  if (!data) return false;
  if (data.success === true) return true;

  const responseDescription = String(data.response_description || '').trim().toLowerCase();
  const code = String(data.code || data.response_code || data.responseCode || '').trim().toLowerCase();
  const txStatus = String(
    data?.content?.transactions?.status ||
      data?.content?.status ||
      data?.data?.content?.transactions?.status ||
      ''
  ).toLowerCase();

  if (code === '000' || code === '00' || code === '0') return true;
  if (txStatus === 'delivered' || txStatus === 'successful' || txStatus === 'success' || txStatus === 'ok') return true;
  if (responseDescription.includes('success')) return true;

  return false;
}

async function fetchProviderPlans(serviceType, params = {}) {
  const normalizedServiceType = normalizeServiceType(serviceType);
  const serviceID = resolveVtpassServiceId(normalizedServiceType, params);

  const response = await callProvider(normalizedServiceType, 'plans', {}, { ...params, serviceID });
  return extractArrayFromProviderResponse(response);
}

function buildProviderPayload({
  serviceType,
  amount,
  phone,
  meterNumber,
  smartCardNumber,
  accountNumber,
  planId,
  planName,
  network,
  selectedPlan,
  extra = {}
}) {
  const normalizedServiceType = normalizeServiceType(serviceType);
  const serviceID = resolveVtpassServiceId(normalizedServiceType, {
    network,
    ...extra
  });

  const request_id = extra.request_id || uid('vt_');
  const variation_code = resolveVtpassVariationCode(normalizedServiceType, {
    selectedPlan,
    planId,
    planName,
    extra
  });

  const payload = {
    request_id,
    serviceID
  };

  if (normalizedServiceType === 'airtime') {
    payload.amount = amount;
    payload.phone = phone;
  } else if (normalizedServiceType === 'data') {
    payload.variation_code = variation_code;
    payload.billersCode = phone || accountNumber || meterNumber || smartCardNumber || '';
    payload.phone = phone || accountNumber || meterNumber || smartCardNumber || '';
    if (amount !== undefined && amount !== null && amount !== '') payload.amount = amount;
  } else if (normalizedServiceType === 'cable_tv') {
    payload.variation_code = variation_code;
    payload.billersCode = smartCardNumber || accountNumber || meterNumber || phone || '';
    payload.phone = phone || smartCardNumber || accountNumber || meterNumber || '';
    if (amount !== undefined && amount !== null && amount !== '') payload.amount = amount;
  } else if (normalizedServiceType === 'electricity') {
    payload.variation_code = variation_code;
    payload.billersCode = meterNumber || accountNumber || phone || '';
    payload.phone = phone || meterNumber || accountNumber || '';
    if (amount !== undefined && amount !== null && amount !== '') payload.amount = amount;
  } else {
    if (variation_code) payload.variation_code = variation_code;
    if (phone) payload.phone = phone;
    if (amount !== undefined && amount !== null && amount !== '') payload.amount = amount;
    if (meterNumber) payload.billersCode = meterNumber;
    if (smartCardNumber) payload.smartcard_number = smartCardNumber;
    if (accountNumber) payload.account_number = accountNumber;
  }

  return compactObject({
    ...payload,
    ...extra
  });
}

async function requeryVtpassTransaction(requestId) {
  if (!VTPASS_BASE_URL) {
    throw new Error('VTPASS_BASE_URL is missing');
  }
  if (!VTPASS_REQUERY_PATH) {
    throw new Error('VTPASS_REQUERY_PATH is missing');
  }

  const response = await axios.post(
    `${VTPASS_BASE_URL}${VTPASS_REQUERY_PATH}`,
    { request_id: requestId },
    {
      headers: providerHeaders('post'),
      timeout: PROVIDER_TIMEOUT_MS
    }
  );

  return response.data;
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
/* AUTH */
app.get('/api/services/data/plans', async (req, res) => {
  const network = req.query.network || 'mtn';

  const serviceMap = {
    mtn: 'mtn-data',
    glo: 'glo-data',
    airtel: 'airtel-data',
    9mobile: 'etisalat-data',

  };

  const serviceID = serviceMap[network];

  const response = await axios.get(
    `https://vtpass.com/api/service-variations?serviceID=${serviceID}`
  );

  res.json(response.data);
});
app.get('/test/data-plans', async (req, res) => {
  try {
    const providerPlans = await fetchProviderPlans('data', {
      network: req.query.network || 'mtn'
    });

    return respondOk(res, {
      plans: providerPlans
    });
  } catch (err) {
    console.error(err);
    return respondError(res, 500, 'Unable to load plans');
  }
});
app.get('/test', (req, res) => {
  res.json({
    success: true,
    message: 'Latest deployment running',
    time: new Date().toISOString()
  });
});

app.post('/api/auth/register', async (req, res) => {
  try {
    const { fullName, email, phone, password, confirmPassword, state } = req.body || {};

    if (!fullName || !email || !phone || !password || !confirmPassword || !state) {
      return respondError(res, 400, 'All fields are required');
    }

    if (String(password).length < 6) {
      return respondError(res, 400, 'Password must be at least 6 characters');
    }

    if (String(password) !== String(confirmPassword)) {
      return respondError(res, 400, 'Passwords do not match');
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
    const userId = uid('usr_');

    const inserted = await query(
      `INSERT INTO users
       (id, role, full_name, email, phone, password_hash, state, avatar_url, kyc_status, profile_complete, online, created_at, updated_at)
       VALUES
       ($1, 'user', $2, $3, $4, $5, $6, NULL, 'unverified', false, false, NOW(), NOW())
       RETURNING id, role, full_name, email, phone, state, avatar_url, kyc_status, profile_complete, online, created_at`,
      [userId, fullName.trim(), normalizedEmail, normalizedPhone, password_hash, state.trim()]
    );

    await ensureWallet(userId);
    await addNotification(userId, 'Welcome to PhoneStop', 'Registration successful', { type: 'auth' }, true);

    const token = signToken({ id: userId, role: 'user' });

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

    if (amt < 100) return respondError(res, 400, 'Minimum funding amount is 100');

    const userResult = await query(
      `SELECT id, full_name, email, phone
       FROM users
       WHERE id = $1
       LIMIT 1`,
      [req.user.id]
    );

    const user = userResult.rows[0];
    if (!user) return respondError(res, 404, 'User not found');

    const init = await flutterwaveInitialize({
      amount: amt,
      user,
      description: 'Wallet funding'
    });

    await query(
      `INSERT INTO payment_intents
       (id, user_id, tx_ref, amount, currency, provider, status, meta, created_at)
       VALUES ($1, $2, $3, $4, 'NGN', 'flutterwave', 'initiated', $5, NOW())`,
      [uid('pit_'), user.id, init.tx_ref, Number(amt).toFixed(2), JSON.stringify({ purpose: 'wallet_funding' })]
    );

    await addTransaction({
      userId: user.id,
      type: 'funding',
      category: 'wallet',
      amount: Number(amt).toFixed(2),
      status: 'pending',
      reference: init.tx_ref,
      description: 'Wallet funding initiated',
      meta: { provider: 'flutterwave' }
    });

    return respondOk(res, {
      tx_ref: init.tx_ref,
      payment_link: init.payment_link
    }, 'Funding initiated');
  } catch (err) {
    console.error(err.response?.data || err.message || err);
    return respondError(res, 500, 'Unable to initiate funding');
  }
});

app.get('/api/wallet/fund/verify/:transactionId', requireAuth, async (req, res) => {
  try {
    const transactionId = req.params.transactionId;
    const data = await flutterwaveVerify(transactionId);

    if (!data) return respondError(res, 400, 'Unable to verify payment');

    const status = String(data.status || '').toLowerCase();
    const amount = toNumber(data.amount, 0);
    const txRef = data.tx_ref;

    if (status !== 'successful') {
      await query(`UPDATE payment_intents SET status = 'failed' WHERE tx_ref = $1`, [txRef]);
      return respondError(res, 400, 'Payment not successful');
    }

    const intent = await query(
      `SELECT * FROM payment_intents WHERE tx_ref = $1 AND user_id = $2 LIMIT 1`,
      [txRef, req.user.id]
    );

    if (!intent.rows[0]) return respondError(res, 404, 'Payment intent not found');

    if (intent.rows[0].status === 'successful') {
      return respondOk(res, { alreadyProcessed: true }, 'Payment already processed');
    }

    const fee = applyWalletFundingFee(amount);

    await query(
      `UPDATE wallets
       SET balance = balance + $2, updated_at = NOW()
       WHERE user_id = $1`,
      [req.user.id, Number(fee.netAmount).toFixed(2)]
    );

    await query(
      `UPDATE payment_intents
       SET status = 'successful', verified_at = NOW()
       WHERE tx_ref = $1`,
      [txRef]
    );

    const tx = await addTransaction({
      userId: req.user.id,
      type: 'funding',
      category: 'wallet',
      amount: Number(fee.netAmount).toFixed(2),
      status: 'success',
      reference: txRef,
      description: 'Wallet funded successfully',
      meta: {
        transaction_id: transactionId,
        provider: 'flutterwave',
        grossAmount: fee.grossAmount,
        feePercent: fee.feePercent,
        feeAmount: fee.feeAmount,
        creditedAmount: fee.netAmount
      }
    });

    await addNotification(
      req.user.id,
      'Wallet funded',
      `₦${Number(fee.netAmount).toFixed(2)} has been added to your wallet`,
      { tx_id: tx.id, txRef, fee },
      true
    );

    const wallet = await ensureWallet(req.user.id);

    return respondOk(res, {
      wallet: {
        balance: Number(wallet.balance).toFixed(2),
        currency: wallet.currency
      },
      fee
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

/* KYC */

app.post(
  '/api/kyc/submit',
  requireAuth,
  kycUpload.fields([
    { name: 'selfie', maxCount: 1 },
    { name: 'idFront', maxCount: 1 },
    { name: 'idBack', maxCount: 1 },
    { name: 'utilityBill', maxCount: 1 }
  ]),
  async (req, res) => {
    try {
      const { idType, idNumber, address } = req.body || {};
      if (!idType || !idNumber) return respondError(res, 400, 'ID type and ID number are required');

      const selfie = req.files?.selfie?.[0];
      const idFront = req.files?.idFront?.[0];
      const idBack = req.files?.idBack?.[0];
      const utilityBill = req.files?.utilityBill?.[0];

      if (!selfie || !idFront) {
        return respondError(res, 400, 'Selfie and ID front are required');
      }

      const inserted = await query(
        `INSERT INTO kyc_requests
         (id, user_id, id_type, id_number, selfie_url, id_front_url, id_back_url, utility_bill_url, address, status, submitted_at)
         VALUES
         ($1,$2,$3,$4,$5,$6,$7,$8,$9,'pending',NOW())
         RETURNING *`,
        [
          uid('kyc_'),
          req.user.id,
          idType,
          idNumber,
          `/uploads/kyc/${selfie.filename}`,
          `/uploads/kyc/${idFront.filename}`,
          idBack ? `/uploads/kyc/${idBack.filename}` : null,
          utilityBill ? `/uploads/kyc/${utilityBill.filename}` : null,
          address || null
        ]
      );

      await query(
        `UPDATE users
         SET kyc_status = 'pending', updated_at = NOW()
         WHERE id = $1`,
        [req.user.id]
      );

      await addNotification(req.user.id, 'KYC submitted', 'Your KYC request has been submitted', { kyc_id: inserted.rows[0].id }, true);

      return respondOk(res, { kyc: inserted.rows[0] }, 'KYC submitted successfully');
    } catch (err) {
      console.error(err);
      return respondError(res, 500, 'Server error');
    }
  }
);

app.get('/api/kyc/status', requireAuth, async (req, res) => {
  try {
    const result = await query(
      `SELECT * FROM kyc_requests
       WHERE user_id = $1
       ORDER BY submitted_at DESC
       LIMIT 1`,
      [req.user.id]
    );

    const user = await query(
      `SELECT kyc_status FROM users WHERE id = $1 LIMIT 1`,
      [req.user.id]
    );

    return respondOk(res, {
      kycStatus: user.rows[0]?.kyc_status || 'unverified',
      kyc: result.rows[0] || null
    });
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

/* BILLS / SERVICES */

app.get('/api/services/:serviceType/plans', requireAuth, async (req, res) => {
  try {
    const serviceType = normalizeServiceType(req.params.serviceType);

    if (![
      'airtime',
      'data',
      'cable_tv',
      'electricity',
      'betting',
      'recharge_pin',
      'data_pin',
      'exam_pin'
    ].includes(serviceType)) {
      return respondError(res, 400, 'Invalid service type');
    }

    if (serviceType === 'airtime' && !VTPASS_VARIATIONS_PATH) {
      return respondOk(res, {
        serviceType,
        plans: []
      }, 'Airtime does not require plans');
    }

    const providerPlans = await fetchProviderPlans(serviceType, {
      network: req.query.network || undefined,
      provider: req.query.provider || undefined,
      serviceID: req.query.serviceID || req.query.serviceId || undefined
    });

    const normalized = extractArrayFromProviderResponse(providerPlans).map(normalizeProviderPlan);

    const withPricing = [];
    for (const plan of normalized) {
      const pricing = await applyMarkup(serviceType, plan.rawPrice);
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
      serviceType,
      plans: withPricing
    }, 'Plans loaded');
  } catch (err) {
    console.error(err.response?.data || err.message || err);
    return respondError(res, 500, 'Unable to load plans');
  }
});

async function processServicePayment(req, res, serviceType, category) {
  try {
    const normalizedServiceType = normalizeServiceType(serviceType);
    const {
      phone,
      meterNumber,
      smartCardNumber,
      accountNumber,
      planId,
      planName,
      provider = SERVICE_PROVIDER,
      network,
      serviceID,
      serviceId
    } = req.body || {};

    const wallet = await ensureWallet(req.user.id);

    let selectedPlan = null;
    let baseAmount = 0;

    if (planId || planName) {
      const plans = await fetchProviderPlans(normalizedServiceType, {
        network: network || undefined,
        provider: provider || undefined,
        serviceID: serviceID || serviceId || undefined
      });

      const normalizedPlans = extractArrayFromProviderResponse(plans).map(normalizeProviderPlan);
      selectedPlan = normalizedPlans.find(
        (p) =>
          String(p.id) === String(planId) ||
          String(p.name).toLowerCase() === String(planName || '').toLowerCase()
      );

      if (!selectedPlan) {
        return respondError(res, 404, 'Selected plan not found');
      }

      baseAmount = Number(selectedPlan.rawPrice);
    } else {
      baseAmount = toNumber(req.body?.amount, 0);
    }

    if (baseAmount <= 0) {
      return respondError(res, 400, 'Amount is required');
    }

    const pricing = await applyMarkup(normalizedServiceType, baseAmount);
    const amt = pricing.finalPrice;

    if (toNumber(wallet.balance, 0) < amt) {
      return respondError(res, 400, 'Insufficient wallet balance');
    }

    await query(
      `UPDATE wallets
       SET balance = balance - $2, updated_at = NOW()
       WHERE user_id = $1`,
      [req.user.id, Number(amt).toFixed(2)]
    );

    let providerReference = uid('srv_');
    let providerResponse = { provider: provider, success: true, mock: true };

    try {
      if (provider === 'vtpass' || provider === SERVICE_PROVIDER) {
        const payload = buildProviderPayload({
          serviceType: normalizedServiceType,
          amount: pricing.basePrice,
          phone,
          meterNumber,
          smartCardNumber,
          accountNumber,
          planId,
          planName,
          network,
          selectedPlan,
          extra: {
            serviceID: serviceID || serviceId,
            finalAmount: pricing.finalPrice,
            pricing
          }
        });

        const response = await callProvider(normalizedServiceType, 'buy', payload, {});
        providerResponse = response;

        providerReference =
          response?.requestId ||
          response?.request_id ||
          response?.content?.requestId ||
          response?.reference ||
          response?.data?.reference ||
          response?.transactionId ||
          response?.data?.transactionId ||
          providerReference;

        if (!providerRequestLooksSuccessful(response)) {
          throw new Error(response?.message || response?.error || response?.response_description || 'Provider purchase failed');
        }
      } else if (process.env.BILLS_PROVIDER_URL) {
        const response = await axios.post(
          `${process.env.BILLS_PROVIDER_URL.replace(/\/$/, '')}/${normalizedServiceType}`,
          {
            amount: pricing.basePrice,
            finalAmount: pricing.finalPrice,
            phone,
            meterNumber,
            smartCardNumber,
            accountNumber,
            plan: selectedPlan?.meta || req.body?.plan,
            planId: selectedPlan?.id || planId,
            network
          },
          {
            headers: {
              Authorization: process.env.BILLS_PROVIDER_KEY ? `Bearer ${process.env.BILLS_PROVIDER_KEY}` : undefined,
              'Content-Type': 'application/json'
            },
            timeout: 30000
          }
        );

        providerResponse = response.data;
        providerReference = response.data?.reference || response.data?.data?.reference || providerReference;
      }
    } catch (err) {
      await query(
        `UPDATE wallets
         SET balance = balance + $2, updated_at = NOW()
         WHERE user_id = $1`,
        [req.user.id, Number(amt).toFixed(2)]
      );
      return respondError(res, 500, err.response?.data?.message || err.message || err?.response_description || 'Bill payment failed');
    }

    const tx = await addTransaction({
      userId: req.user.id,
      type: 'debit',
      category,
      amount: Number(amt).toFixed(2),
      status: 'success',
      reference: providerReference,
      description: `${category} payment`,
      meta: { serviceType: normalizedServiceType, provider, selectedPlan, pricing, providerResponse }
    });

    await addNotification(
      req.user.id,
      `${category} successful`,
      `${category} payment of ₦${Number(amt).toFixed(2)} was successful`,
      { tx_id: tx.id, serviceType: normalizedServiceType, pricing },
      true
    );

    return respondOk(res, {
      transaction: tx,
      pricing,
      providerResponse
    }, `${category} payment successful`);
  } catch (err) {
    console.error(err);
    return respondError(res, 500, 'Server error');
  }
}
app.post('/api/services/airtime', requireAuth, async (req, res) => processServicePayment(req, res, 'airtime', 'Airtime'));
app.post('/api/services/data', requireAuth, async (req, res) => processServicePayment(req, res, 'data', 'Data'));
app.post('/api/services/electricity', requireAuth, async (req, res) => processServicePayment(req, res, 'electricity', 'Electricity'));
app.post('/api/services/cable', requireAuth, async (req, res) => processServicePayment(req, res, 'cable_tv', 'Cable TV'));
app.post('/api/services/betting', requireAuth, async (req, res) => processServicePayment(req, res, 'betting', 'Betting'));

// New service routes from your screenshot
app.post('/api/services/recharge-pin', requireAuth, async (req, res) => processServicePayment(req, res, 'recharge_pin', 'Recharge Pin'));
app.post('/api/services/data-pin', requireAuth, async (req, res) => processServicePayment(req, res, 'data_pin', 'Data Pin'));
app.post('/api/services/exam-pin', requireAuth, async (req, res) => processServicePayment(req, res, 'exam_pin', 'Exam PIN'));

/* WEBHOOK */

app.post('/api/webhooks/flutterwave', async (req, res) => {
  try {
    if (process.env.FLW_WEBHOOK_HASH) {
      const got = req.headers['verif-hash'] || req.headers['x-flw-secret-hash'];
      if (got !== process.env.FLW_WEBHOOK_HASH) {
        return respondError(res, 401, 'Invalid webhook signature');
      }
    }

    const body = req.body || {};
    const event = String(body.event || '').toLowerCase();
    const data = body.data || {};

    if (event === 'charge.completed' || event === 'transfer.completed' || event === 'transfer.successful') {
      const txId = data.id || data.transaction_id;
      if (!txId) return respondOk(res, { received: true }, 'Webhook received');

      const verified = await flutterwaveVerify(txId);
      const txRef = verified?.tx_ref || data.tx_ref;
      const amount = toNumber(verified?.amount || data.amount, 0);
      const status = String(verified?.status || data.status || '').toLowerCase();
      const userMetaId = verified?.meta?.user_id || data.meta?.user_id;

      if (status === 'successful' && userMetaId && txRef) {
        const intent = await query(
          `SELECT * FROM payment_intents WHERE tx_ref = $1 AND user_id = $2 LIMIT 1`,
          [txRef, userMetaId]
        );

        if (intent.rows[0] && intent.rows[0].status !== 'successful') {
          const fee = applyWalletFundingFee(amount);

          await query(
            `UPDATE wallets
             SET balance = balance + $2, updated_at = NOW()
             WHERE user_id = $1`,
            [userMetaId, Number(fee.netAmount).toFixed(2)]
          );

          await query(
            `UPDATE payment_intents
             SET status = 'successful', verified_at = NOW()
             WHERE tx_ref = $1`,
            [txRef]
          );

          await addTransaction({
            userId: userMetaId,
            type: 'funding',
            category: 'wallet',
            amount: Number(fee.netAmount).toFixed(2),
            status: 'success',
            reference: txRef,
            description: 'Wallet funded successfully',
            meta: {
              transaction_id: txId,
              provider: 'flutterwave',
              grossAmount: fee.grossAmount,
              feePercent: fee.feePercent,
              feeAmount: fee.feeAmount,
              creditedAmount: fee.netAmount
            }
          });

          await addNotification(
            userMetaId,
            'Wallet funded',
            `₦${Number(fee.netAmount).toFixed(2)} has been added to your wallet`,
            { txRef, transaction_id: txId, fee },
            true
          );
        }
      }
    }

    return respondOk(res, { received: true }, 'Webhook received');
  } catch (err) {
    console.error(err);
    return respondError(res, 500, 'Webhook error');
  }
});

/* ADMIN */

app.get('/api/admin/dashboard', requireAdmin, async (req, res) => {
  try {
    const users = await query('SELECT COUNT(*)::int AS count FROM users');
    const wallets = await query('SELECT COALESCE(SUM(balance), 0) AS total FROM wallets');
    const txns = await query('SELECT COUNT(*)::int AS count FROM transactions');
    const kycPending = await query("SELECT COUNT(*)::int AS count FROM kyc_requests WHERE status = 'pending'");
    const unread = await query("SELECT COUNT(*)::int AS count FROM notifications WHERE is_read = false");

    await query(
      `INSERT INTO admin_logs (id, admin_id, action, meta, created_at)
       VALUES ($1,$2,$3,$4,NOW())`,
      [uid('log_'), req.user.id, 'view_dashboard', JSON.stringify({})]
    );

    return respondOk(res, {
      stats: {
        users: users.rows[0]?.count || 0,
        totalWalletBalance: Number(wallets.rows[0]?.total || 0).toFixed(2),
        transactions: txns.rows[0]?.count || 0,
        pendingKyc: kycPending.rows[0]?.count || 0,
        unreadNotifications: unread.rows[0]?.count || 0
      }
    });
  } catch (err) {
    console.error(err);
    return respondError(res, 500, 'Server error');
  }
});

app.get('/api/admin/users', requireAdmin, async (req, res) => {
  try {
    const result = await query(
      `SELECT id, role, full_name, email, phone, state, avatar_url, kyc_status, profile_complete, online, created_at, updated_at
       FROM users
       ORDER BY created_at DESC
       LIMIT 300`
    );
    return respondOk(res, { users: result.rows });
  } catch (err) {
    console.error(err);
    return respondError(res, 500, 'Server error');
  }
});

app.get('/api/admin/users', requireAdmin, async (req, res) => {
  try {
    const result = await query(
      `SELECT id, role, full_name, email, phone, state, avatar_url, kyc_status, profile_complete, online, created_at, updated_at
       FROM users
       ORDER BY created_at DESC
       LIMIT 300`
    );
    return respondOk(res, { users: result.rows });
  } catch (err) {
    console.error(err);
    return respondError(res, 500, 'Server error');
  }
});

app.get('/api/admin/users/:id', requireAdmin, async (req, res) => {
  try {
    const result = await query(
      `SELECT id, role, full_name, email, phone, state, avatar_url, kyc_status, profile_complete, online, created_at, updated_at, last_login_at
       FROM users
       WHERE id = $1
       LIMIT 1`,
      [req.params.id]
    );

    if (!result.rows[0]) return respondError(res, 404, 'User not found');

    const wallet = await ensureWallet(req.params.id);
    const txns = await query(
      `SELECT * FROM transactions WHERE user_id = $1 ORDER BY created_at DESC LIMIT 20`,
      [req.params.id]
    );
    const kyc = await query(
      `SELECT * FROM kyc_requests WHERE user_id = $1 ORDER BY submitted_at DESC LIMIT 1`,
      [req.params.id]
    );

    return respondOk(res, {
      user: result.rows[0],
      wallet: { balance: Number(wallet.balance).toFixed(2), currency: wallet.currency },
      transactions: txns.rows,
      kyc: kyc.rows[0] || null
    });
  } catch (err) {
    console.error(err);
    return respondError(res, 500, 'Server error');
  }
});

app.get('/api/admin/transactions', requireAdmin, async (req, res) => {
  try {
    const result = await query(
      `SELECT * FROM transactions ORDER BY created_at DESC LIMIT 500`
    );
    return respondOk(res, { transactions: result.rows });
  } catch (err) {
    console.error(err);
    return respondError(res, 500, 'Server error');
  }
});

app.get('/api/admin/kyc', requireAdmin, async (req, res) => {
  try {
    const result = await query(
      `SELECT * FROM kyc_requests ORDER BY submitted_at DESC LIMIT 300`
    );
    return respondOk(res, { kycRequests: result.rows });
  } catch (err) {
    console.error(err);
    return respondError(res, 500, 'Server error');
  }
});

app.patch('/api/admin/users/:id/kyc', requireAdmin, async (req, res) => {
  try {
    const { status, note } = req.body || {};
    if (!['verified', 'rejected', 'pending'].includes(String(status))) {
      return respondError(res, 400, 'Invalid KYC status');
    }

    const kyc = await query(
      `SELECT * FROM kyc_requests WHERE user_id = $1 ORDER BY submitted_at DESC LIMIT 1`,
      [req.params.id]
    );

    if (!kyc.rows[0]) return respondError(res, 404, 'KYC record not found');

    const updated = await query(
      `UPDATE kyc_requests
       SET status = $2, admin_note = $3, reviewed_at = NOW()
       WHERE id = $1
       RETURNING *`,
      [kyc.rows[0].id, status, note || null]
    );

    await query(
      `UPDATE users
       SET kyc_status = $2, updated_at = NOW()
       WHERE id = $1`,
      [req.params.id, status]
    );

    await addNotification(
      req.params.id,
      'KYC updated',
      `Your KYC status was updated to ${status}`,
      { status, note: note || null },
      true
    );

    await query(
      `INSERT INTO admin_logs (id, admin_id, action, meta, created_at)
       VALUES ($1,$2,$3,$4,NOW())`,
      [uid('log_'), req.user.id, 'update_kyc', JSON.stringify({ user_id: req.params.id, status, note: note || null })]
    );

    return respondOk(res, { kyc: updated.rows[0] }, 'KYC updated');
  } catch (err) {
    console.error(err);
    return respondError(res, 500, 'Server error');
  }
});

app.post('/api/admin/notifications', requireAdmin, async (req, res) => {
  try {
    const { userId, title, message, meta = {} } = req.body || {};
    if (!userId || !title || !message) return respondError(res, 400, 'userId, title and message are required');

    await addNotification(userId, title, message, meta, true);

    await query(
      `INSERT INTO admin_logs (id, admin_id, action, meta, created_at)
       VALUES ($1,$2,$3,$4,NOW())`,
      [uid('log_'), req.user.id, 'create_notification', JSON.stringify({ userId, title, message })]
    );

    return respondOk(res, {}, 'Notification sent');
  } catch (err) {
    console.error(err);
    return respondError(res, 500, 'Server error');
  }
});

app.put('/api/admin/pricing/:serviceType', requireAdmin, async (req, res) => {
  try {
    const serviceType = normalizeServiceType(req.params.serviceType);
    const { markupPercent } = req.body || {};

    if (![
      'airtime',
      'data',
      'cable_tv',
      'electricity',
      'betting',
      'recharge_pin',
      'data_pin',
      'exam_pin'
    ].includes(serviceType)) {
      return respondError(res, 400, 'Invalid service type');
    }

    const markup = toNumber(markupPercent, NaN);
    if (!Number.isFinite(markup) || markup < 0) {
      return respondError(res, 400, 'Invalid markup percent');
    }

    const existing = await query(
      `SELECT * FROM pricing_rules WHERE service_type = $1 LIMIT 1`,
      [serviceType]
    );

    let updated;

    if (existing.rows[0]) {
      updated = await query(
        `UPDATE pricing_rules
         SET markup_percent = $2, updated_at = NOW()
         WHERE service_type = $1
         RETURNING *`,
        [serviceType, Number(markup).toFixed(2)]
      );
    } else {
      updated = await query(
        `INSERT INTO pricing_rules (id, service_type, markup_percent, is_active, created_at, updated_at)
         VALUES ($1, $2, $3, true, NOW(), NOW())
         RETURNING *`,
        [uid('prc_'), serviceType, Number(markup).toFixed(2)]
      );
    }

    return respondOk(res, { pricingRule: updated.rows[0] }, 'Pricing updated');
  } catch (err) {
    console.error(err);
    return respondError(res, 500, 'Server error');
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