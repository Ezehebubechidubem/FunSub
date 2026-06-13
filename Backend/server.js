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
const mockProvider = require('./mock-vtpass-server');
const fs = require('fs');
const crypto = require('crypto');

const app = express();
app.disable('x-powered-by');
const PORT = process.env.PORT || 3000;

const envNumber = (value, fallback) => {
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
};

const JWT_SECRET = process.env.JWT_SECRET || 'change_this_secret';
const FRONTEND_URL = process.env.FRONTEND_URL || '*';

const FLW_SECRET_KEY = process.env.FLW_SECRET_KEY;
const FLW_BASE_URL = String(process.env.FLW_BASE_URL || 'https://api.flutterwave.com/v3').replace(/\/$/, '');
const FLW_WEBHOOK_HASH = process.env.FLW_WEBHOOK_HASH;
const FLW_ACCOUNT_TYPE = String(process.env.FLW_ACCOUNT_TYPE || 'dynamic').toLowerCase();
const FLW_CUSTOMER_URL = String(process.env.FLW_CUSTOMER_URL || `${FLW_BASE_URL}/customers`).trim();
const FLW_VA_URL = String(process.env.FLW_VA_URL || `${FLW_BASE_URL}/virtual-account-numbers`).trim();

const SUCCESS_STATUSES = new Set([
  'successful',
  'success',
  'completed',
  'complete',
  'paid',
  'ok'
]);

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

const SERVICE_PROVIDER = String(process.env.SERVICE_PROVIDER || 'vtpass').toLowerCase();
const USING_MOCK_PROVIDER = SERVICE_PROVIDER === 'mock';

const VTPASS_VARIATIONS_PATH = String(process.env.VTPASS_VARIATIONS_PATH || '');
const VTPASS_PAY_PATH = String(process.env.VTPASS_PAY_PATH || '');
const VTPASS_REQUERY_PATH = String(process.env.VTPASS_REQUERY_PATH || '');

const VTPASS_API_KEY = process.env.VTPASS_API_KEY || '';
const VTPASS_PUBLIC_KEY = process.env.VTPASS_PUBLIC_KEY || '';
const VTPASS_SECRET_KEY = process.env.VTPASS_SECRET_KEY || '';
const PROVIDER_TIMEOUT_MS = envNumber(process.env.PROVIDER_TIMEOUT_MS, 30000);

const FUNDING_INITIATE_LIMIT_COUNT = envNumber(process.env.FUNDING_INITIATE_LIMIT_COUNT, 5);
const FUNDING_INITIATE_LIMIT_WINDOW_MINUTES = envNumber(process.env.FUNDING_INITIATE_LIMIT_WINDOW_MINUTES, 10);
const PAYMENT_INTENT_TTL_MINUTES = envNumber(process.env.PAYMENT_INTENT_TTL_MINUTES, 15);
const PURCHASE_IDEMPOTENCY_TTL_MINUTES = envNumber(process.env.PURCHASE_IDEMPOTENCY_TTL_MINUTES, 15);

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

const AUTH_LOGIN_LIMITER = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false
});
app.use('/api/auth/login', AUTH_LOGIN_LIMITER);

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

function isSuccessStatus(value) {
  return SUCCESS_STATUSES.has(normalizeStatus(value));
}

function isFailureStatus(value) {
  return [
    'failed',
    'cancelled',
    'canceled',
    'reversed',
    'aborted',
    'error',
    'timeout',
    'timed-out',
    'declined'
  ].includes(normalizeStatus(value));
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
  if (!FLW_WEBHOOK_HASH) return true;
  const got = String(req.headers['verif-hash'] || req.headers['x-flw-secret-hash'] || '').trim();
  return got && got === FLW_WEBHOOK_HASH;
}

async function query(text, params = []) {
  return pool.query(text, params);
}

function requireAuth(req, res, next) {
  try {
    console.log('================ AUTH DEBUG ================');

    const authHeaderValue = req.headers.authorization;
    console.log('AUTH HEADER:', authHeaderValue);

    if (!authHeaderValue) {
      return res.status(401).json({ success: false, message: 'Authorization header missing' });
    }

    if (!authHeaderValue.startsWith('Bearer ')) {
      return res.status(401).json({ success: false, message: 'Invalid authorization format' });
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

    return res.status(401).json({ success: false, message: err.message || 'Unauthorized' });
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
  meta = {},
  idempotencyKey = null,
  requestHash = null
}) {
  const txRef = reference || uid('ref_');

  const inserted = await query(
    `INSERT INTO transactions
     (id, user_id, type, category, amount, currency, status, reference, description, meta, idempotency_key, request_hash, updated_at, created_at)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,NOW(),NOW())
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
      JSON.stringify(meta),
      idempotencyKey,
      requestHash
    ]
  );

  return inserted.rows[0];
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

function requireDebugAccess(req, res, next) {
  const got = req.headers['x-debug-key'] || req.query.debug_key;
  const expected = process.env.DEBUG_KEY;

  if (!expected || got !== expected) {
    return respondError(res, 403, 'Debug access denied');
  }

  next();
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

function buildDepositBreakdown(netAmount) {
  const net = toNumber(netAmount, 0);
  const feePercent = FLW_WALLET_FEE_PERCENT;
  const feeAmount = Number(((net * feePercent) / 100).toFixed(2));
  const grossAmount = Number((net + feeAmount).toFixed(2));

  return {
    netAmount: Number(net.toFixed(2)),
    feePercent: Number(feePercent.toFixed(2)),
    feeAmount,
    grossAmount
  };
}

function hashJson(value) {
  return crypto.createHash('sha256').update(JSON.stringify(value || {})).digest('hex');
}

function webhookDedupKey(body = {}) {
  const data = body.data || {};
  return hashJson([
    String(body.event || ''),
    String(data.tx_ref || body.tx_ref || ''),
    String(data.status || body.status || ''),
    String(data.amount || body.amount || ''),
    String(data.flw_ref || ''),
    String(data.id || '')
  ]);
}

function getPurchaseIdempotencyKey(req, fallbackKey = '') {
  return String(
    req.headers['x-idempotency-key'] ||
    req.body?.idempotencyKey ||
    req.body?.idempotency_key ||
    fallbackKey ||
    ''
  ).trim();
}

function getPurchaseRequestHash({
  serviceType,
  body = {},
  destination = '',
  pricing = null,
  selectedPlan = null,
  providerPayload = null
} = {}) {
  return hashJson({
    serviceType: normalizeServiceType(serviceType),
    network: String(body.network || '').trim().toLowerCase(),
    serviceID: String(providerPayload?.serviceID || body.serviceID || body.serviceId || '').trim(),
    destination: String(destination || '').trim(),
    amount: Number(pricing?.finalPrice || 0),
    variation_code: String(
      body.variation_code ||
      body.planId ||
      body.plan_id ||
      body.planCode ||
      body.code ||
      selectedPlan?.id ||
      ''
    ).trim().toLowerCase(),
    plan_name: String(body.plan_name || selectedPlan?.name || '').trim().toLowerCase(),
    billersCode: String(
      body.billersCode ||
      body.meter_number ||
      body.smartcard_number ||
      body.accountNumber ||
      body.customer_id ||
      ''
    ).trim(),
    phone: String(body.phone || '').trim()
  });
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

function providerHeaders(kind = 'get') {
  const headers = { 'Content-Type': 'application/json' };

  if (VTPASS_API_KEY) headers['api-key'] = VTPASS_API_KEY;

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

function getProviderConfig(serviceType) {
  const normalized = normalizeServiceType(serviceType);
  return { serviceType: normalized, ...PROVIDER_ENDPOINTS[normalized] };
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
  const usingMock = SERVICE_PROVIDER === 'mock';

  const baseUrl = usingMock ? MOCK_PROVIDER_BASE_URL : VTPASS_BASE_URL;
  const variationsPath = usingMock ? '/api/service-variations' : VTPASS_VARIATIONS_PATH;
  const payPath = usingMock ? '/api/pay' : VTPASS_PAY_PATH;

  if (!baseUrl) throw new Error('Provider base URL is missing');

  if (action === 'plans') {
    const serviceID = params.serviceID || resolveVtpassServiceId(normalizedServiceType, params);
    if (!serviceID) throw new Error(`Missing serviceID for ${normalizedServiceType}`);

    const response = await axios.get(`${baseUrl}${variationsPath}`, {
      params: { serviceID },
      headers: providerHeaders('get'),
      timeout: PROVIDER_TIMEOUT_MS
    });

    return response.data;
  }

  if (action === 'buy') {
    const response = await axios.post(
      `${baseUrl}${payPath}`,
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

  if (!serviceID) throw new Error(`Missing serviceID for ${normalizedServiceType}`);

  if (USING_MOCK_PROVIDER) {
    return mockProvider.getPlans(normalizedServiceType, serviceID);
  }

  if (!VTPASS_BASE_URL) throw new Error('VTPASS_BASE_URL is missing');
  if (!VTPASS_VARIATIONS_PATH) throw new Error('VTPASS_VARIATIONS_PATH is missing');

  const response = await axios.get(`${VTPASS_BASE_URL}${VTPASS_VARIATIONS_PATH}`, {
    params: { serviceID },
    headers: providerHeaders('get'),
    timeout: PROVIDER_TIMEOUT_MS
  });

  const rawVariations = extractArrayFromProviderResponse(response.data);

  return rawVariations.map((item) => ({
    id: item.variation_code || item.id || item.code || uid('plan_'),
    name: item.name || item.variation_name || 'Plan',
    rawPrice: Number(item.variation_amount ?? item.price ?? item.amount ?? 0),
    meta: item
  }));
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
  const serviceID = resolveVtpassServiceId(normalizedServiceType, { network, ...extra });

  const request_id = extra.request_id || uid('vt_');
  const variation_code = resolveVtpassVariationCode(normalizedServiceType, {
    selectedPlan,
    planId,
    planName,
    extra
  });

  const payload = { request_id, serviceID };

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
  const usingMock = SERVICE_PROVIDER === 'mock';
  const baseUrl = usingMock ? MOCK_PROVIDER_BASE_URL : VTPASS_BASE_URL;
  const requeryPath = usingMock ? '/api/requery' : VTPASS_REQUERY_PATH;

  if (!baseUrl) throw new Error('Provider base URL is missing');
  if (!requeryPath) throw new Error('Provider requery path is missing');

  const response = await axios.post(
    `${baseUrl}${requeryPath}`,
    { request_id: requestId },
    { headers: providerHeaders('post'), timeout: PROVIDER_TIMEOUT_MS }
  );

  return response.data;
}

async function deleteExpiredPaymentIntents() {
  try {
    await query(`
      DELETE FROM payment_intents
      WHERE provider = 'flutterwave'
        AND status IN ('initiated', 'pending')
        AND expires_at IS NOT NULL
        AND expires_at <= NOW()
    `);
  } catch (err) {
    console.error('PAYMENT INTENT CLEANUP ERROR:', err);
  }
}

setInterval(() => {
  deleteExpiredPaymentIntents().catch(err => {
    console.error('PAYMENT INTENT CLEANUP LOOP ERROR:', err?.message || err);
  });
}, 60 * 1000).unref?.();
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
      idempotency_key TEXT,
      request_hash TEXT,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
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
      expires_at TIMESTAMPTZ,
      provider_tx_ref TEXT,
      webhook_hash TEXT,
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

    CREATE TABLE IF NOT EXISTS processed_webhook_events (
      id TEXT PRIMARY KEY,
      event_hash TEXT NOT NULL UNIQUE,
      reference TEXT,
      payload JSONB DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await query(`
    CREATE UNIQUE INDEX IF NOT EXISTS transactions_purchase_idempotency_unique
    ON transactions (user_id, category, idempotency_key, request_hash)
    WHERE type = 'purchase'
      AND idempotency_key IS NOT NULL
      AND request_hash IS NOT NULL;
  `);

  await query(`
    CREATE INDEX IF NOT EXISTS transactions_user_id_category_idx
    ON transactions (user_id, category, created_at DESC);
  `);
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

    const walletResult = await client.query(
      `SELECT * FROM wallets
       WHERE user_id = $1
       FOR UPDATE`,
      [intent.user_id]
    );

    const wallet = walletResult.rows[0];
    if (!wallet) {
      await client.query('ROLLBACK');
      return { ok: false, reason: 'Wallet not found' };
    }

    const expectedAmount = Number(intent.amount || 0);
    const paidAmount = Number(amount || 0);

    if (expectedAmount && paidAmount && Math.abs(expectedAmount - paidAmount) > 0.01) {
      await client.query(
        `UPDATE payment_intents
         SET status = 'failed',
             verified_at = NOW(),
             provider_tx_ref = COALESCE($2, provider_tx_ref),
             webhook_hash = COALESCE($3, webhook_hash),
             meta = $4
         WHERE tx_ref = $1`,
        [
          reference,
          String(flutterwaveData?.id || flutterwaveData?.flw_ref || flutterwaveData?.reference || '') || null,
          String(rawWebhook ? webhookDedupKey(rawWebhook) : '') || null,
          JSON.stringify({
            reason: 'amount_mismatch',
            expectedAmount,
            paidAmount,
            flutterwaveData,
            rawWebhook
          })
        ]
      );

      const failedTx = await client.query(
        `UPDATE transactions
         SET status = 'failed',
             description = $2,
             meta = $3,
             updated_at = NOW()
         WHERE reference = $1
           AND user_id = $4
         RETURNING *`,
        [
          reference,
          'Wallet funding failed',
          JSON.stringify({
            reason: 'amount_mismatch',
            expectedAmount,
            paidAmount,
            flutterwaveData,
            rawWebhook
          }),
          intent.user_id
        ]
      );

      if (!failedTx.rows[0]) {
        await client.query(
          `INSERT INTO transactions
           (id, user_id, type, category, amount, currency, status, reference, description, meta, updated_at, created_at)
           VALUES ($1, $2, $3, $4, $5, 'NGN', 'failed', $6, $7, $8, NOW(), NOW())`,
          [
            uid('tx_'),
            intent.user_id,
            'funding',
            'wallet',
            expectedAmount,
            reference,
            'Wallet funding failed',
            JSON.stringify({
              reason: 'amount_mismatch',
              expectedAmount,
              paidAmount,
              flutterwaveData,
              rawWebhook
            })
          ]
        );
      }

      await client.query('COMMIT');
      return { ok: false, reason: 'Amount mismatch' };
    }

    const fee = applyWalletFundingFee(paidAmount || expectedAmount);
    const creditedAmount = Number(fee.netAmount || 0);

    if (!Number.isFinite(creditedAmount) || creditedAmount <= 0) {
      await client.query('ROLLBACK');
      return { ok: false, reason: 'Invalid credited amount' };
    }

    await client.query(
      `UPDATE wallets
       SET balance = balance + $2,
           updated_at = NOW()
       WHERE user_id = $1`,
      [intent.user_id, creditedAmount]
    );

    const txUpdate = await client.query(
      `UPDATE transactions
       SET status = 'success',
           amount = $2,
           meta = $3,
           updated_at = NOW()
       WHERE reference = $1
         AND user_id = $4
       RETURNING *`,
      [
        reference,
        creditedAmount,
        JSON.stringify({
          flutterwaveData,
          rawWebhook,
          creditedAmount,
          fee,
          grossAmount: expectedAmount,
          netAmount: creditedAmount
        }),
        intent.user_id
      ]
    );

    if (!txUpdate.rows[0]) {
      await client.query(
        `INSERT INTO transactions
         (id, user_id, type, category, amount, currency, status, reference, description, meta, updated_at, created_at)
         VALUES ($1, $2, $3, $4, $5, 'NGN', 'success', $6, $7, $8, NOW(), NOW())`,
        [
          uid('tx_'),
          intent.user_id,
          'funding',
          'wallet',
          creditedAmount,
          reference,
          'Wallet funded successfully',
          JSON.stringify({
            flutterwaveData,
            rawWebhook,
            creditedAmount,
            fee,
            grossAmount: expectedAmount,
            netAmount: creditedAmount
          })
        ]
      );
    }

    await client.query(
      `UPDATE payment_intents
       SET status = 'successful',
           verified_at = NOW(),
           provider_tx_ref = COALESCE($2, provider_tx_ref),
           webhook_hash = COALESCE($3, webhook_hash),
           meta = $4
       WHERE tx_ref = $1`,
      [
        reference,
        String(flutterwaveData?.id || flutterwaveData?.flw_ref || flutterwaveData?.reference || '') || null,
        String(rawWebhook ? webhookDedupKey(rawWebhook) : '') || null,
        JSON.stringify({
          flutterwaveData,
          rawWebhook,
          creditedAmount,
          fee,
          grossAmount: expectedAmount,
          netAmount: creditedAmount
        })
      ]
    );

    await client.query('COMMIT');

    try {
      await addNotification(
        intent.user_id,
        'Wallet funded',
        `₦${Number(creditedAmount).toFixed(2)} has been added to your wallet`,
        { reference, creditedAmount, fee },
        true
      );
    } catch (notifyErr) {
      console.error('NOTIFICATION ERROR:', notifyErr?.message || notifyErr);
    }

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

async function processFundingFailure({
  reference,
  flutterwaveData = {},
  rawWebhook = null,
  reason = 'failed'
}) {
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

    await client.query(
      `UPDATE payment_intents
       SET status = 'failed',
           verified_at = NOW(),
           provider_tx_ref = COALESCE($2, provider_tx_ref),
           webhook_hash = COALESCE($3, webhook_hash),
           meta = $4
       WHERE tx_ref = $1`,
      [
        reference,
        String(flutterwaveData?.id || flutterwaveData?.flw_ref || flutterwaveData?.reference || '') || null,
        String(rawWebhook ? webhookDedupKey(rawWebhook) : '') || null,
        JSON.stringify({
          reason,
          flutterwaveData,
          rawWebhook
        })
      ]
    );

    const failedTx = await client.query(
      `UPDATE transactions
       SET status = 'failed',
           description = $2,
           meta = $3,
           updated_at = NOW()
       WHERE reference = $1
         AND user_id = $4
       RETURNING *`,
      [
        reference,
        'Wallet funding failed',
        JSON.stringify({
          reason,
          flutterwaveData,
          rawWebhook
        }),
        intent.user_id
      ]
    );

    if (!failedTx.rows[0]) {
      await client.query(
        `INSERT INTO transactions
         (id, user_id, type, category, amount, currency, status, reference, description, meta, updated_at, created_at)
         VALUES ($1, $2, $3, $4, $5, 'NGN', 'failed', $6, $7, $8, NOW(), NOW())`,
        [
          uid('tx_'),
          intent.user_id,
          'funding',
          'wallet',
          Number(intent.amount || 0),
          reference,
          'Wallet funding failed',
          JSON.stringify({
            reason,
            flutterwaveData,
            rawWebhook
          })
        ]
      );
    }

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
///////////////////////////////////////////////////////////////////////////////////////////
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

    return respondOk(res, { token, user: inserted.rows[0] }, 'Registration successful');
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
  const client = await pool.connect();

  try {
    const { amount } = req.body || {};
    const amt = toNumber(amount, 0);

    if (amt < 100) {
      return respondError(res, 400, 'Minimum funding amount is 100');
    }

    const recentAttempts = await query(
      `SELECT COUNT(*)::int AS count
       FROM payment_intents
       WHERE user_id = $1
         AND provider = 'flutterwave'
         AND created_at > NOW() - INTERVAL '${FUNDING_INITIATE_LIMIT_WINDOW_MINUTES} minutes'`,
      [req.user.id]
    );

    if ((recentAttempts.rows[0]?.count || 0) >= FUNDING_INITIATE_LIMIT_COUNT) {
      return respondError(res, 429, 'Too many funding requests. Try again later.');
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

    const fee = buildDepositBreakdown(amt);
    const reference = flutterwaveTxRef('fund');
    const expiresAt = new Date(Date.now() + (PAYMENT_INTENT_TTL_MINUTES * 60 * 1000));

    const virtualAccount = await flutterwaveCreateVirtualAccount({
      amount: fee.grossAmount,
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
      grossAmount: fee.grossAmount,
      netAmount: fee.netAmount,
      fee,
      virtualAccount
    };

    await query(
      `INSERT INTO payment_intents
       (id, user_id, tx_ref, amount, currency, provider, status, meta, expires_at, created_at)
       VALUES ($1, $2, $3, $4, 'NGN', 'flutterwave', 'initiated', $5, $6, NOW())`,
      [
        uid('pit_'),
        user.id,
        reference,
        fee.grossAmount,
        JSON.stringify(intentMeta),
        expiresAt
      ]
    );

    await query(
      `INSERT INTO transactions
       (id, user_id, type, category, amount, currency, status, reference, description, meta, updated_at, created_at)
       VALUES ($1, $2, $3, $4, $5, 'NGN', 'pending', $6, $7, $8, NOW(), NOW())`,
      [
        uid('tx_'),
        user.id,
        'funding',
        'wallet',
        fee.netAmount,
        reference,
        'Wallet funding initiated',
        JSON.stringify({
          provider: 'flutterwave',
          grossAmount: fee.grossAmount,
          feePercent: fee.feePercent,
          feeAmount: fee.feeAmount,
          netAmount: fee.netAmount,
          accountType: FLW_ACCOUNT_TYPE === 'static' ? 'static' : 'dynamic',
          expiresAt
        })
      ]
    );

    return respondOk(res, {
      reference,
      amount: fee.netAmount.toFixed(2),
      gross_amount: fee.grossAmount.toFixed(2),
      fee_percent: fee.feePercent.toFixed(2),
      fee_amount: fee.feeAmount.toFixed(2),
      net_amount: fee.netAmount.toFixed(2),
      account_number: accountNumber,
      bank_name: bankName,
      account_name: accountName,
      expiry_date: expiryDate,
      expires_at: expiresAt,
      account_type: FLW_ACCOUNT_TYPE === 'static' ? 'static' : 'dynamic'
    }, 'Funding details generated');
  } catch (err) {
    try { await client.query('ROLLBACK'); } catch (_) {}
    console.error('FUND INITIATE ERROR:', err?.response?.data || err?.message || err);
    return respondError(res, 500, err?.message || 'Unable to initiate funding');
  } finally {
    client.release();
  }
});

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

app.get('/api/wallet/fund/verify/:transactionId', requireAuth, async (req, res) => {
  try {
    const transactionId = String(req.params.transactionId || '').trim();
    if (!transactionId) {
      return respondError(res, 400, 'transactionId is required');
    }

    const data = await axios.get(`${FLW_BASE_URL}/transactions/verify_by_reference`, {
      params: { tx_ref: transactionId },
      headers: flutterwaveHeaders(),
      timeout: 30000
    }).then(r => r.data?.data || r.data);

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

    if (isSuccessStatus(providerStatus)) {
      const result = await processFundingSuccess({
        reference: txRef,
        amount,
        flutterwaveData: data,
        rawWebhook: null
      });

      const wallet = await ensureWallet(req.user.id);

      return respondOk(res, {
        processed: true,
        result,
        wallet: {
          balance: Number(wallet.balance).toFixed(2),
          currency: wallet.currency
        }
      }, 'Wallet funded successfully');
    }

    if (isFailureStatus(providerStatus)) {
      await processFundingFailure({
        reference: txRef,
        flutterwaveData: data,
        rawWebhook: null,
        reason: providerStatus || 'failed'
      });

      return respondError(res, 400, 'Payment not successful');
    }

    return respondOk(res, {
      pending: true,
      reference: txRef,
      status: providerStatus || 'pending',
      transaction: existingTransaction,
      intent
    }, 'Payment still pending');
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

app.get('/api/services', requireAuth, async (req, res) => {
  try {
    return respondOk(res, { services: SERVICE_CATALOG }, 'Services loaded');
  } catch (err) {
    console.error(err);
    return respondError(res, 500, 'Server error');
  }
});

/* SERVICES LIST */
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

app.get('/api/services', requireAuth, async (req, res) => {
  try {
    return respondOk(res, { services: SERVICE_CATALOG }, 'Services loaded');
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

    const providerPlans = await fetchProviderPlans(serviceType, {
      network: req.query.network || undefined,
      provider: req.query.provider || undefined,
      serviceID: req.query.serviceID || req.query.serviceId || undefined
    });

    const normalized = providerPlans.map(normalizeProviderPlan);

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

    return respondOk(res, { serviceType, plans: withPricing }, 'Plans loaded');
  } catch (err) {
    console.error('LOAD PLANS ERROR:', err);
    console.error('MESSAGE:', err?.message);
    console.error('STACK:', err?.stack);
    console.error('RESPONSE DATA:', err?.response?.data);
    return respondError(res, 500, 'Unable to load plans');
  }
});

app.post('/api/services/airtime', requireAuth, async (req, res) => processServicePayment(req, res, 'airtime', 'Airtime'));
app.post('/api/services/data', requireAuth, async (req, res) => processServicePayment(req, res, 'data', 'Data'));
app.post('/api/services/electricity', requireAuth, async (req, res) => processServicePayment(req, res, 'electricity', 'Electricity'));
app.post('/api/services/cable', requireAuth, async (req, res) => processServicePayment(req, res, 'cable_tv', 'Cable TV'));
app.post('/api/services/betting', requireAuth, async (req, res) => processServicePayment(req, res, 'betting', 'Betting'));
app.post('/api/services/recharge-pin', requireAuth, async (req, res) => processServicePayment(req, res, 'recharge_pin', 'Recharge Pin'));
app.post('/api/services/data-pin', requireAuth, async (req, res) => processServicePayment(req, res, 'data_pin', 'Data Pin'));
app.post('/api/services/exam-pin', requireAuth, async (req, res) => processServicePayment(req, res, 'exam_pin', 'Exam PIN'));

/* WALLET FUNDING */
app.post('/api/wallet/fund/initiate', requireAuth, async (req, res) => {
  const client = await pool.connect();

  try {
    const { amount } = req.body || {};
    const amt = toNumber(amount, 0);

    if (amt < 100) {
      return respondError(res, 400, 'Minimum funding amount is 100');
    }

    const recentAttempts = await query(
      `SELECT COUNT(*)::int AS count
       FROM payment_intents
       WHERE user_id = $1
         AND provider = 'flutterwave'
         AND created_at > NOW() - INTERVAL '${FUNDING_INITIATE_LIMIT_WINDOW_MINUTES} minutes'`,
      [req.user.id]
    );

    if ((recentAttempts.rows[0]?.count || 0) >= FUNDING_INITIATE_LIMIT_COUNT) {
      return respondError(res, 429, 'Too many funding requests. Try again later.');
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

    const fee = buildDepositBreakdown(amt);
    const reference = flutterwaveTxRef('fund');
    const expiresAt = new Date(Date.now() + (PAYMENT_INTENT_TTL_MINUTES * 60 * 1000));

    const virtualAccount = await flutterwaveCreateVirtualAccount({
      amount: fee.grossAmount,
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
      grossAmount: fee.grossAmount,
      netAmount: fee.netAmount,
      fee,
      virtualAccount
    };

    await query(
      `INSERT INTO payment_intents
       (id, user_id, tx_ref, amount, currency, provider, status, meta, expires_at, created_at)
       VALUES ($1, $2, $3, $4, 'NGN', 'flutterwave', 'initiated', $5, $6, NOW())`,
      [
        uid('pit_'),
        user.id,
        reference,
        fee.grossAmount,
        JSON.stringify(intentMeta),
        expiresAt
      ]
    );

    await query(
      `INSERT INTO transactions
       (id, user_id, type, category, amount, currency, status, reference, description, meta, updated_at, created_at)
       VALUES ($1, $2, $3, $4, $5, 'NGN', 'pending', $6, $7, $8, NOW(), NOW())`,
      [
        uid('tx_'),
        user.id,
        'funding',
        'wallet',
        fee.netAmount,
        reference,
        'Wallet funding initiated',
        JSON.stringify({
          provider: 'flutterwave',
          grossAmount: fee.grossAmount,
          feePercent: fee.feePercent,
          feeAmount: fee.feeAmount,
          netAmount: fee.netAmount,
          accountType: FLW_ACCOUNT_TYPE === 'static' ? 'static' : 'dynamic',
          expiresAt
        })
      ]
    );

    return respondOk(res, {
      reference,
      amount: fee.netAmount.toFixed(2),
      gross_amount: fee.grossAmount.toFixed(2),
      fee_percent: fee.feePercent.toFixed(2),
      fee_amount: fee.feeAmount.toFixed(2),
      net_amount: fee.netAmount.toFixed(2),
      account_number: accountNumber,
      bank_name: bankName,
      account_name: accountName,
      expiry_date: expiryDate,
      expires_at: expiresAt,
      account_type: FLW_ACCOUNT_TYPE === 'static' ? 'static' : 'dynamic'
    }, 'Funding details generated');
  } catch (err) {
    try { await client.query('ROLLBACK'); } catch (_) {}
    console.error('FUND INITIATE ERROR:', err?.response?.data || err?.message || err);
    return respondError(res, 500, err?.message || 'Unable to initiate funding');
  } finally {
    client.release();
  }
});

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

app.get('/api/wallet/fund/verify/:transactionId', requireAuth, async (req, res) => {
  try {
    const transactionId = String(req.params.transactionId || '').trim();
    if (!transactionId) {
      return respondError(res, 400, 'transactionId is required');
    }

    const data = await axios.get(`${FLW_BASE_URL}/transactions/verify_by_reference`, {
      params: { tx_ref: transactionId },
      headers: flutterwaveHeaders(),
      timeout: 30000
    }).then(r => r.data?.data || r.data);

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

    if (isSuccessStatus(providerStatus)) {
      const result = await processFundingSuccess({
        reference: txRef,
        amount,
        flutterwaveData: data,
        rawWebhook: null
      });

      const wallet = await ensureWallet(req.user.id);

      return respondOk(res, {
        processed: true,
        result,
        wallet: {
          balance: Number(wallet.balance).toFixed(2),
          currency: wallet.currency
        }
      }, 'Wallet funded successfully');
    }

    if (isFailureStatus(providerStatus)) {
      await processFundingFailure({
        reference: txRef,
        flutterwaveData: data,
        rawWebhook: null,
        reason: providerStatus || 'failed'
      });

      return respondError(res, 400, 'Payment not successful');
    }

    return respondOk(res, {
      pending: true,
      reference: txRef,
      status: providerStatus || 'pending',
      transaction: existingTransaction,
      intent
    }, 'Payment still pending');
  } catch (err) {
    console.error(err.response?.data || err.message || err);
    return respondError(res, 500, 'Unable to verify payment');
  }
});
/* WEBHOOK */
app.get('/api/webhooks/flutterwave', (req, res) => {
  return res.status(200).send('Flutterwave webhook endpoint is live');
});

app.post('/api/webhooks/flutterwave', async (req, res) => {
  try {
    console.log('========== FLW WEBHOOK HIT ==========');
    console.log('Expected Hash:', FLW_WEBHOOK_HASH);
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

    const dedupKey = webhookDedupKey(body);

    const dedup = await query(
      `INSERT INTO processed_webhook_events (id, event_hash, reference, payload)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (event_hash) DO NOTHING
       RETURNING id`,
      [uid('whe_'), dedupKey, reference, JSON.stringify(body)]
    );

    if (!dedup.rows[0]) {
      return res.status(200).json({ received: true, duplicate: true });
    }

    if (isSuccessStatus(status)) {
      const result = await processFundingSuccess({
        reference,
        amount,
        flutterwaveData: data,
        rawWebhook: body
      });

      return res.status(200).json({ received: true, processed: true, result });
    }

    if (isFailureStatus(status)) {
      const result = await processFundingFailure({
        reference,
        flutterwaveData: data,
        rawWebhook: body,
        reason: status || 'failed'
      });

      return res.status(200).json({ received: true, processed: true, result });
    }

    console.log('PAYMENT STILL PENDING, NO STATUS CHANGE');

    await query(
      `UPDATE payment_intents
       SET meta = COALESCE(meta, '{}'::jsonb) || $2::jsonb
       WHERE tx_ref = $1`,
      [
        reference,
        JSON.stringify({
          lastWebhookStatus: status || 'pending',
          lastWebhookPayload: body
        })
      ]
    );

    await query(
      `UPDATE transactions
       SET meta = COALESCE(meta, '{}'::jsonb) || $2::jsonb,
           updated_at = NOW()
       WHERE reference = $1`,
      [
        reference,
        JSON.stringify({
          lastWebhookStatus: status || 'pending',
          lastWebhookPayload: body
        })
      ]
    );

    return res.status(200).json({ received: true, pending: true });
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