const fs = require('fs');
const path = require('path');

const CATALOG_ROOT = path.join(__dirname, 'provider-catalog');

function normalizeKey(v) {
  return String(v || '')
    .trim()
    .toLowerCase()
    .replace(/\s+/g, '-')
    .replace(/[^a-z0-9._-]/g, '');
}

function uid(prefix = '') {
  return `${prefix}${Date.now()}${Math.floor(Math.random() * 100000)}`;
}

function fileExists(filePath) {
  try {
    return fs.existsSync(filePath);
  } catch {
    return false;
  }
}

function safeReadFile(filePath) {
  try {
    const raw = fs.readFileSync(filePath, 'utf8').trim();
    if (!raw) return null;
    return raw;
  } catch (err) {
    console.error('READ ERROR:', filePath, err.message);
    return null;
  }
}

function loadFileData(filePath) {
  try {
    delete require.cache[require.resolve(filePath)];
    const mod = require(filePath);

    if (Array.isArray(mod)) return mod;
    if (Array.isArray(mod?.default)) return mod.default;
    if (Array.isArray(mod?.plans)) return mod.plans;

    return null;
  } catch (err) {
    const raw = safeReadFile(filePath);
    if (!raw) {
      console.error('LOAD ERROR:', filePath, err.message);
      return null;
    }

    try {
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed)) return parsed;
      if (Array.isArray(parsed?.plans)) return parsed.plans;
      if (Array.isArray(parsed?.default)) return parsed.default;
      return null;
    } catch (jsonErr) {
      console.error('JSON PARSE ERROR:', filePath, jsonErr.message);
      return null;
    }
  }
}

function resolveCatalogFile(category, key) {
  const cleanCategory = normalizeKey(category);
  const cleanKey = normalizeKey(key);

  const candidates = [
    path.join(CATALOG_ROOT, cleanCategory, `${cleanKey}.js`),
    path.join(CATALOG_ROOT, cleanCategory, `${cleanKey}.json`),
    path.join(CATALOG_ROOT, cleanCategory, cleanKey, 'index.js'),
    path.join(CATALOG_ROOT, cleanCategory, cleanKey, 'index.json'),
    path.join(CATALOG_ROOT, cleanCategory, 'index.js'),
    path.join(CATALOG_ROOT, cleanCategory, 'index.json')
  ];

  for (const candidate of candidates) {
    if (fileExists(candidate)) return candidate;
  }

  return null;
}

function readPlansFromCatalog(category, key, fallback = []) {
  const filePath = resolveCatalogFile(category, key);
  if (!filePath) return fallback;

  const data = loadFileData(filePath);
  if (!Array.isArray(data)) return fallback;

  return data;
}

function buildDefaultAirtimePlans(network) {
  const base = network || 'mtn';
  return [
    { variation_code: `${base}-50`, name: `${base.toUpperCase()} 50`, variation_amount: 50 },
    { variation_code: `${base}-100`, name: `${base.toUpperCase()} 100`, variation_amount: 100 },
    { variation_code: `${base}-200`, name: `${base.toUpperCase()} 200`, variation_amount: 200 },
    { variation_code: `${base}-500`, name: `${base.toUpperCase()} 500`, variation_amount: 500 }
  ];
}

function buildDefaultDataPlans(network) {
  const base = network || 'mtn';
  return [
    { variation_code: `${base}-500mb`, name: `${base.toUpperCase()} 500MB`, variation_amount: 300 },
    { variation_code: `${base}-1gb`, name: `${base.toUpperCase()} 1GB`, variation_amount: 500 },
    { variation_code: `${base}-2gb`, name: `${base.toUpperCase()} 2GB`, variation_amount: 1000 },
    { variation_code: `${base}-5gb`, name: `${base.toUpperCase()} 5GB`, variation_amount: 2500 }
  ];
}

function buildDefaultCablePlans(provider) {
  const base = provider || 'dstv';
  return [
    { variation_code: `${base}-compact`, name: `${base.toUpperCase()} Compact`, variation_amount: 12000 },
    { variation_code: `${base}-compact-plus`, name: `${base.toUpperCase()} Compact Plus`, variation_amount: 18900 },
    { variation_code: `${base}-premium`, name: `${base.toUpperCase()} Premium`, variation_amount: 24500 }
  ];
}

function buildDefaultElectricityPlans(provider) {
  const base = provider || 'ekedc';
  return [
    { variation_code: `${base}-prepaid`, name: `${base.toUpperCase()} Prepaid`, variation_amount: 1000 },
    { variation_code: `${base}-postpaid`, name: `${base.toUpperCase()} Postpaid`, variation_amount: 2000 }
  ];
}

function buildDefaultExamPlans(provider) {
  const base = provider || 'waec';
  return [
    { variation_code: `${base}-pin-1`, name: `${base.toUpperCase()} PIN 1`, variation_amount: 5000 },
    { variation_code: `${base}-pin-2`, name: `${base.toUpperCase()} PIN 2`, variation_amount: 7000 }
  ];
}

function normalizeServiceType(v) {
  const s = String(v || '').trim().toLowerCase();

  const map = {
    cable: 'cable_tv',
    'cable-tv': 'cable_tv',
    cabletv: 'cable_tv',

    rechargepin: 'recharge_pin',
    'recharge-pin': 'recharge_pin',
    recharge_pin: 'recharge_pin',

    datapin: 'data_pin',
    'data-pin': 'data_pin',
    data_pin: 'data_pin',

    exampin: 'exam_pin',
    'exam-pin': 'exam_pin',
    exam_pin: 'exam_pin'
  };

  return map[s] || s;
}

function extractNetworkOrProvider(serviceType, serviceID, extra = {}) {
  const raw =
    extra.network ||
    extra.provider ||
    extra.serviceID ||
    extra.serviceId ||
    serviceID ||
    '';

  const normalized = normalizeKey(raw);

  if (serviceType === 'data') {
    return normalized.replace(/-data$/, '') || 'mtn';
  }

  if (serviceType === 'airtime') {
    return normalized || 'mtn';
  }

  return normalized || serviceType;
}

function getPlans(serviceType, serviceID, extra = {}) {
  const type = normalizeServiceType(serviceType);
  const key = extractNetworkOrProvider(type, serviceID, extra);

  // Try catalog first
  const catalogPlans = readPlansFromCatalog(type, key, []);

  if (catalogPlans.length > 0) {
    return catalogPlans;
  }

  // Then try category-wide fallback file
  const categoryFallback = readPlansFromCatalog(type, 'index', []);
  if (categoryFallback.length > 0) {
    return categoryFallback;
  }

  // Default built-in fallback if no file exists
  if (type === 'airtime') {
    return buildDefaultAirtimePlans(key);
  }

  if (type === 'data') {
    return buildDefaultDataPlans(key);
  }

  if (type === 'cable_tv') {
    return buildDefaultCablePlans(key);
  }

  if (type === 'electricity') {
    return buildDefaultElectricityPlans(key);
  }

  if (type === 'exam_pin') {
    return buildDefaultExamPlans(key);
  }

  if (type === 'recharge_pin' || type === 'data_pin') {
    return [
      { variation_code: `${key}-basic`, name: `${key.toUpperCase()} Basic`, variation_amount: 1000 },
      { variation_code: `${key}-standard`, name: `${key.toUpperCase()} Standard`, variation_amount: 2000 }
    ];
  }

  return [
    { variation_code: `${key}-basic`, name: `${key.toUpperCase()} Basic`, variation_amount: 100 },
    { variation_code: `${key}-standard`, name: `${key.toUpperCase()} Standard`, variation_amount: 500 }
  ];
}

function buildTxBase({
  request_id,
  serviceID,
  phone,
  amount,
  serviceType,
  productName,
  type,
  email,
  status,
  variation_code
}) {
  const amt = Number(amount || 0);

  return {
    requestId: request_id || uid('req_'),
    amount: amt,
    transaction_date: new Date().toISOString(),
    purchased_code: '',
    code: status === 'failed' ? '016' : '000',
    response_description: status === 'failed' ? 'TRANSACTION FAILED' : 'TRANSACTION SUCCESSFUL',
    content: {
      transactions: {
        status,
        product_name: productName,
        unique_element: phone || null,
        unit_price: String(amt),
        quantity: 1,
        service_verification: null,
        channel: 'api',
        commission: 3.5,
        total_amount: amt - 3.5,
        discount: null,
        type,
        email: email || 'mock@vtu.local',
        phone: phone || null,
        name: null,
        convinience_fee: 0,
        amount: String(amt),
        platform: 'api',
        method: 'api',
        transactionId: uid('tx_'),
        commission_details: {
          amount: 3.5,
          rate: '3.50',
          rate_type: 'percent',
          computation_type: 'default'
        },
        serviceID: serviceID || null,
        variation_code: variation_code || null
      }
    }
  };
}

function buySuccess({
  request_id,
  serviceID,
  phone,
  amount,
  variation_code,
  serviceType,
  email
}) {
  const type =
    serviceType === 'data'
      ? 'Data Purchase'
      : serviceType === 'cable_tv'
        ? 'Cable TV Subscription'
        : serviceType === 'electricity'
          ? 'Electricity Bill Payment'
          : serviceType === 'exam_pin'
            ? 'Exam PIN Purchase'
            : 'Airtime Recharge';

  const productName =
    serviceType === 'data'
      ? `${String(serviceID || 'DATA').toUpperCase()} Data`
      : serviceType === 'cable_tv'
        ? `${String(serviceID || 'CABLE').toUpperCase()} Cable TV`
        : serviceType === 'electricity'
          ? `${String(serviceID || 'ELECTRICITY').toUpperCase()} Electricity`
          : serviceType === 'exam_pin'
            ? `${String(serviceID || 'EXAM').toUpperCase()} Exam PIN`
            : `${String(serviceID || 'AIRTIME').toUpperCase()} Airtime VTU`;

  return buildTxBase({
    request_id,
    serviceID,
    phone,
    amount,
    serviceType,
    productName,
    type,
    email,
    status: 'delivered',
    variation_code
  });
}

function buyFail({
  request_id,
  serviceID,
  phone,
  amount,
  serviceType,
  email
}) {
  const type =
    serviceType === 'data'
      ? 'Data Purchase'
      : serviceType === 'cable_tv'
        ? 'Cable TV Subscription'
        : serviceType === 'electricity'
          ? 'Electricity Bill Payment'
          : serviceType === 'exam_pin'
            ? 'Exam PIN Purchase'
            : 'Airtime Recharge';

  const productName = `${String(serviceID || serviceType || 'SERVICE').toUpperCase()} Service`;

  return buildTxBase({
    request_id,
    serviceID,
    phone,
    amount,
    serviceType,
    productName,
    type,
    email,
    status: 'failed'
  });
}

function requery(request_id) {
  return {
    code: '000',
    response_description: 'TRANSACTION SUCCESSFUL',
    requestId: request_id || uid('req_'),
    content: {
      transactions: {
        status: 'delivered',
        request_id: request_id || uid('req_'),
        transactionId: uid('tx_'),
        product_name: 'Mock Requery',
        amount: 0,
        phone: null
      }
    }
  };
}

module.exports = {
  getPlans,
  buySuccess,
  buyFail,
  requery
};