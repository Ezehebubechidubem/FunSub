const fs = require('fs');
const path = require('path');

const CATALOG_DIR = path.join(__dirname, 'provider-catalog');

function normalizeServiceId(v) {
  return String(v || '').trim().toLowerCase();
}

function uid(prefix = '') {
  return `${prefix}${Date.now()}${Math.floor(Math.random() * 100000)}`;
}

function readCatalog(fileName, fallback = []) {
  try {
    const filePath = path.join(CATALOG_DIR, fileName);
    if (!fs.existsSync(filePath)) return fallback;

    const raw = fs.readFileSync(filePath, 'utf8').trim();
    if (!raw) return fallback;

    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : fallback;
  } catch (err) {
    console.error('CATALOG READ ERROR:', fileName, err.message);
    return fallback;
  }
}

function getPlans(serviceType, serviceID) {
  const type = normalizeServiceId(serviceType);

  if (type === 'data') return readCatalog('data.json', []);
  if (type === 'airtime') return readCatalog('airtime.json', []);
  if (type === 'cable_tv') return readCatalog('cable_tv.json', []);
  if (type === 'electricity') return readCatalog('electricity.json', []);
  if (type === 'betting') return readCatalog('betting.json', []);
  if (type === 'recharge_pin') return readCatalog('recharge_pin.json', []);
  if (type === 'data_pin') return readCatalog('data_pin.json', []);
  if (type === 'exam_pin') return readCatalog('exam_pin.json', []);

  return readCatalog('data.json', []);
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
  status
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
        serviceID: serviceID || null
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
          : 'Airtime Recharge';

  const productName =
    serviceType === 'data'
      ? `${String(serviceID || 'DATA').toUpperCase()} Data`
      : serviceType === 'cable_tv'
        ? `${String(serviceID || 'CABLE').toUpperCase()} Cable TV`
        : serviceType === 'electricity'
          ? `${String(serviceID || 'ELECTRICITY').toUpperCase()} Electricity`
          : `${String(serviceID || 'AIRTIME').toUpperCase()} Airtime VTU`;

  const tx = buildTxBase({
    request_id,
    serviceID,
    phone,
    amount,
    serviceType,
    productName,
    type,
    email,
    status: 'delivered'
  });

  tx.content.transactions.variation_code = variation_code || null;
  return tx;
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