require('dotenv').config();

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 4005;

app.use(helmet());
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true }));

function uid(prefix = '') {
  return `${prefix}${crypto.randomUUID().replace(/-/g, '')}`;
}

function normalizeServiceId(v) {
  return String(v || '').trim().toLowerCase();
}

function normalizePhone(v) {
  return String(v || '').replace(/\D/g, '');
}

function compactObject(obj) {
  const out = {};
  for (const [k, v] of Object.entries(obj || {})) {
    if (v !== undefined && v !== null && v !== '') out[k] = v;
  }
  return out;
}

function ok(res, payload = {}) {
  return res.json(payload);
}

function invalidArgs(res, errors = []) {
  return res.json({
    code: '011',
    response_description: 'INVALID ARGUMENTS',
    content: { errors }
  });
}

function failed(res, requestId, amount, serviceID, phone, productName = 'Airtime Recharge', extra = {}) {
  return res.json({
    code: '016',
    content: {
      transactions: {
        status: 'failed',
        product_name: productName,
        unique_element: phone || null,
        unit_price: String(amount || '0'),
        quantity: 1,
        service_verification: null,
        channel: 'api',
        commission: 3.5,
        total_amount: Number(amount || 0) - 3.5,
        discount: null,
        type: extra.type || 'Airtime Recharge',
        email: extra.email || 'mock@vtu.local',
        phone: phone || null,
        name: null,
        convinience_fee: 0,
        amount: String(amount || '0'),
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
    },
    response_description: 'TRANSACTION FAILED',
    requestId: requestId || null,
    amount: Number(amount || 0),
    transaction_date: new Date().toISOString(),
    purchased_code: ''
  });
}

function success(res, { requestId, amount, serviceID, phone, productName = 'Airtime Recharge', type = 'Airtime Recharge', extra = {} }) {
  return res.json({
    code: '000',
    content: {
      transactions: {
        status: 'delivered',
        product_name: productName,
        unique_element: phone || null,
        unit_price: String(amount || '0'),
        quantity: 1,
        service_verification: null,
        channel: 'api',
        commission: 3.5,
        total_amount: Number(amount || 0) - 3.5,
        discount: null,
        type,
        email: extra.email || 'mock@vtu.local',
        phone: phone || null,
        name: null,
        convinience_fee: 0,
        amount: String(amount || '0'),
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
        ...(extra.meta || {})
      }
    },
    response_description: 'TRANSACTION SUCCESSFUL',
    requestId: requestId || null,
    amount: Number(amount || 0),
    transaction_date: new Date().toISOString(),
    purchased_code: extra.purchased_code || ''
  });
}

function getDataPlans(serviceID) {
  const network = normalizeServiceId(serviceID).replace(/-data$/, '');
  const base = network || 'mtn';
  return [
    { variation_code: `${base}-100mb`, name: `${base.toUpperCase()} 100MB`, variation_amount: 100 },
    { variation_code: `${base}-500mb`, name: `${base.toUpperCase()} 500MB`, variation_amount: 300 },
    { variation_code: `${base}-1gb`, name: `${base.toUpperCase()} 1GB`, variation_amount: 500 },
    { variation_code: `${base}-2gb`, name: `${base.toUpperCase()} 2GB`, variation_amount: 1000 },
    { variation_code: `${base}-5gb`, name: `${base.toUpperCase()} 5GB`, variation_amount: 2500 }
  ];
}

function getCablePlans(serviceID) {
  const provider = normalizeServiceId(serviceID) || 'dstv';
  return [
    { variation_code: `${provider}-compact`, name: `${provider.toUpperCase()} Compact`, variation_amount: 12000 },
    { variation_code: `${provider}-compact-plus`, name: `${provider.toUpperCase()} Compact Plus`, variation_amount: 18900 },
    { variation_code: `${provider}-premium`, name: `${provider.toUpperCase()} Premium`, variation_amount: 24500 }
  ];
}

function getElectricityPlans(serviceID) {
  const disco = normalizeServiceId(serviceID) || 'ikeja-electric';
  return [
    { variation_code: `${disco}-prepaid`, name: `${disco.toUpperCase()} Prepaid`, variation_amount: 1000 },
    { variation_code: `${disco}-postpaid`, name: `${disco.toUpperCase()} Postpaid`, variation_amount: 2000 }
  ];
}

function getGenericPlans(serviceID) {
  const s = normalizeServiceId(serviceID) || 'service';
  return [
    { variation_code: `${s}-basic`, name: `${s.toUpperCase()} Basic`, variation_amount: 100 },
    { variation_code: `${s}-standard`, name: `${s.toUpperCase()} Standard`, variation_amount: 500 },
    { variation_code: `${s}-pro`, name: `${s.toUpperCase()} Pro`, variation_amount: 1000 }
  ];
}

app.get('/', (req, res) => {
  res.json({ success: true, message: 'Mock VTpass API is running', service: 'mock-vtpass' });
});

app.get('/health', (req, res) => {
  res.json({ success: true, message: 'OK' });
});

app.get(['/api/service-variations', '/api/service-variations/'], (req, res) => {
  const serviceID = normalizeServiceId(req.query.serviceID);

  if (!serviceID) {
    return invalidArgs(res, ['serviceID is empty']);
  }

  let variations = [];

  if (serviceID.includes('data')) {
    variations = getDataPlans(serviceID);
  } else if (serviceID.includes('dstv') || serviceID.includes('gotv') || serviceID.includes('startimes') || serviceID.includes('cable')) {
    variations = getCablePlans(serviceID);
  } else if (serviceID.includes('electric')) {
    variations = getElectricityPlans(serviceID);
  } else if (serviceID.includes('airtime')) {
    variations = [
      { variation_code: 'airtime-50', name: 'Airtime 50', variation_amount: 50 },
      { variation_code: 'airtime-100', name: 'Airtime 100', variation_amount: 100 },
      { variation_code: 'airtime-200', name: 'Airtime 200', variation_amount: 200 }
    ];
  } else {
    variations = getGenericPlans(serviceID);
  }

  return ok(res, {
    code: '000',
    content: { variations },
    response_description: 'OK'
  });
});

app.post(['/api/pay', '/api/pay/'], (req, res) => {
  const body = compactObject(req.body || {});
  const requestId = body.request_id || body.requestId || '';
  const serviceID = normalizeServiceId(body.serviceID || body.serviceId || body.service_id);
  const phone = normalizePhone(body.phone || body.billersCode || body.smartcard_number || body.meter_number || body.accountNumber);
  const amount = body.amount ?? body.plan_amount ?? body.variation_amount ?? '';
  const variationCode = String(body.variation_code || body.variationCode || '').trim();

  const errors = [];
  if (!requestId) errors.push('request_id ID is empty');
  if (!serviceID) errors.push('serviceID is empty');

  const isAirtime = serviceID === 'mtn' || serviceID === 'airtel' || serviceID === 'glo' || serviceID === 'etisalat' || serviceID === '9mobile' || serviceID === 'airtime';
  const isData = serviceID.includes('data');
  const isCable = serviceID.includes('dstv') || serviceID.includes('gotv') || serviceID.includes('startimes') || serviceID.includes('cable');
  const isElectricity = serviceID.includes('electric');

  if (isAirtime) {
    if (!phone) errors.push('phone is empty');
    if (amount === '' || amount === null || amount === undefined) errors.push('amount is empty');
  } else if (isData || isCable || isElectricity) {
    if (!phone) errors.push('phone is empty');
    if (!variationCode) errors.push('variation_code is empty');
    if (amount === '' || amount === null || amount === undefined) errors.push('amount is empty');
  } else {
    if (!phone) errors.push('phone is empty');
  }

  if (errors.length) {
    return invalidArgs(res, errors);
  }

  if (String(body.force_fail).toLowerCase() === 'true' || String(body.simulate).toLowerCase() === 'fail') {
    return failed(res, requestId, amount, serviceID, phone, `${serviceID.toUpperCase()} Recharge`, {
      email: body.email,
      type: 'Airtime Recharge'
    });
  }

  const productName = isAirtime
    ? `${serviceID.toUpperCase()} Airtime VTU`
    : isData
      ? `${serviceID.toUpperCase()} Data`
      : isCable
        ? `${serviceID.toUpperCase()} Cable TV`
        : isElectricity
          ? `${serviceID.toUpperCase()} Electricity`
          : `${serviceID.toUpperCase()} Service`;

  const type = isAirtime
    ? 'Airtime Recharge'
    : isData
      ? 'Data Purchase'
      : isCable
        ? 'Cable TV Subscription'
        : isElectricity
          ? 'Electricity Bill Payment'
          : 'Service Purchase';

  return success(res, {
    requestId,
    amount,
    serviceID,
    phone,
    productName,
    type,
    extra: {
      email: body.email,
      purchased_code: body.purchased_code,
      meta: {
        variation_code: variationCode || null,
        billersCode: body.billersCode || null
      }
    }
  });
});

app.post(['/api/requery', '/api/requery/'], (req, res) => {
  const body = compactObject(req.body || {});
  const requestId = String(body.request_id || body.requestId || '').trim();

  if (!requestId) {
    return invalidArgs(res, ['request_id ID is empty']);
  }

  return ok(res, {
    code: '000',
    response_description: 'TRANSACTION SUCCESSFUL',
    content: {
      transactions: {
        status: 'delivered',
        request_id: requestId,
        transactionId: uid('tx_'),
        product_name: 'Mock Requery',
        amount: 0,
        phone: null
      }
    },
    requestId
  });
});

app.post('/debug/echo', (req, res) => {
  res.json({
    success: true,
    headers: req.headers,
    body: req.body
  });
});

app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: 'Route not found',
    path: req.originalUrl
  });
});

app.listen(PORT, () => {
  console.log(`Mock VTpass API running on port ${PORT}`);
});