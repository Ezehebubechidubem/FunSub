function normalizeServiceId(v) {
  return String(v || '').trim().toLowerCase();
}

function uid(prefix = '') {
  return `${prefix}${Date.now()}${Math.floor(Math.random() * 100000)}`;
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

function getPlans(serviceType, serviceID) {
  const type = normalizeServiceId(serviceType);

  if (type === 'data') return getDataPlans(serviceID);
  if (type === 'cable_tv') return getCablePlans(serviceID);
  if (type === 'electricity') return getElectricityPlans(serviceID);
  if (type === 'airtime') {
    return [
      { variation_code: 'airtime-50', name: 'Airtime 50', variation_amount: 50 },
      { variation_code: 'airtime-100', name: 'Airtime 100', variation_amount: 100 },
      { variation_code: 'airtime-200', name: 'Airtime 200', variation_amount: 200 }
    ];
  }

  return getGenericPlans(serviceID);
}

function buySuccess({ request_id, serviceID, phone, amount, variation_code, serviceType, email }) {
  const amt = Number(amount || 0);

  return {
    code: '000',
    response_description: 'TRANSACTION SUCCESSFUL',
    requestId: request_id || uid('req_'),
    amount: amt,
    transaction_date: new Date().toISOString(),
    purchased_code: '',
    content: {
      transactions: {
        status: 'delivered',
        product_name: `${String(serviceID || serviceType || 'Service').toUpperCase()} ${serviceType === 'airtime' ? 'Airtime VTU' : serviceType === 'data' ? 'Data' : serviceType === 'cable_tv' ? 'Cable TV' : serviceType === 'electricity' ? 'Electricity' : 'Service'}`,
        unique_element: phone || null,
        unit_price: String(amt),
        quantity: 1,
        service_verification: null,
        channel: 'api',
        commission: 3.5,
        total_amount: amt - 3.5,
        discount: null,
        type: serviceType === 'data' ? 'Data Purchase' : serviceType === 'cable_tv' ? 'Cable TV Subscription' : serviceType === 'electricity' ? 'Electricity Bill Payment' : 'Airtime Recharge',
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

function buyFail({ request_id, serviceID, phone, amount, serviceType, email }) {
  const amt = Number(amount || 0);

  return {
    code: '016',
    response_description: 'TRANSACTION FAILED',
    requestId: request_id || uid('req_'),
    amount: amt,
    transaction_date: new Date().toISOString(),
    purchased_code: '',
    content: {
      transactions: {
        status: 'failed',
        product_name: `${String(serviceID || serviceType || 'Service').toUpperCase()} Service`,
        unique_element: phone || null,
        unit_price: String(amt),
        quantity: 1,
        service_verification: null,
        channel: 'api',
        commission: 3.5,
        total_amount: amt - 3.5,
        discount: null,
        type: serviceType === 'data' ? 'Data Purchase' : 'Airtime Recharge',
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

function requery(request_id) {
  return {
    code: '000',
    response_description: 'TRANSACTION SUCCESSFUL',
    content: {
      transactions: {
        status: 'delivered',
        request_id: request_id || uid('req_'),
        transactionId: uid('tx_'),
        product_name: 'Mock Requery',
        amount: 0,
        phone: null
      }
    },
    requestId: request_id || null
  };
}

module.exports = {
  getPlans,
  getDataPlans,
  getCablePlans,
  getElectricityPlans,
  buySuccess,
  buyFail,
  requery
};