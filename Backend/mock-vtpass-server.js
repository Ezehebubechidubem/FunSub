const fs = require('fs');
const path = require('path');

const CATALOG_DIR = path.join(__dirname, 'provider-catalog');

function readCatalog(fileName, fallback = []) {
  try {
    const filePath = path.join(CATALOG_DIR, fileName);
    if (!fs.existsSync(filePath)) return fallback;

    const raw = fs.readFileSync(filePath, 'utf8');
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : fallback;
  } catch {
    return fallback;
  }
}

function getPlans(serviceType, serviceID) {
  const type = String(serviceType || '').toLowerCase();

  if (type === 'data') {
    return readCatalog('data.json', []);
  }

  if (type === 'cable_tv') {
    return readCatalog('cable_tv.json', []);
  }

  if (type === 'electricity') {
    return readCatalog('electricity.json', []);
  }

  if (type === 'airtime') {
    return readCatalog('airtime.json', []);
  }

  if (type === 'betting') {
    return readCatalog('betting.json', []);
  }

  if (type === 'recharge_pin') {
    return readCatalog('recharge_pin.json', []);
  }

  if (type === 'data_pin') {
    return readCatalog('data_pin.json', []);
  }

  if (type === 'exam_pin') {
    return readCatalog('exam_pin.json', []);
  }

  return readCatalog('data.json', []);
}