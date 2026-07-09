const DEFAULT_MARKUP_PERCENT = toNumber(process.env.DEFAULT_MARKUP_PERCENT, 1);

const SERVICE_MARKUP_DEFAULTS = {
airtime: toNumber(process.env.AIRTIME_MARKUP_PERCENT, 1),
data: toNumber(process.env.DATA_MARKUP_PERCENT, 1.5),
cable_tv: toNumber(process.env.CABLE_TV_MARKUP_PERCENT, DEFAULT_MARKUP_PERCENT),
electricity: toNumber(process.env.ELECTRICITY_MARKUP_PERCENT, DEFAULT_MARKUP_PERCENT),
betting: toNumber(process.env.BETTING_MARKUP_PERCENT, DEFAULT_MARKUP_PERCENT),
recharge_pin: toNumber(process.env.RECHARGE_PIN_MARKUP_PERCENT, DEFAULT_MARKUP_PERCENT),
data_pin: toNumber(process.env.DATA_PIN_MARKUP_PERCENT, DEFAULT_MARKUP_PERCENT),
exam_pin: toNumber(process.env.EXAM_PIN_MARKUP_PERCENT, DEFAULT_MARKUP_PERCENT)
};

const MARKUP_BANDS = [
{ key: '0_500', min: 0, max: 500 },
{ key: '501_1000', min: 501, max: 1000 },
{ key: '1001_5000', min: 1001, max: 5000 },
{ key: '5001_20000', min: 5001, max: 20000 },
{ key: '20001_50000', min: 20001, max: 50000 },
{ key: '50001_150000', min: 50001, max: 150000 },
{ key: '150001_300000', min: 150001, max: 300000 },
{ key: '300001_ABOVE', min: 300001, max: Infinity }
];

function toNumber(value, fallback = 0) {
const n = Number(value);
return Number.isFinite(n) ? n : fallback;
}

function normalizeServiceType(value) {
const s = String(value || '').trim().toLowerCase();

const map = {
cable: 'cable_tv',
'cable-tv': 'cable_tv',
cabletv: 'cable_tv',
cable_tv: 'cable_tv',
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

function getAmountBandKey(amount) {
const value = toNumber(amount, 0);

for (const band of MARKUP_BANDS) {
if (value >= band.min && value <= band.max) {
return band.key;
}
}

return '300001_ABOVE';
}

function normalizeDataNetwork(value) {
const s = String(value || '').trim().toLowerCase();

const map = {
mtn: 'MTN',
glo: 'GLO',
airtel: 'AIRTEL',
'9mobile': 'MOBILE',
mobile: 'MOBILE',
etisalat: 'MOBILE'
};

return map[s] || null;
}

function normalizeCableProvider(value) {
const s = String(value || '').trim().toLowerCase();

const map = {
dstv: 'DSTV',
gotv: 'GOTV',
startimes: 'STARTIMES',
showmax: 'SHOWMAX'
};

return map[s] || null;
}

function readPercentDetail(keys, fallbackPercent = DEFAULT_MARKUP_PERCENT) {
for (const key of keys) {
const raw = process.env[key];
const num = Number(raw);

if (  
  raw !== undefined &&  
  raw !== null &&  
  String(raw).trim() !== '' &&  
  Number.isFinite(num)  
) {  
  return {  
    key,  
    percent: num,  
    source: 'env'  
  };  
}

}

return {
key: null,
percent: toNumber(fallbackPercent, DEFAULT_MARKUP_PERCENT),
source: 'fallback'
};
}

function getTieredMarkupPercent(serviceType, baseAmount, options = {}) {
const normalized = normalizeServiceType(serviceType);
const bandKey = getAmountBandKey(baseAmount);

if (normalized === 'data') {
const network = normalizeDataNetwork(
options.network || options.service_id || options.serviceId || options.provider || options.networkId
);

const candidates = [];  

if (network) {  
  candidates.push(`${network}_DATA_MARKUP_${bandKey}`);  

  if (network === 'MOBILE') {  
    candidates.push(`9MOBILE_DATA_MARKUP_${bandKey}`);  
  }  
}  

candidates.push(  
  `DATA_MARKUP_${bandKey}`,  
  `DATA_MARKUP_PERCENT`  
);  

const result = readPercentDetail(candidates, SERVICE_MARKUP_DEFAULTS.data);  

console.log('MARKUP DEBUG:', {  
  serviceType: normalized,  
  baseAmount: toNumber(baseAmount, 0),  
  bandKey,  
  network,  
  candidates,  
  selectedKey: result.key,  
  selectedPercent: result.percent,  
  source: result.source  
});  

return result.percent;

}

if (normalized === 'cable_tv') {
const provider = normalizeCableProvider(
options.provider || options.service_id || options.serviceId || options.network
);

const candidates = [];  

if (provider) {  
  candidates.push(`${provider}_CABLE_MARKUP_${bandKey}`);  
}  

candidates.push(  
  `CABLE_TV_MARKUP_${bandKey}`,  
  `CABLE_TV_MARKUP_PERCENT`  
);  

const result = readPercentDetail(candidates, SERVICE_MARKUP_DEFAULTS.cable_tv);  

console.log('MARKUP DEBUG:', {  
  serviceType: normalized,  
  baseAmount: toNumber(baseAmount, 0),  
  bandKey,  
  provider,  
  candidates,  
  selectedKey: result.key,  
  selectedPercent: result.percent,  
  source: result.source  
});  

return result.percent;

}

const percent = SERVICE_MARKUP_DEFAULTS[normalized] ?? DEFAULT_MARKUP_PERCENT;

console.log('MARKUP DEBUG:', {
serviceType: normalized,
baseAmount: toNumber(baseAmount, 0),
bandKey: null,
candidates: [],
selectedKey: null,
selectedPercent: percent,
source: 'service_default'
});

return percent;
}

function getMarkupPercent(serviceType, baseAmount, options = {}) {
return getTieredMarkupPercent(serviceType, baseAmount, options);
}

function applyMarkup(serviceType, baseAmount, options = {}) {
const markupPercent = getMarkupPercent(serviceType, baseAmount, options);
const base = toNumber(baseAmount, 0);
const fee = (base * markupPercent) / 100;
const finalPrice = base + fee;

const result = {
serviceType: normalizeServiceType(serviceType),
basePrice: Number(base.toFixed(2)),
markupPercent: Number(markupPercent.toFixed(2)),
markupFee: Number(fee.toFixed(2)),
finalPrice: Number(finalPrice.toFixed(2))
};

console.log('APPLY MARKUP:', {
serviceType: result.serviceType,
basePrice: result.basePrice,
markupPercent: result.markupPercent,
markupFee: result.markupFee,
finalPrice: result.finalPrice
});

return result;
}

module.exports = {
normalizeServiceType,
getAmountBandKey,
getMarkupPercent,
applyMarkup
};