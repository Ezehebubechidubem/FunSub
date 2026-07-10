// services/vtuGateway.js
const axios = require("axios");
const crypto = require("crypto");

function makeRequestId(prefix = "FUNSUB") {
  return `${prefix}_${Date.now()}_${crypto.randomBytes(4).toString("hex")}`;
}

function isRetryableError(err) {
  const status = err?.response?.status;
  if (!status) return true; // network / timeout / DNS
  return status >= 500 || status === 408 || status === 425 || status === 429;
}

function clean(obj = {}) {
  const out = {};
  for (const [k, v] of Object.entries(obj)) {
    if (v !== undefined && v !== null && v !== "") out[k] = v;
  }
  return out;
}

function pickArray(data) {
  if (Array.isArray(data)) return data;
  if (Array.isArray(data?.data)) return data.data;
  if (Array.isArray(data?.plans)) return data.plans;
  if (Array.isArray(data?.items)) return data.items;
  if (Array.isArray(data?.result)) return data.result;
  if (Array.isArray(data?.response)) return data.response;
  if (Array.isArray(data?.content?.variations)) return data.content.variations;
  if (Array.isArray(data?.data?.content?.variations)) return data.data.content.variations;
  if (Array.isArray(data?.data?.variations)) return data.data.variations;
  if (Array.isArray(data?.variations)) return data.variations;
  return [];
}

function normalizeText(value) {
  return String(value || "").trim().toLowerCase();
}

function isSuccessfulResponse(data) {
  if (!data) return false;

  if (data.success === true) return true;

  const status = normalizeText(data.status || data.response_status || data.state);
  const code = normalizeText(data.code || data.response_code || data.responseCode);
  const message = normalizeText(data.message || data.response_description || data.description);

  if (
    status === "success" ||
    status === "successful" ||
    status === "completed" ||
    status === "complete" ||
    status === "paid" ||
    status === "ok"
  ) {
    return true;
  }

  if (code === "000" || code === "00" || code === "0") return true;
  if (message.includes("success")) return true;

  return false;
}

function getErrorCode(data) {
  return normalizeText(
    data?.error?.code ||
      data?.code ||
      data?.error_code ||
      data?.response_code ||
      data?.responseCode
  );
}

function getErrorMessage(data) {
  return String(
    data?.error?.message ||
      data?.message ||
      data?.response_description ||
      data?.description ||
      "Request failed"
  ).trim();
}

class ProviderClient {
  constructor({ name, baseURL, apiKey, authType = "bearer", timeout = 30000 }) {
    if (!name) throw new Error("Provider name is required");
    if (!baseURL) throw new Error(`Missing baseURL for ${name}`);
    if (!apiKey) throw new Error(`Missing apiKey for ${name}`);

    this.name = name;
    this.http = axios.create({
      baseURL: String(baseURL).replace(/\/$/, ""),
      timeout,
      headers:
        String(authType).toLowerCase() === "x-api-key"
          ? {
              "X-API-Key": apiKey,
              "Content-Type": "application/json",
              Accept: "application/json",
            }
          : {
              Authorization: `Bearer ${apiKey}`,
              "Content-Type": "application/json",
              Accept: "application/json",
            },
    });
  }

  get(path, params) {
    return this.http.get(path, { params }).then((r) => r.data);
  }

  post(path, body) {
    return this.http.post(path, clean(body)).then((r) => r.data);
  }
}

function createVtuGateway({ primary, fallback }) {
  const p = new ProviderClient(primary);
  const f = fallback ? new ProviderClient(fallback) : null;

  const primaryBettingVerifyPath = primary?.bettingVerifyPath || "/verify-customer";
  const primaryBettingBuyPath = primary?.bettingBuyPath || "/betting";

  const fallbackBettingVerifyPath = fallback?.bettingVerifyPath || "/verify-customer";
  const fallbackBettingBuyPath = fallback?.bettingBuyPath || "/betting";

  async function withFallback(primaryFn, fallbackFn) {
    try {
      return await primaryFn();
    } catch (err) {
      if (!f || !isRetryableError(err)) throw err;
      return await fallbackFn();
    }
  }

  function normalizeDataPlan(item, source = "primary") {
    return {
      id: item.variation_id ?? item.data_plan ?? item.id ?? item.code,
      name: item.data_plan ?? item.name ?? item.variation_name ?? "Plan",
      price: Number(item.reseller_price ?? item.price ?? item.api_user_price ?? item.amount ?? 0),
      availability: item.availability ?? "Available",
      source,
      meta: item,
    };
  }

  function normalizeCablePlan(item, source = "primary") {
    return {
      id: item.variation_id ?? item.id ?? item.code,
      name: item.name ?? item.variation_name ?? "Plan",
      price: Number(item.reseller_price ?? item.price ?? item.amount ?? 0),
      availability: item.availability ?? "Available",
      source,
      meta: item,
    };
  }

  async function getProviders() {
    return withFallback(
      () => p.get("/providers"),
      () => f.get("/providers")
    );
  }

  async function getVariations({ product, service_id } = {}) {
    if (!product) throw new Error("product is required");
    return withFallback(
      () => p.get("/variations", { product, service_id }),
      () => f.get("/variations", { product, service_id })
    );
  }

  async function getBudgetPlans({ network_id, provider } = {}) {
    return withFallback(
      () => p.get("/budget-data/plans", clean({ network_id, provider })),
      () => f.get("/budget-data/plans", clean({ network_id, provider }))
    );
  }

  async function getPlans({ product, service_id, network_id, provider } = {}) {
    if (product === "data") {
      const regular = await getVariations({ product: "data", service_id }).catch(() => null);
      const budget = await getBudgetPlans({ network_id, provider }).catch(() => null);

      const regularList = pickArray(regular);
      const budgetList = pickArray(budget);

      return {
        product: "data",
        service_id,
        plans: [
          ...regularList.map((x) => ({
            ...normalizeDataPlan(x, "regular"),
            purchase_route: "/data",
            purchase_key: x.variation_id ?? x.id ?? x.code,
          })),
          ...budgetList.map((x) => ({
            id: x.data_plan ?? x.id ?? x.code,
            name: x.name ?? x.data_plan ?? "Plan",
            price: Number(x.api_user_price ?? x.price ?? 0),
            availability: "Available",
            source: "budget-data",
            meta: x,
            purchase_route: "/budget-data",
            purchase_key: x.data_plan ?? x.id ?? x.code,
          })),
        ],
      };
    }

    if (product === "cable") {
      const cable = await getVariations({ product: "cable", service_id }).catch(() => null);
      const list = pickArray(cable);

      return {
        product: "cable",
        service_id,
        plans: list.map((x) => ({
          ...normalizeCablePlan(x, "cable"),
          purchase_route: "/cable",
          purchase_key: x.variation_id ?? x.id ?? x.code,
        })),
      };
    }

    return getProviders();
  }

  async function buyAirtime({ request_id, phone, service_id, amount }) {
    const body = {
      request_id: request_id || makeRequestId("AIRTIME"),
      phone,
      service_id,
      amount,
    };

    return withFallback(
      () => p.post("/airtime", body),
      () => f.post("/airtime", body)
    );
  }

  async function buyBudgetData({ request_id, phone, data_plan }) {
    const body = {
      request_id: request_id || makeRequestId("BUDGETDATA"),
      phone,
      data_plan,
    };

    return withFallback(
      () => p.post("/budget-data", body),
      () => f.post("/budget-data", body)
    );
  }

  async function buyData({ request_id, phone, plan, service_id }) {
    if (!plan) throw new Error("Plan is required");

    const body = {
      request_id: request_id || makeRequestId("DATA"),
      phone,
    };

    if (plan.purchase_route === "/budget-data") {
      body.data_plan = plan.purchase_key ?? plan.id;
      return buyBudgetData(body);
    }

    body.variation_id = plan.purchase_key ?? plan.id;
    body.service_id = service_id || plan.meta?.service_id || plan.meta?.serviceId || plan.meta?.network;

    return withFallback(
      () => p.post("/data", body),
      () => f.post("/data", body)
    );
  }

  async function buyCable({ request_id, customer_id, service_id, plan }) {
    const body = {
      request_id: request_id || makeRequestId("CABLE"),
      customer_id,
      service_id,
      variation_id: plan?.purchase_key ?? plan?.id,
    };

    return withFallback(
      () => p.post("/cable", body),
      () => f.post("/cable", body)
    );
  }

  async function buyElectricity(payload) {
    const body = {
      request_id: payload.request_id || makeRequestId("ELECTRICITY"),
      ...payload,
    };

    return withFallback(
      () => p.post("/electricity", body),
      () => f.post("/electricity", body)
    );
  }

  async function buyBetting({
    request_id,
    customer_id,
    service_id,
    amount,
    skip_verify = false,
  }) {
    const verifyPayload = {
      customer_id,
      service_id,
    };

    if (!skip_verify) {
      const verification = await withFallback(
        () => p.post(primaryBettingVerifyPath, verifyPayload),
        () => f.post(fallbackBettingVerifyPath, verifyPayload)
      );

      if (!isSuccessfulResponse(verification)) {
        const code = getErrorCode(verification);
        const message = getErrorMessage(verification);

        const err = new Error(message || "Betting verification failed");
        err.response = { data: verification };

        if (code === "customer_not_found") {
          err.code = "customer_not_found";
          throw err;
        }

        throw err;
      }
    }

    const body = {
      request_id: request_id || makeRequestId("BETTING"),
      customer_id,
      service_id,
      amount,
    };

    return withFallback(
      () => p.post(primaryBettingBuyPath, body),
      () => f.post(fallbackBettingBuyPath, body)
    );
  }

  async function verifyBettingCustomer({ customer_id, service_id }) {
    const body = {
      customer_id,
      service_id,
    };

    const verification = await withFallback(
      () => p.post(primaryBettingVerifyPath, body),
      () => f.post(fallbackBettingVerifyPath, body)
    );

    if (!isSuccessfulResponse(verification)) {
      const code = getErrorCode(verification);
      const message = getErrorMessage(verification);
      const err = new Error(message || "Betting verification failed");
      err.response = { data: verification };
      if (code) err.code = code;
      throw err;
    }

    return verification;
  }

  async function requery(request_id) {
    return withFallback(
      () => p.post("/requery", { request_id }),
      () => f.post("/requery", { request_id })
    );
  }

  return {
    primary: p.name,
    fallback: f?.name || null,
    getProviders,
    getVariations,
    getBudgetPlans,
    getPlans,
    buyAirtime,
    buyBudgetData,
    buyData,
    buyCable,
    buyElectricity,
    buyBetting,
    verifyBettingCustomer,
    requery,
  };
}

function createIacafeGateway({ baseURL, apiKey, authType = "bearer", timeout = 30000, fallback } = {}) {
  return createVtuGateway({
    primary: {
      name: "iacafe",
      baseURL,
      apiKey,
      authType,
      timeout,
      bettingVerifyPath: "/verify-customer",
      bettingBuyPath: "/betting",
    },
    fallback: fallback
      ? {
          name: fallback.name || "fallback",
          baseURL: fallback.baseURL,
          apiKey: fallback.apiKey,
          authType: fallback.authType || "bearer",
          timeout: fallback.timeout || timeout,
          bettingVerifyPath: fallback.bettingVerifyPath || "/verify-customer",
          bettingBuyPath: fallback.bettingBuyPath || "/betting",
        }
      : null,
  });
}

module.exports = {
  createVtuGateway,
  createIacafeGateway,
  makeRequestId,
  isRetryableError,
};