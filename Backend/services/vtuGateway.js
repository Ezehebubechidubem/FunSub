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
            }
          : {
              Authorization: `Bearer ${apiKey}`,
              "Content-Type": "application/json",
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

  async function withFallback(primaryFn, fallbackFn) {
    try {
      return await primaryFn();
    } catch (err) {
      if (!f || !isRetryableError(err)) throw err;
      return await fallbackFn();
    }
  }

  function normalizeDataPlan(item, source = "iacafe") {
    return {
      id: item.variation_id ?? item.data_plan ?? item.id,
      name: item.data_plan ?? item.name ?? item.variation_name ?? "Plan",
      price: Number(item.reseller_price ?? item.price ?? item.api_user_price ?? 0),
      availability: item.availability ?? "Available",
      source,
      meta: item,
    };
  }

  function normalizeCablePlan(item, source = "iacafe") {
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

  async function getPlans({ product, service_id, network_id, provider } = {}) {
    if (product === "data") {
      const regular = await withFallback(
        () => p.get("/variations", { product: "data", service_id }),
        () => f.get("/variations", { product: "data", service_id })
      );

      const budget = await withFallback(
        () => p.get("/budget-data/plans", clean({ network_id, provider })),
        () => f.get("/budget-data/plans", clean({ network_id, provider }))
      ).catch(() => null);

      const regularList = Array.isArray(regular?.data) ? regular.data : [];
      const budgetList = Array.isArray(budget?.data) ? budget.data : [];

      return {
        product: "data",
        service_id,
        plans: [
          ...regularList.map((x) => ({
            ...normalizeDataPlan(x, "regular"),
            purchase_route: "/data",
            purchase_key: x.variation_id,
          })),
          ...budgetList.map((x) => ({
            id: x.data_plan,
            name: x.name,
            price: Number(x.api_user_price ?? 0),
            availability: "Available",
            source: "budget-data",
            meta: x,
            purchase_route: "/budget-data",
            purchase_key: x.data_plan,
          })),
        ],
      };
    }

    if (product === "cable") {
      const cable = await withFallback(
        () => p.get("/variations", { product: "cable", service_id }),
        () => f.get("/variations", { product: "cable", service_id })
      );

      const list = Array.isArray(cable?.data) ? cable.data : [];
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

    // airtime / electricity / betting / epins
    const response = await withFallback(
      () => p.get("/providers"),
      () => f.get("/providers")
    );

    return response;
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

  async function buyData({ request_id, phone, plan }) {
    const body = {
      request_id: request_id || makeRequestId("DATA"),
      phone,
    };

    if (!plan) throw new Error("Plan is required");

    // If plan came from /budget-data/plans, buy with /budget-data
    if (plan.purchase_route === "/budget-data") {
      body.data_plan = plan.purchase_key;
      return withFallback(
        () => p.post("/budget-data", body),
        () => f.post("/budget-data", body)
      );
    }

    // Regular data variation buy
    body.variation_id = plan.purchase_key;
    body.service_id = plan.meta?.service_id || plan.meta?.serviceId || plan.meta?.network || plan.service_id;
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

  async function buyBetting({ request_id, customer_id, service_id, amount }) {
    const body = {
      request_id: request_id || makeRequestId("BETTING"),
      customer_id,
      service_id,
      amount,
    };

    return withFallback(
      () => p.post("/betting", body),
      () => f.post("/betting", body)
    );
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
    getPlans,
    buyAirtime,
    buyData,
    buyCable,
    buyElectricity,
    buyBetting,
    requery,
  };
}

module.exports = { createVtuGateway, makeRequestId };