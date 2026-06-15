// services/vtuGateway.js
const axios = require("axios");
const { randomUUID } = require("crypto");

function makeRequestId(prefix = "FUNSUB") {
  return `${prefix}_${Date.now()}_${randomUUID().slice(0, 8)}`;
}

function buildHeaders({ apiKey, authType = "bearer" }) {
  if (!apiKey) throw new Error("Missing apiKey");

  if (authType.toLowerCase() === "x-api-key") {
    return {
      "X-API-Key": apiKey,
      "Content-Type": "application/json",
    };
  }

  return {
    Authorization: `Bearer ${apiKey}`,
    "Content-Type": "application/json",
  };
}

class ProviderClient {
  constructor({ name, baseURL, apiKey, authType = "bearer", timeout = 30000 }) {
    if (!name) throw new Error("Provider name is required");
    if (!baseURL) throw new Error(`Missing baseURL for ${name}`);
    if (!apiKey) throw new Error(`Missing apiKey for ${name}`);

    this.name = name;
    this.http = axios.create({
      baseURL,
      timeout,
      headers: buildHeaders({ apiKey, authType }),
    });
  }

  async get(path, params = {}) {
    const res = await this.http.get(path, { params });
    return res.data;
  }

  async post(path, body = {}) {
    const res = await this.http.post(path, body);
    return res.data;
  }
}

function isRetryableError(err) {
  const status = err?.response?.status;

  if (!status) return true; // network, timeout, DNS, etc.
  return status >= 500 || status === 408 || status === 425 || status === 429;
}

function pickFirstDefined(...values) {
  return values.find((v) => v !== undefined && v !== null);
}

function normalizeAirtimePayload(payload = {}) {
  return {
    request_id: pickFirstDefined(payload.request_id, makeRequestId("AIRTIME")),
    phone: payload.phone,
    service_id: payload.service_id,
    amount: payload.amount,
  };
}

function normalizeBudgetDataPayload(payload = {}) {
  return {
    request_id: pickFirstDefined(payload.request_id, makeRequestId("BUDGET")),
    phone: payload.phone,
    data_plan: payload.data_plan,
  };
}

function normalizeBettingPayload(payload = {}) {
  return {
    request_id: pickFirstDefined(payload.request_id, makeRequestId("BET")),
    customer_id: payload.customer_id,
    service_id: payload.service_id,
    amount: payload.amount,
  };
}

function normalizeGenericPayload(payload = {}) {
  return {
    request_id: pickFirstDefined(payload.request_id, makeRequestId("VTU")),
    ...payload,
  };
}

function createVtuGateway({ primary, fallback }) {
  const primaryClient = new ProviderClient(primary);
  const fallbackClient = fallback ? new ProviderClient(fallback) : null;

  async function withFallback(primaryFn, fallbackFn) {
    try {
      return await primaryFn();
    } catch (err) {
      if (!fallbackClient || !isRetryableError(err)) {
        throw err;
      }
      return await fallbackFn();
    }
  }

  return {
    primary: primaryClient.name,
    fallback: fallbackClient?.name || null,

    health() {
      return primaryClient.get("/ping");
    },

    whoami() {
      return withFallback(
        () => primaryClient.get("/whoami"),
        () => fallbackClient.get("/whoami")
      );
    },

    balance() {
      return withFallback(
        () => primaryClient.get("/balance"),
        () => fallbackClient.get("/balance")
      );
    },

    wallet() {
      return withFallback(
        () => primaryClient.get("/wallet"),
        () => fallbackClient.get("/wallet")
      );
    },

    getProviders() {
      return withFallback(
        () => primaryClient.get("/providers"),
        () => fallbackClient.get("/providers")
      );
    },

    getVariations({ product, service_id }) {
      return withFallback(
        () => primaryClient.get("/variations", { product, service_id }),
        () => fallbackClient.get("/variations", { product, service_id })
      );
    },

    getBudgetDataPlans(params = {}) {
      return withFallback(
        () => primaryClient.get("/budget-data/plans", params),
        () => fallbackClient.get("/budget-data/plans", params)
      );
    },

    buyAirtime(payload) {
      const body = normalizeAirtimePayload(payload);

      return withFallback(
        () => primaryClient.post("/airtime", body),
        () => fallbackClient.post("/airtime", body)
      );
    },

    buyBudgetData(payload) {
      const body = normalizeBudgetDataPayload(payload);

      return withFallback(
        () => primaryClient.post("/budget-data", body),
        () => fallbackClient.post("/budget-data", body)
      );
    },

    buyBetting(payload) {
      const body = normalizeBettingPayload(payload);

      return withFallback(
        () => primaryClient.post("/betting", body),
        () => fallbackClient.post("/betting", body)
      );
    },

    buyElectricity(payload) {
      const body = normalizeGenericPayload(payload);

      return withFallback(
        () => primaryClient.post("/electricity", body),
        () => fallbackClient.post("/electricity", body)
      );
    },

    buyCable(payload) {
      const body = normalizeGenericPayload(payload);

      return withFallback(
        () => primaryClient.post("/cable", body),
        () => fallbackClient.post("/cable", body)
      );
    },

    buyTv(payload) {
      const body = normalizeGenericPayload(payload);

      return withFallback(
        () => primaryClient.post("/tv", body),
        () => fallbackClient.post("/tv", body)
      );
    },

    verifyCustomer(payload) {
      const body = normalizeGenericPayload(payload);

      return withFallback(
        () => primaryClient.post("/verify-customer", body),
        () => fallbackClient.post("/verify-customer", body)
      );
    },

    requery(payload) {
      const body = normalizeGenericPayload(payload);

      return withFallback(
        () => primaryClient.post("/requery", body),
        () => fallbackClient.post("/requery", body)
      );
    },
  };
}

module.exports = {
  createVtuGateway,
  makeRequestId,
};