const express = require("express");

function toNumber(value, fallback = 0) {
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
}

function getUserId(reqUser) {
  return reqUser?.id || reqUser?.userId || null;
}

function createAgentRouter({
  pool,
  requireAuth,
  respondOk,
  respondError,
  uid,
  addNotification,
  verifyFundPin
}) {
  if (!pool) throw new Error("pool is required");
  if (typeof requireAuth !== "function") throw new Error("requireAuth is required");
  if (typeof respondOk !== "function") throw new Error("respondOk is required");
  if (typeof respondError !== "function") throw new Error("respondError is required");
  if (typeof uid !== "function") throw new Error("uid is required");
  if (typeof verifyFundPin !== "function") throw new Error("verifyFundPin is required");

  const router = express.Router();

  router.get("/config", requireAuth, async (_req, res) => {
    try {
      return respondOk(
        res,
        {
          config: {
            title: "Upgrade to Agent",
            subtitle: "Unlock cheaper data plans, better discounts, and priority access.",
            upgrade_amount: toNumber(process.env.AGENT_UPGRADE_AMOUNT, 4000),
            currency: "NGN",
            benefits: [
              "Cheaper data plans",
              "Better discount rates",
              "Priority access to agent pricing",
              "Automatic upgrade after PIN verification"
            ]
          }
        },
        "Agent config loaded"
      );
    } catch (err) {
      return respondError(res, 500, err?.message || "Unable to load agent config");
    }
  });

  router.get("/status", requireAuth, async (req, res) => {
    try {
      const userId = getUserId(req.user);
      if (!userId) return respondError(res, 401, "Unauthorized");

      const result = await pool.query(
        `SELECT
           u.id,
           u.role,
           u.full_name,
           u.email,
           COALESCE(w.balance, 0) AS wallet_balance,
           COALESCE(w.currency, 'NGN') AS wallet_currency
         FROM users u
         LEFT JOIN wallets w ON w.user_id = u.id
         WHERE u.id = $1
         LIMIT 1`,
        [userId]
      );

      const row = result.rows[0];
      if (!row) return respondError(res, 404, "User not found");

      const isAgent = String(row.role || "").toLowerCase() === "agent";

      return respondOk(
        res,
        {
          agent: {
            user_id: row.id,
            full_name: row.full_name,
            email: row.email,
            role: row.role,
            is_agent: isAgent,
            wallet_balance: Number(row.wallet_balance || 0),
            wallet_currency: row.wallet_currency || "NGN"
          }
        },
        "Agent status loaded"
      );
    } catch (err) {
      return respondError(res, 500, err?.message || "Unable to load agent status");
    }
  });
router.post("/upgrade", requireAuth, async (req, res) => {
    const client = await pool.connect();

    try {
      const userId = getUserId(req.user);
      if (!userId) return respondError(res, 401, "Unauthorized");

      const amountToDeduct = toNumber(process.env.AGENT_UPGRADE_AMOUNT, 4000);
      const fundPin = String(req.body?.fundPin || req.body?.fund_pin || "").trim();

      if (!fundPin) {
        return respondError(res, 400, "Transaction PIN is required");
      }

      const pinOk = await verifyFundPin(userId, fundPin);
      if (!pinOk) {
        return respondError(res, 401, "Invalid transaction PIN");
      }

      await client.query("BEGIN");

      const userResult = await client.query(
        `SELECT
           u.id,
           u.role,
           u.full_name,
           u.email,
           COALESCE(w.balance, 0) AS wallet_balance,
           w.id AS wallet_id
         FROM users u
         LEFT JOIN wallets w ON w.user_id = u.id
         WHERE u.id = $1
         FOR UPDATE`,
        [userId]
      );

      const userRow = userResult.rows[0];
      if (!userRow) {
        await client.query("ROLLBACK");
        return respondError(res, 404, "User not found");
      }

      if (String(userRow.role || "").toLowerCase() === "agent") {
        await client.query("ROLLBACK");
        return respondOk(res, { already_agent: true }, "Account is already an Agent");
      }

      if (!userRow.wallet_id) {
        await client.query("ROLLBACK");
        return respondError(res, 404, "Wallet not found");
      }

      const walletBalance = Number(userRow.wallet_balance || 0);
      if (walletBalance < amountToDeduct) {
        await client.query("ROLLBACK");
        return respondError(res, 400, "Insufficient wallet balance for agent upgrade");
      }

      const newBalance = walletBalance - amountToDeduct;

      await client.query(
        `UPDATE wallets
         SET balance = balance - $2,
             updated_at = NOW()
         WHERE user_id = $1`,
        [userId, amountToDeduct]
      );

      await client.query(
        `UPDATE users
         SET role = 'agent',
             updated_at = NOW()
         WHERE id = $1`,
        [userId]
      );

      const reference = `AGENT_${Date.now()}_${uid("ref_")}`;
      const txId = uid("tx_");

      const insertedTx = await client.query(
        `INSERT INTO transactions
         (id, user_id, type, category, amount, currency, status, reference, description, meta, created_at)
         VALUES
         ($1, $2, $3, $4, $5, $6, 'success', $7, $8, $9, NOW())
         RETURNING *`,
        [
          txId,
          userId,
          "debit",
          "agent_upgrade",
          amountToDeduct,
          "NGN",
          reference,
          "Agent upgrade",
          JSON.stringify({
            service: "agent_upgrade",
            upgrade_amount: amountToDeduct,
            previous_role: userRow.role || "subscriber",
            new_role: "agent"
          })
        ]
      );

      await client.query("COMMIT");

      if (typeof addNotification === "function") {
        try {
          await addNotification(
            userId,
            "Agent upgrade successful",
            `Your account has been upgraded to Agent. ₦${Number(amountToDeduct).toLocaleString("en-NG")} was deducted from your wallet.`,
            {
              transactionId: txId,
              reference,
              amount: amountToDeduct,
              newRole: "agent"
            },
            true
          );
        } catch (notifyErr) {
          console.error("addNotification failed:", notifyErr?.message);
        }
      }

      return respondOk(
        res,
        {
          message: "Account upgraded to Agent successfully",
          agent: {
            role: "agent",
            is_agent: true
          },
          wallet: {
            balance: newBalance,
            currency: "NGN"
          },
          transaction: insertedTx.rows[0]
        },
        "Account upgraded to Agent successfully"
      );
    } catch (err) {
      try {
        await client.query("ROLLBACK");
      } catch (_) {}
      console.error("AGENT UPGRADE ERROR:", err);
      return respondError(res, 500, err?.message || "Unable to upgrade account");
    } finally {
      client.release();
    }
  });

  return router;
}

module.exports = {
  createAgentRouter
};