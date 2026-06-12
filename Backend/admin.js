/* ADMIN */

app.get('/api/admin/dashboard', requireAdmin, async (req, res) => {
  try {
    const users = await query('SELECT COUNT(*)::int AS count FROM users');
    const wallets = await query('SELECT COALESCE(SUM(balance), 0) AS total FROM wallets');
    const txns = await query('SELECT COUNT(*)::int AS count FROM transactions');
    const kycPending = await query("SELECT COUNT(*)::int AS count FROM kyc_requests WHERE status = 'pending'");
    const unread = await query("SELECT COUNT(*)::int AS count FROM notifications WHERE is_read = false");

    await query(
      `INSERT INTO admin_logs (id, admin_id, action, meta, created_at)
       VALUES ($1,$2,$3,$4,NOW())`,
      [uid('log_'), req.user.id, 'view_dashboard', JSON.stringify({})]
    );

    return respondOk(res, {
      stats: {
        users: users.rows[0]?.count || 0,
        totalWalletBalance: Number(wallets.rows[0]?.total || 0).toFixed(2),
        transactions: txns.rows[0]?.count || 0,
        pendingKyc: kycPending.rows[0]?.count || 0,
        unreadNotifications: unread.rows[0]?.count || 0
      }
    });
  } catch (err) {
    console.error(err);
    return respondError(res, 500, 'Server error');
  }
});

app.get('/api/admin/users', requireAdmin, async (req, res) => {
  try {
    const result = await query(
      `SELECT id, role, full_name, email, phone, state, avatar_url, kyc_status, profile_complete, online, created_at, updated_at
       FROM users
       ORDER BY created_at DESC
       LIMIT 300`
    );
    return respondOk(res, { users: result.rows });
  } catch (err) {
    console.error(err);
    return respondError(res, 500, 'Server error');
  }
});

app.get('/api/admin/users', requireAdmin, async (req, res) => {
  try {
    const result = await query(
      `SELECT id, role, full_name, email, phone, state, avatar_url, kyc_status, profile_complete, online, created_at, updated_at
       FROM users
       ORDER BY created_at DESC
       LIMIT 300`
    );
    return respondOk(res, { users: result.rows });
  } catch (err) {
    console.error(err);
    return respondError(res, 500, 'Server error');
  }
});

app.get('/api/admin/users', requireAdmin, async (req, res) => {
  try {
    const result = await query(
      `SELECT id, role, full_name, email, phone, state, avatar_url, kyc_status, profile_complete, online, created_at, updated_at
       FROM users
       ORDER BY created_at DESC
       LIMIT 300`
    );
    return respondOk(res, { users: result.rows });
  } catch (err) {
    console.error(err);
    return respondError(res, 500, 'Server error');
  }
});

app.get('/api/admin/users/:id', requireAdmin, async (req, res) => {
  try {
    const result = await query(
      `SELECT id, role, full_name, email, phone, state, avatar_url, kyc_status, profile_complete, online, created_at, updated_at, last_login_at
       FROM users
       WHERE id = $1
       LIMIT 1`,
      [req.params.id]
    );

    if (!result.rows[0]) return respondError(res, 404, 'User not found');

    const wallet = await ensureWallet(req.params.id);
    const txns = await query(
      `SELECT * FROM transactions WHERE user_id = $1 ORDER BY created_at DESC LIMIT 20`,
      [req.params.id]
    );
    const kyc = await query(
      `SELECT * FROM kyc_requests WHERE user_id = $1 ORDER BY submitted_at DESC LIMIT 1`,
      [req.params.id]
    );

    return respondOk(res, {
      user: result.rows[0],
      wallet: { balance: Number(wallet.balance).toFixed(2), currency: wallet.currency },
      transactions: txns.rows,
      kyc: kyc.rows[0] || null
    });
  } catch (err) {
    console.error(err);
    return respondError(res, 500, 'Server error');
  }
});
app.get('/api/admin/transactions', requireAdmin, async (req, res) => {
  try {
    const result = await query(
      `SELECT * FROM transactions ORDER BY created_at DESC LIMIT 500`
    );
    return respondOk(res, { transactions: result.rows });
  } catch (err) {
    console.error(err);
    return respondError(res, 500, 'Server error');
  }
});

app.get('/api/admin/kyc', requireAdmin, async (req, res) => {
  try {
    const result = await query(
      `SELECT * FROM kyc_requests ORDER BY submitted_at DESC LIMIT 300`
    );
    return respondOk(res, { kycRequests: result.rows });
  } catch (err) {
    console.error(err);
    return respondError(res, 500, 'Server error');
  }
});

app.patch('/api/admin/users/:id/kyc', requireAdmin, async (req, res) => {
  try {
    const { status, note } = req.body || {};
    if (!['verified', 'rejected', 'pending'].includes(String(status))) {
      return respondError(res, 400, 'Invalid KYC status');
    }

    const kyc = await query(
      `SELECT * FROM kyc_requests WHERE user_id = $1 ORDER BY submitted_at DESC LIMIT 1`,
      [req.params.id]
    );

    if (!kyc.rows[0]) return respondError(res, 404, 'KYC record not found');

    const updated = await query(
      `UPDATE kyc_requests
       SET status = $2, admin_note = $3, reviewed_at = NOW()
       WHERE id = $1
       RETURNING *`,
      [kyc.rows[0].id, status, note || null]
    );

    await query(
      `UPDATE users
       SET kyc_status = $2, updated_at = NOW()
       WHERE id = $1`,
      [req.params.id, status]
    );

    await addNotification(
      req.params.id,
      'KYC updated',
      `Your KYC status was updated to ${status}`,
      { status, note: note || null },
      true
    );

    await query(
      `INSERT INTO admin_logs (id, admin_id, action, meta, created_at)
       VALUES ($1,$2,$3,$4,NOW())`,
      [uid('log_'), req.user.id, 'update_kyc', JSON.stringify({ user_id: req.params.id, status, note: note || null })]
    );

    return respondOk(res, { kyc: updated.rows[0] }, 'KYC updated');
  } catch (err) {
    console.error(err);
    return respondError(res, 500, 'Server error');
  }
});
app.post('/api/admin/notifications', requireAdmin, async (req, res) => {
  try {
    const { userId, title, message, meta = {} } = req.body || {};
    if (!userId || !title || !message) return respondError(res, 400, 'userId, title and message are required');

    await addNotification(userId, title, message, meta, true);

    await query(
      `INSERT INTO admin_logs (id, admin_id, action, meta, created_at)
       VALUES ($1,$2,$3,$4,NOW())`,
      [uid('log_'), req.user.id, 'create_notification', JSON.stringify({ userId, title, message })]
    );

    return respondOk(res, {}, 'Notification sent');
  } catch (err) {
    console.error(err);
    return respondError(res, 500, 'Server error');
  }
});

app.put('/api/admin/pricing/:serviceType', requireAdmin, async (req, res) => {
  try {
    const serviceType = normalizeServiceType(req.params.serviceType);
    const { markupPercent } = req.body || {};

    if (![
      'airtime',
      'data',
      'cable_tv',
      'electricity',
      'betting',
      'recharge_pin',
      'data_pin',
      'exam_pin'
    ].includes(serviceType)) {
      return respondError(res, 400, 'Invalid service type');
    }

    const markup = toNumber(markupPercent, NaN);
    if (!Number.isFinite(markup) || markup < 0) {
      return respondError(res, 400, 'Invalid markup percent');
    }

    const existing = await query(
      `SELECT * FROM pricing_rules WHERE service_type = $1 LIMIT 1`,
      [serviceType]
    );

    let updated;

    if (existing.rows[0]) {
      updated = await query(
        `UPDATE pricing_rules
         SET markup_percent = $2, updated_at = NOW()
         WHERE service_type = $1
         RETURNING *`,
        [serviceType, Number(markup).toFixed(2)]
      );
    } else {
      updated = await query(
        `INSERT INTO pricing_rules (id, service_type, markup_percent, is_active, created_at, updated_at)
         VALUES ($1, $2, $3, true, NOW(), NOW())
         RETURNING *`,
        [uid('prc_'), serviceType, Number(markup).toFixed(2)]
      );
    }

    return respondOk(res, { pricingRule: updated.rows[0] }, 'Pricing updated');
  } catch (err) {
    console.error(err);
    return respondError(res, 500, 'Server error');
  }
});
