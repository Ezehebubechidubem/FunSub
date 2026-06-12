/* KYC */

app.post(
  '/api/kyc/submit',
  requireAuth,
  kycUpload.fields([
    { name: 'selfie', maxCount: 1 },
    { name: 'idFront', maxCount: 1 },
    { name: 'idBack', maxCount: 1 },
    { name: 'utilityBill', maxCount: 1 }
  ]),
  async (req, res) => {
    try {
      const { idType, idNumber, address } = req.body || {};
      if (!idType || !idNumber) return respondError(res, 400, 'ID type and ID number are required');

      const selfie = req.files?.selfie?.[0];
      const idFront = req.files?.idFront?.[0];
      const idBack = req.files?.idBack?.[0];
      const utilityBill = req.files?.utilityBill?.[0];

      if (!selfie || !idFront) {
        return respondError(res, 400, 'Selfie and ID front are required');
      }

      const inserted = await query(
        `INSERT INTO kyc_requests
         (id, user_id, id_type, id_number, selfie_url, id_front_url, id_back_url, utility_bill_url, address, status, submitted_at)
         VALUES
         ($1,$2,$3,$4,$5,$6,$7,$8,$9,'pending',NOW())
         RETURNING *`,
        [
          uid('kyc_'),
          req.user.id,
          idType,
          idNumber,
          `/uploads/kyc/${selfie.filename}`,
          `/uploads/kyc/${idFront.filename}`,
          idBack ? `/uploads/kyc/${idBack.filename}` : null,
          utilityBill ? `/uploads/kyc/${utilityBill.filename}` : null,
          address || null
        ]
      );

      await query(
        `UPDATE users
         SET kyc_status = 'pending', updated_at = NOW()
         WHERE id = $1`,
        [req.user.id]
      );

      await addNotification(req.user.id, 'KYC submitted', 'Your KYC request has been submitted', { kyc_id: inserted.rows[0].id }, true);

      return respondOk(res, { kyc: inserted.rows[0] }, 'KYC submitted successfully');
    } catch (err) {
      console.error(err);
      return respondError(res, 500, 'Server error');
    }
  }
);

app.get('/api/kyc/status', requireAuth, async (req, res) => {
  try {
    const result = await query(
      `SELECT * FROM kyc_requests
       WHERE user_id = $1
       ORDER BY submitted_at DESC
       LIMIT 1`,
      [req.user.id]
    );

    const user = await query(
      `SELECT kyc_status FROM users WHERE id = $1 LIMIT 1`,
      [req.user.id]
    );

    return respondOk(res, {
      kycStatus: user.rows[0]?.kyc_status || 'unverified',
      kyc: result.rows[0] || null
    });
  } catch (err) {
    console.error(err);
    return respondError(res, 500, 'Server error');
  }
});