/**
 * Cloudflare Pages Function: /api/verify-and-mint
 * 1. Verifies Razorpay HMAC SHA-256 signature
 * 2. Anchors SHA-256 hash to OpenTimestamps (free public Bitcoin ledger proof)
 * 3. Stores certificate record in Supabase (Mumbai ap-south-1)
 * 4. Dispatches professional BSA Section 63 Certificate email via Resend
 */

export async function onRequestPost(context) {
  const { request, env } = context;

  try {
    const body = await request.json();
    const {
      razorpay_order_id,
      razorpay_payment_id,
      razorpay_signature,
      sha256_hash,
      byte_size,
      owner_full_name,
      owner_email,
      asset_title,
      asset_category,
      amount_paid_paise
    } = body;

    // 1. Basic input validation
    if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature) {
      return jsonResponse({ error: 'Missing payment verification parameters.' }, 400);
    }
    if (!sha256_hash || !/^[a-f0-9]{64}$/i.test(sha256_hash)) {
      return jsonResponse({ error: 'Invalid SHA-256 hash.' }, 400);
    }

    // 2. Cryptographically verify Razorpay signature using Web Crypto HMAC SHA-256
    const isSignatureValid = await verifyRazorpaySignature(
      razorpay_order_id,
      razorpay_payment_id,
      razorpay_signature,
      env.RAZORPAY_KEY_SECRET
    );

    if (!isSignatureValid) {
      return jsonResponse({ error: 'Payment signature verification failed. Unauthorized request.' }, 403);
    }

    const cleanHash = sha256_hash.toLowerCase();
    const certCode = generateCertificateCode();

    // 3. Submit hash to OpenTimestamps (Independent public ledger anchor - non-blocking fallback)
    const otsBase64 = await anchorToOpenTimestamps(cleanHash);

    // 4. Insert record into Supabase (triggers automatic sync to public_ledger)
    const insertPayload = {
      certificate_code: certCode,
      owner_full_name: owner_full_name.trim(),
      owner_email: owner_email.trim().toLowerCase(),
      asset_title: asset_title.trim(),
      asset_category: (asset_category || 'General IP').trim(),
      sha256_hash: cleanHash,
      byte_size: Number(byte_size) || 0,
      razorpay_order_id,
      razorpay_payment_id,
      amount_paid_paise: Number(amount_paid_paise) || 100,
      ots_receipt_base64: otsBase64
    };

    const sbRes = await fetch(`${env.SUPABASE_URL}/rest/v1/certificates`, {
      method: 'POST',
      headers: {
        'apikey': env.SUPABASE_SERVICE_ROLE_KEY,
        'Authorization': `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`,
        'Content-Type': 'application/json',
        'Prefer': 'return=representation'
      },
      body: JSON.stringify(insertPayload)
    });

    const sbData = await sbRes.json();

    if (!sbRes.ok) {
      // Handle duplicate payment replay gracefully
      if (sbData?.code === '23505') {
        return jsonResponse({ error: 'This payment has already been processed for a certificate.' }, 409);
      }
      return jsonResponse({ error: 'Database error saving certificate record.' }, 500);
    }

    const savedRecord = Array.isArray(sbData) ? sbData[0] : sbData;

    // 5. Send Executive BSA Section 63 Certificate Email via Resend
    const resendId = await sendCertificateEmail(env.RESEND_API_KEY, savedRecord, request.url);

    // Update Resend delivery audit ID in Supabase
    if (resendId) {
      await fetch(`${env.SUPABASE_URL}/rest/v1/certificates?certificate_code=eq.${certCode}`, {
        method: 'PATCH',
        headers: {
          'apikey': env.SUPABASE_SERVICE_ROLE_KEY,
          'Authorization': `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ resend_message_id: resendId })
      });
    }

    return jsonResponse({
      success: true,
      certificate: {
        certificate_code: savedRecord.certificate_code,
        sha256_hash: savedRecord.sha256_hash,
        ist_timestamp: savedRecord.ist_timestamp_formatted,
        asset_title: savedRecord.asset_title,
        owner_full_name: savedRecord.owner_full_name,
        ots_anchored: Boolean(otsBase64)
      }
    }, 200);

  } catch (err) {
    return jsonResponse({ error: 'Internal server error during certificate minting.' }, 500);
  }
}

/**
 * Verifies Razorpay HMAC SHA-256 signature natively in Cloudflare Workers
 */
async function verifyRazorpaySignature(orderId, paymentId, signature, secret) {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );

  const data = encoder.encode(`${orderId}|${paymentId}`);
  const signatureBuffer = await crypto.subtle.sign('HMAC', key, data);
  const expectedSignature = Array.from(new Uint8Array(signatureBuffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');

  return expectedSignature === signature;
}

/**
 * Anchors 32-byte raw SHA-256 digest to OpenTimestamps public calendar server
 */
async function anchorToOpenTimestamps(hexHash) {
  try {
    const rawBytes = new Uint8Array(
      hexHash.match(/.{1,2}/g).map(byte => parseInt(byte, 16))
    );

    const response = await fetch('https://a.pool.opentimestamps.org/digest', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: rawBytes
    });

    if (!response.ok) return null;
    const otsBuffer = await response.arrayBuffer();
    const otsBytes = new Uint8Array(otsBuffer);
    let binary = '';
    for (let i = 0; i < otsBytes.length; i++) {
      binary += String.fromCharCode(otsBytes[i]);
    }
    return btoa(binary);
  } catch {
    return null;
  }
}

/**
 * Generates an executive, print-ready BSA Section 63 Certificate email via Resend
 */
async function sendCertificateEmail(resendApiKey, record, requestUrl) {
  try {
    const origin = new URL(requestUrl).origin;
    const verifyUrl = `${origin}/verify.html?id=${encodeURIComponent(record.certificate_code)}`;
    const qrUrl = `https://api.qrserver.com/v1/create-qr-code/?size=140x140&data=${encodeURIComponent(verifyUrl)}`;

    const htmlBody = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8" />
  <title>HashPaper Cryptographic Priority Certificate</title>
</head>
<body style="margin:0;padding:0;background-color:#f4f4f6;font-family:'Helvetica Neue',Helvetica,Arial,sans-serif;color:#111827;">
  <table width="100%" cellpadding="0" cellspacing="0" style="padding:32px 16px;">
    <tr>
      <td align="center">
        <table width="100%" style="max-width:640px;background:#ffffff;border:1px solid #d1d5db;border-radius:8px;overflow:hidden;">
          <!-- Header -->
          <tr>
            <td style="background:#0f172a;padding:28px 32px;color:#ffffff;">
              <table width="100%">
                <tr>
                  <td>
                    <div style="font-size:11px;letter-spacing:2px;text-transform:uppercase;color:#94a3b8;font-weight:600;">CRYPTOGRAPHIC IP REGISTRY • INDIA</div>
                    <div style="font-size:24px;font-weight:700;margin-top:4px;letter-spacing:-0.5px;">HashPaper</div>
                  </td>
                  <td align="right" style="vertical-align:top;">
                    <span style="display:inline-block;background:#1e293b;border:1px solid #334155;color:#38bdf8;font-size:12px;font-weight:600;padding:6px 12px;border-radius:4px;">
                      ${record.certificate_code}
                    </span>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- Certificate Title -->
          <tr>
            <td style="padding:32px 32px 16px 32px;border-bottom:1px solid #e5e7eb;">
              <div style="font-size:12px;font-weight:700;color:#0369a1;text-transform:uppercase;letter-spacing:1px;">Certificate of Cryptographic Existence & Priority</div>
              <h1 style="font-size:20px;margin:8px 0 0 0;color:#0f172a;">Digital Asset Timestamp Record</h1>
              <p style="font-size:13px;color:#4b5563;line-height:1.6;margin:10px 0 0 0;">
                This certifies that the cryptographic SHA-256 fingerprint of the digital work identified below was irrevocably recorded on the HashPaper Public Ledger in accordance with electronic record integrity standards under <strong>Section 63 of the Bharatiya Sakshya Adhiniyam (BSA), 2023</strong>.
              </p>
            </td>
          </tr>

          <!-- Core Metadata Table -->
          <tr>
            <td style="padding:24px 32px;">
              <table width="100%" cellpadding="0" cellspacing="0" style="font-size:13px;border-collapse:collapse;">
                <tr>
                  <td style="padding:10px 0;color:#6b7280;width:36%;border-bottom:1px solid #f3f4f6;">Registered Declarant</td>
                  <td style="padding:10px 0;color:#111827;font-weight:600;border-bottom:1px solid #f3f4f6;">${escapeHtml(record.owner_full_name)}</td>
                </tr>
                <tr>
                  <td style="padding:10px 0;color:#6b7280;border-bottom:1px solid #f3f4f6;">Asset Title</td>
                  <td style="padding:10px 0;color:#111827;font-weight:600;border-bottom:1px solid #f3f4f6;">${escapeHtml(record.asset_title)}</td>
                </tr>
                <tr>
                  <td style="padding:10px 0;color:#6b7280;border-bottom:1px solid #f3f4f6;">Classification</td>
                  <td style="padding:10px 0;color:#111827;border-bottom:1px solid #f3f4f6;">${escapeHtml(record.asset_category)} (${record.byte_size} bytes UTF-8)</td>
                </tr>
                <tr>
                  <td style="padding:10px 0;color:#6b7280;border-bottom:1px solid #f3f4f6;">Authoritative IST Timestamp</td>
                  <td style="padding:10px 0;color:#0f172a;font-weight:700;border-bottom:1px solid #f3f4f6;">${record.ist_timestamp_formatted}</td>
                </tr>
                <tr>
                  <td style="padding:10px 0;color:#6b7280;border-bottom:1px solid #f3f4f6;">Payment Audit Ref</td>
                  <td style="padding:10px 0;color:#374151;font-family:monospace;border-bottom:1px solid #f3f4f6;">${record.razorpay_payment_id}</td>
                </tr>
              </table>

              <!-- SHA-256 Box -->
              <div style="margin-top:20px;background:#f8fafc;border:1px solid #cbd5e1;border-radius:6px;padding:16px;">
                <div style="font-size:11px;font-weight:700;color:#475569;text-transform:uppercase;letter-spacing:0.8px;">SHA-256 Cryptographic Fingerprint</div>
                <div style="margin-top:6px;font-family:'Courier New',Courier,monospace;font-size:12px;color:#0f172a;word-break:break-all;font-weight:700;">
                  ${record.sha256_hash}
                </div>
              </div>

              <!-- QR Verification & BSA Section 63 Notice -->
              <table width="100%" style="margin-top:24px;background:#f9fafb;border:1px solid #e5e7eb;border-radius:6px;padding:16px;">
                <tr>
                  <td style="vertical-align:middle;padding-right:16px;">
                    <div style="font-size:12px;font-weight:700;color:#111827;">Independent Public Verification</div>
                    <p style="font-size:12px;color:#4b5563;line-height:1.5;margin:6px 0 10px 0;">
                      Scan the QR code or verify this record anytime on the HashPaper Blind Ledger. Retain your exact original <code>.txt</code> reference file unaltered—any modification of even a single character will alter the SHA-256 hash.
                    </p>
                    <a href="${verifyUrl}" style="display:inline-block;background:#0f172a;color:#ffffff;text-decoration:none;font-size:12px;font-weight:600;padding:8px 14px;border-radius:4px;">
                      Verify on Public Ledger →
                    </a>
                  </td>
                  <td align="right" style="vertical-align:middle;width:110px;">
                    <img src="${qrUrl}" alt="Verification QR" width="100" height="100" style="border:1px solid #e5e7eb;border-radius:4px;" />
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td style="background:#f8fafc;padding:20px 32px;border-top:1px solid #e5e7eb;font-size:11px;color:#6b7280;line-height:1.5;">
              <strong>Zero-Retention Notice:</strong> HashPaper computed this hash locally inside the declarant's browser and never received, stored, or viewed the underlying intellectual property payload.<br/>
              Issued by <strong>HashPaper</strong> (A Your Legal Indian / MDM Global Holdings Initiative, Bengaluru, India).
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>`;

    const res = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${resendApiKey}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        from: 'HashPaper Registry <certificates@hashpaper.in>',
        to: [record.owner_email],
        subject: `[${record.certificate_code}] HashPaper Cryptographic Priority Certificate — ${record.asset_title}`,
        html: htmlBody
      })
    });

    if (!res.ok) return null;
    const data = await res.json();
    return data.id || null;
  } catch {
    return null;
  }
}

function generateCertificateCode() {
  const year = new Date().getFullYear();
  const bytes = new Uint8Array(4);
  crypto.getRandomValues(bytes);
  const hex = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
  return `HP-${year}-${hex}`;
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function jsonResponse(payload, status = 200) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { 'Content-Type': 'application/json' }
  });
}
