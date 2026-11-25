/**
 * Cloudflare Pages Function: /api/create-order
 * Creates a tamper-proof Razorpay Order ID on the edge server.
 */

// Price in paise: 100 = ₹1 (Change to 29900 for ₹299 when ready for full launch)
const CERTIFICATE_PRICE_PAISE = 100;

export async function onRequestPost(context) {
  const { request, env } = context;

  try {
    const body = await request.json();
    const { sha256_hash, owner_email, asset_title } = body;

    // Validate 64-char SHA-256 hex hash
    if (!sha256_hash || !/^[a-f0-9]{64}$/i.test(sha256_hash)) {
      return new Response(
        JSON.stringify({ error: 'Invalid SHA-256 hash format.' }),
        { status: 400, headers: { 'Content-Type': 'application/json' } }
      );
    }

    if (!owner_email || !asset_title) {
      return new Response(
        JSON.stringify({ error: 'Full name, email, and asset title are required.' }),
        { status: 400, headers: { 'Content-Type': 'application/json' } }
      );
    }

    // Create Basic Auth header for Razorpay API
    const authString = btoa(`${env.RAZORPAY_KEY_ID}:${env.RAZORPAY_KEY_SECRET}`);

    const orderPayload = {
      amount: CERTIFICATE_PRICE_PAISE,
      currency: 'INR',
      receipt: `hp_${Date.now()}`,
      notes: {
        sha256_hash: sha256_hash.toLowerCase(),
        owner_email: owner_email.trim(),
        asset_title: asset_title.trim().substring(0, 100)
      }
    };

    const rzpResponse = await fetch('https://api.razorpay.com/v1/orders', {
      method: 'POST',
      headers: {
        'Authorization': `Basic ${authString}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(orderPayload)
    });

    const rzpData = await rzpResponse.json();

    if (!rzpResponse.ok) {
      return new Response(
        JSON.stringify({ error: rzpData.error?.description || 'Failed to create Razorpay order.' }),
        { status: 502, headers: { 'Content-Type': 'application/json' } }
      );
    }

    return new Response(
      JSON.stringify({
        order_id: rzpData.id,
        amount: rzpData.amount,
        currency: rzpData.currency,
        key_id: env.RAZORPAY_KEY_ID
      }),
      { status: 200, headers: { 'Content-Type': 'application/json' } }
    );
  } catch (err) {
    return new Response(
      JSON.stringify({ error: 'Server error initializing payment order.' }),
      { status: 500, headers: { 'Content-Type': 'application/json' } }
    );
  }
}
