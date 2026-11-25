/**
 * Cloudflare Pages Function: /api/verify-ledger
 * Queries the masked public_ledger in Supabase by Certificate ID or SHA-256 Hash.
 */

export async function onRequestGet(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const query = (url.searchParams.get('q') || '').trim();

  if (!query) {
    return jsonResponse({ error: 'Please provide a Certificate ID or SHA-256 hash.' }, 400);
  }

  let filterParam = '';

  // Check if query is a 64-char SHA-256 hash
  if (/^[a-f0-9]{64}$/i.test(query)) {
    filterParam = `sha256_hash=eq.${query.toLowerCase()}`;
  }
  // Check if query is a Certificate Code (e.g., HP-2026-8F9A2B)
  else if (/^HP-\d{4}-[A-F0-9]{8}$/i.test(query)) {
    filterParam = `certificate_code=eq.${query.toUpperCase()}`;
  } else {
    return jsonResponse({
      verified: false,
      error: 'Invalid format. Enter a valid 64-character SHA-256 hash or Certificate ID (e.g., HP-2026-XXXXXXXX).'
    }, 400);
  }

  try {
    const sbRes = await fetch(
      `${env.SUPABASE_URL}/rest/v1/public_ledger?${filterParam}&order=created_at.asc`,
      {
        method: 'GET',
        headers: {
          'apikey': env.SUPABASE_SERVICE_ROLE_KEY,
          'Authorization': `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`,
          'Content-Type': 'application/json'
        }
      }
    );

    if (!sbRes.ok) {
      return jsonResponse({ error: 'Unable to query public verification ledger.' }, 502);
    }

    const records = await sbRes.json();

    if (!Array.isArray(records) || records.length === 0) {
      return jsonResponse({
        verified: false,
        message: 'No matching cryptographic record found on the HashPaper Public Ledger.'
      }, 200);
    }

    // Return earliest priority record (and total count if multiple people hashed the same text later)
    return jsonResponse({
      verified: true,
      earliest_record: records[0],
      total_matches: records.length
    }, 200);

  } catch (err) {
    return jsonResponse({ error: 'Verification service temporarily unavailable.' }, 500);
  }
}

function jsonResponse(payload, status = 200) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { 'Content-Type': 'application/json' }
  });
}
