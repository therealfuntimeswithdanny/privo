// DPoP (RFC 9449) proofs for AT Protocol OAuth: ES256 keypairs and the
// dpop+jwt proofs Bluesky's authorization servers require on PAR and token
// requests.

import { base64url, base64urlEncode, randomToken } from "../lib/crypto";

export interface DpopKeyPair {
  privateJwk: JsonWebKey;
  publicJwk: { kty: string; crv: string; x: string; y: string };
}

export async function generateDpopKey(): Promise<DpopKeyPair> {
  const pair = (await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign"]
  )) as CryptoKeyPair;
  const privateJwk = (await crypto.subtle.exportKey("jwk", pair.privateKey)) as JsonWebKey;
  return {
    privateJwk,
    publicJwk: { kty: "EC", crv: "P-256", x: privateJwk.x!, y: privateJwk.y! },
  };
}

async function importPrivate(jwk: JsonWebKey): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "jwk",
    { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y, d: jwk.d, key_ops: ["sign"] },
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"]
  );
}

/**
 * Sign a DPoP proof for `htm httpMethod` against `htu endpoint`.
 * `nonce` is included when the server demands one (use_dpop_nonce errors).
 */
export async function dpopProof(
  key: DpopKeyPair,
  method: string,
  endpoint: string,
  opts: { iss?: string; nonce?: string } = {}
): Promise<string> {
  const header = {
    typ: "dpop+jwt",
    alg: "ES256",
    jwk: key.publicJwk,
  };

  const now = Math.floor(Date.now() / 1000);
  // No `exp` claim: RFC 9449 doesn't require one, the reference ATProto
  // client omits it, and some PDS builds reject proofs whose exp falls
  // outside their accepted window ("exp claim timestamp check failed").
  const payload: Record<string, unknown> = {
    jti: randomToken(16),
    htm: method,
    htu: endpoint,
    iat: now,
  };
  if (opts.iss) payload.iss = opts.iss;
  if (opts.nonce) payload.nonce = opts.nonce;

  const signingInput = `${base64urlEncode(JSON.stringify(header))}.${base64urlEncode(JSON.stringify(payload))}`;
  const privateKey = await importPrivate(key.privateJwk);
  const signature = new Uint8Array(
    await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      privateKey,
      new TextEncoder().encode(signingInput)
    )
  );

  return `${signingInput}.${base64url(signature)}`;
}
