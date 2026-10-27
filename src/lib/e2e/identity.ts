// =============================================================================
// Account key (AK) — one per PERSON, held by all of that person's devices
// (docs/e2e-design.md §3, §5). X25519 receives key envelopes, Ed25519 signs
// envelopes, invitations and the self-statement published in
// `user_identity_keys`.
//
// Curves run on @noble/curves rather than WebCrypto because X25519/Ed25519 in
// WebCrypto only reached every major browser in 2025 and older iPads lack it.
// The private half therefore exists as bytes in memory while in use; at rest it
// is only ever stored wrapped (device storage key, passkey PRF, recovery code).
// =============================================================================

import { ed25519, x25519 } from "@noble/curves/ed25519.js";

import { concat, E2eError, encodeFields, toB64url, sha256, type Bytes, type Field } from "./bytes";

export type AccountKey = {
  x25519Priv: Bytes;
  x25519Pub: Bytes;
  edSk: Bytes;
  edPk: Bytes;
};

export type PublicAccountKey = {
  x25519Pub: Bytes;
  edPk: Bytes;
};

const AK_FORMAT = 1;
const AK_LEN = 1 + 4 * 32;

export function generateAccountKey(): AccountKey {
  const x25519Priv = x25519.utils.randomSecretKey() as Bytes;
  const edSk = ed25519.utils.randomSecretKey() as Bytes;
  return {
    x25519Priv,
    x25519Pub: x25519.getPublicKey(x25519Priv) as Bytes,
    edSk,
    edPk: ed25519.getPublicKey(edSk) as Bytes,
  };
}

/** Private serialisation — ONLY ever passed to a wrapping function. */
export function serializeAccountKey(ak: AccountKey): Bytes {
  return concat(new Uint8Array([AK_FORMAT]), ak.x25519Priv, ak.x25519Pub, ak.edSk, ak.edPk);
}

export function deserializeAccountKey(b: Uint8Array): AccountKey {
  if (b.byteLength !== AK_LEN || b[0] !== AK_FORMAT) throw new E2eError("format");
  const part = (i: number) => new Uint8Array(b.subarray(1 + i * 32, 1 + (i + 1) * 32));
  const ak = { x25519Priv: part(0), x25519Pub: part(1), edSk: part(2), edPk: part(3) };
  // A corrupted or tampered blob must not yield a key whose halves disagree.
  if (
    toB64url(x25519.getPublicKey(ak.x25519Priv)) !== toB64url(ak.x25519Pub) ||
    toB64url(ed25519.getPublicKey(ak.edSk)) !== toB64url(ak.edPk)
  ) {
    throw new E2eError("format");
  }
  return ak;
}

export function publicPart(ak: AccountKey): PublicAccountKey {
  return { x25519Pub: ak.x25519Pub, edPk: ak.edPk };
}

// ---------------------------------------------------------------------------
// Domain-separated signatures. Every signed message starts with a context
// string so a signature for one purpose can never be replayed as another.
// ---------------------------------------------------------------------------

export function sign(edSk: Uint8Array, context: string, ...fields: Field[]): Bytes {
  return ed25519.sign(encodeFields(context, ...fields), edSk) as Bytes;
}

export function verify(
  edPk: Uint8Array,
  sig: Uint8Array,
  context: string,
  ...fields: Field[]
): boolean {
  try {
    // ⛔ STRENG NACH RFC 8032 (K-07): `@noble/curves` prüft von sich aus im
    // ZIP-215-Modus — nicht-kanonische Punktkodierungen gelten, und mit einem
    // Schlüssel kleiner Ordnung „verifiziert“ jede Signatur. Unsere eigenen
    // Signaturen sind kanonisch und bestehen die strenge Prüfung unverändert.
    return ed25519.verify(sig, encodeFields(context, ...fields), edPk, { zip215: false });
  } catch {
    return false;
  }
}

export const CTX_SELF = "fm/ak-self/v1";

/** Statement published with the public AK: "this user owns these keys". */
export function selfSign(ak: AccountKey, userId: string): Bytes {
  return sign(ak.edSk, CTX_SELF, userId, ak.x25519Pub, ak.edPk);
}

export function verifySelf(pub: PublicAccountKey, userId: string, sig: Uint8Array): boolean {
  return verify(pub.edPk, sig, CTX_SELF, userId, pub.x25519Pub, pub.edPk);
}

/** Stable short identifier of a public AK, used as the TOFU store key. */
export async function fingerprint(pub: PublicAccountKey): Promise<string> {
  return toB64url(await sha256(encodeFields("fm/ak-fp/v1", pub.x25519Pub, pub.edPk)));
}
