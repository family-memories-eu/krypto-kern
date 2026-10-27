// =============================================================================
// Tag blind index (E2E, design §4.5): name_idx = HMAC(TIK_v, normalize(name)),
// cut to 16 bytes — unique per family without the server learning the name.
// TIK_v is derived from the family key of that version and never stored.
// Light on purpose (WebCrypto only) — the tag writes import it statically.
// =============================================================================

import { encodeFields, hkdf, own, toB64url } from "./bytes";

export async function tagIndexKey(familyKeyRaw: Uint8Array): Promise<CryptoKey> {
  const raw = await hkdf(familyKeyRaw, new Uint8Array(0), encodeFields("fm/tag-index/v1"));
  return globalThis.crypto.subtle.importKey("raw", raw, { name: "HMAC", hash: "SHA-256" }, false, [
    "sign",
  ]);
}

/** "  Urlaub   2019 " and "urlaub 2019" index identically. */
export function normalizeTag(name: string): string {
  return name.normalize("NFKC").trim().replace(/\s+/g, " ").toLowerCase();
}

export async function tagIndex(key: CryptoKey, name: string): Promise<string> {
  const mac = await globalThis.crypto.subtle.sign(
    "HMAC",
    key,
    own(new TextEncoder().encode(normalizeTag(name))),
  );
  return toB64url(new Uint8Array(mac).subarray(0, 16));
}
