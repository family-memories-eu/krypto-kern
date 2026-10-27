// =============================================================================
// One key per media object (E2E Etappe 5 · E5.1, design §4.3 — deviation noted
// there). Photos, posters, videos and recordings of an E2E family are encrypted
// with a key DERIVED from the family (or collaborative story) key of version N:
//
//   K_obj = HKDF-SHA256(FMK_N, salt = "", info = "fm/media-object/v1" ‖ scope ‖
//           scopeId ‖ path ‖ N ‖ rowId)  → AES-256-GCM, not extractable
//
// The derivation does what the design wanted from an AAD: an object copied to
// another path, another row (photo, story, chapter), another family or another
// key version opens with a different key, so GCM refuses it. Unlike an AAD it
// needs no new container format — the whole-blob format (`iv ‖ ct`), FMV2
// video chunks (also in the service worker) and the audio MIME frame stay
// exactly as they are; only where the key comes from changes. The base key per
// version is an HKDF key that can only derive, never be read back.
//
// The version is part of the path (`….e2e.v<N>.enc`, mediaSeal.ts), so a
// reader knows which base key to use from the path alone.
//
// Light on purpose (WebCrypto + bytes only).
// =============================================================================

import { encodeFields, own } from "./bytes";

export type ObjectScope = "family" | "story";

export type ObjectRef = {
  scope: ObjectScope;
  /** The family id, or the collaborative story's id. */
  scopeId: string;
  /** The storage path inside the family-media bucket. */
  path: string;
  version: number;
  /** The row the object belongs to: photo id, story id or chapter id. */
  rowId: string;
};

/** The HKDF base key of one family/story key version (derive only). */
export function mediaBaseKey(rawContentKey: Uint8Array): Promise<CryptoKey> {
  return globalThis.crypto.subtle.importKey("raw", own(rawContentKey), "HKDF", false, ["deriveKey"]);
}

export function objectKeyInfo(ref: ObjectRef): Uint8Array {
  return encodeFields("fm/media-object/v1", ref.scope, ref.scopeId, ref.path, ref.version, ref.rowId);
}

/** The object's own AES-256-GCM key (encrypt + decrypt, not extractable). */
export function objectKey(base: CryptoKey, ref: ObjectRef): Promise<CryptoKey> {
  return globalThis.crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: own(objectKeyInfo(ref)) },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}
