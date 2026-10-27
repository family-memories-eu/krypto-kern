// =============================================================================
// Client-side media encryption (runs in the browser only).
//
// AES-256-GCM over blobs: the E2E media pipeline (photos, videos' posters,
// recordings, branding) seals each object under its own key derived in the
// browser (lib/e2e/objectKey.ts) and hands the bytes through here. The Phase 11
// family media key and its server-side wrapping are gone since E5.5.
//
//   * AES-GCM is AEAD — CONFIDENTIALITY *and* INTEGRITY. Decryption verifies a
//     128-bit tag and THROWS if a single byte (or the IV) was tampered with; we
//     surface that as `errorDecrypt`.
//   * A fresh 96-bit random IV per encryption, prepended: `iv || ciphertext(+tag)`.
//
// No third-party crypto library — WebCrypto (SubtleCrypto) only, same self-hosted
// stance as the on-device Whisper worker in Phase 9. This module is browser-only
// (it needs `crypto.subtle`, available in secure contexts) and must not be
// imported into server code.
// =============================================================================

import { objectAllowed } from "@/lib/e2e/objBinding";

const KEY_ALGO = "AES-GCM";
const IV_BYTES = 12; // 96-bit nonce — the size AES-GCM is defined for.

// Error codes map 1:1 to i18n keys (Photos namespace), so the UI can show a
// translated, human message instead of a raw exception — same pattern as
// ImageError in ./images.ts.
export type CryptoErrorCode =
  | "errorCryptoUnavailable" // no SubtleCrypto (insecure context / ancient browser)
  | "errorDecrypt" // wrong key or tampered/corrupt ciphertext (GCM tag failed)
  | "errorKey"; // malformed key material

export class CryptoError extends Error {
  constructor(public code: CryptoErrorCode) {
    super(code);
    this.name = "CryptoError";
  }
}

// SubtleCrypto is only present in secure contexts (https / localhost). Fail with
// a translatable code rather than a raw "cannot read property of undefined".
function subtle(): SubtleCrypto {
  const s = globalThis.crypto?.subtle;
  if (!s) throw new CryptoError("errorCryptoUnavailable");
  return s;
}

// -----------------------------------------------------------------------------
// Blob encryption (photos full/thumb/original, story audio).
// The output blob is opaque `iv || ciphertext(+tag)`, uploaded with a `.enc`
// name. We tag it application/octet-stream so nothing downstream mistakes the
// ciphertext for a real image/audio type.
// -----------------------------------------------------------------------------

export async function encryptBlob(key: CryptoKey, data: Blob): Promise<Blob> {
  const plaintext = new Uint8Array(await data.arrayBuffer());
  const packed = await encryptBytes(key, plaintext);
  return new Blob([packed], { type: "application/octet-stream" });
}

// Decrypt a `.enc` blob back to its real bytes. Pass the real MIME type (e.g.
// "image/jpeg", "audio/webm") so the returned Blob can go straight into an
// object URL for an <img>/<audio> element.
export async function decryptBlob(
  key: CryptoKey,
  data: Blob,
  mimeType: string,
): Promise<Blob> {
  const packed = new Uint8Array(await data.arrayBuffer());
  // K-03: an object key tied to a row opens only the object that row binds.
  if (!(await objectAllowed(key, packed))) throw new CryptoError("errorDecrypt");
  const plaintext = await decryptBytes(key, packed);
  return new Blob([plaintext], { type: mimeType });
}

// -----------------------------------------------------------------------------
// Core AES-GCM primitives + helpers. Everything above funnels through these so
// the `iv || ciphertext` framing lives in exactly one place.
// -----------------------------------------------------------------------------

// Uint8Array is generic over its backing buffer since TS 5.7; WebCrypto and Blob
// want ArrayBuffer-backed views, so we pin the generic to <ArrayBuffer> here.
async function encryptBytes(
  key: CryptoKey,
  plaintext: Uint8Array<ArrayBuffer>,
): Promise<Uint8Array<ArrayBuffer>> {
  // Fresh random 96-bit IV per call; never reuse an IV under the same key.
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const ct = new Uint8Array(
    await subtle().encrypt({ name: KEY_ALGO, iv }, key, plaintext),
  );
  // Prepend the IV so decryption is self-contained: [ iv | ciphertext(+tag) ].
  const packed = new Uint8Array(iv.byteLength + ct.byteLength);
  packed.set(iv, 0);
  packed.set(ct, iv.byteLength);
  return packed;
}

async function decryptBytes(
  key: CryptoKey,
  packed: Uint8Array<ArrayBuffer>,
): Promise<Uint8Array<ArrayBuffer>> {
  if (packed.byteLength <= IV_BYTES) throw new CryptoError("errorDecrypt");
  const iv = packed.subarray(0, IV_BYTES);
  const ct = packed.subarray(IV_BYTES);
  try {
    // Throws if the GCM auth tag doesn't verify — wrong key OR tampered bytes.
    return new Uint8Array(await subtle().decrypt({ name: KEY_ALGO, iv }, key, ct));
  } catch {
    throw new CryptoError("errorDecrypt");
  }
}


