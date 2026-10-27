// =============================================================================
// Byte helpers for the end-to-end layer (docs/e2e-design.md).
//
// The one thing here that is security-relevant is `encodeFields`: everything we
// SIGN or bind as AAD/HPKE-info goes through it, so two different field lists
// can never serialise to the same bytes ("ab"+"c" vs "a"+"bc"). Each field is a
// 4-byte big-endian length followed by its bytes. Never build a signed message
// by string concatenation.
// =============================================================================

export type Bytes = Uint8Array<ArrayBuffer>;

const enc = new TextEncoder();
const dec = new TextDecoder("utf-8", { fatal: true });

export function utf8(s: string): Bytes {
  return enc.encode(s) as Bytes;
}

export function fromUtf8(b: Uint8Array): string {
  return dec.decode(b);
}

export function randomBytes(n: number): Bytes {
  return globalThis.crypto.getRandomValues(new Uint8Array(n));
}

export function concat(...parts: Uint8Array[]): Bytes {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.byteLength, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.byteLength;
  }
  return out;
}

/** Copy into a fresh ArrayBuffer-backed array (WebCrypto wants exactly that). */
export function own(b: ArrayBuffer | Uint8Array): Bytes {
  return b instanceof Uint8Array ? new Uint8Array(b) : new Uint8Array(b.slice(0));
}

export type Field = Uint8Array | string | number;

/** Unambiguous, length-prefixed encoding of a field list. Numbers are u32. */
export function encodeFields(...fields: Field[]): Bytes {
  const parts: Uint8Array[] = [];
  for (const f of fields) {
    let b: Uint8Array;
    if (typeof f === "string") b = utf8(f);
    else if (typeof f === "number") {
      if (!Number.isInteger(f) || f < 0 || f > 0xffffffff) {
        throw new RangeError("encodeFields: numbers must be u32");
      }
      b = u32(f);
    } else b = f;
    parts.push(u32(b.byteLength), b);
  }
  return concat(...parts);
}

function u32(n: number): Bytes {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n);
  return b;
}

/** Constant-time comparison (for codes and fingerprints, not for secrets in RAM). */
export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength) return false;
  let d = 0;
  for (let i = 0; i < a.byteLength; i++) d |= a[i] ^ b[i];
  return d === 0;
}

export function toB64url(b: Uint8Array): string {
  let s = "";
  for (let i = 0; i < b.byteLength; i++) s += String.fromCharCode(b[i]);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function fromB64url(s: string): Bytes {
  if (!/^[A-Za-z0-9_-]*$/.test(s)) throw new TypeError("fromB64url: invalid input");
  const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4));
  const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/") + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export async function sha256(b: Uint8Array): Promise<Bytes> {
  return new Uint8Array(await globalThis.crypto.subtle.digest("SHA-256", own(b)));
}

export async function sha512(b: Uint8Array): Promise<Bytes> {
  return new Uint8Array(await globalThis.crypto.subtle.digest("SHA-512", own(b)));
}

/** HKDF-SHA256 to `length` bytes. */
export async function hkdf(
  ikm: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array,
  length = 32,
): Promise<Bytes> {
  const k = await globalThis.crypto.subtle.importKey("raw", own(ikm), "HKDF", false, [
    "deriveBits",
  ]);
  const bits = await globalThis.crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: own(salt), info: own(info) },
    k,
    length * 8,
  );
  return new Uint8Array(bits);
}

/** Import 32 raw bytes as a NON-extractable AES-256-GCM key. */
export async function importAesKey(raw: Uint8Array): Promise<CryptoKey> {
  if (raw.byteLength !== 32) throw new RangeError("importAesKey: need 32 bytes");
  return globalThis.crypto.subtle.importKey("raw", own(raw), "AES-GCM", false, [
    "encrypt",
    "decrypt",
  ]);
}

const IV = 12;

/** AES-256-GCM with AAD; output `iv || ct+tag`. */
export async function aesSeal(key: CryptoKey, pt: Uint8Array, aad: Uint8Array): Promise<Bytes> {
  const iv = randomBytes(IV);
  const ct = await globalThis.crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: own(aad) },
    key,
    own(pt),
  );
  return concat(iv, new Uint8Array(ct));
}

export async function aesOpen(key: CryptoKey, blob: Uint8Array, aad: Uint8Array): Promise<Bytes> {
  if (blob.byteLength < IV + 16) throw new E2eError("decrypt");
  try {
    const pt = await globalThis.crypto.subtle.decrypt(
      { name: "AES-GCM", iv: own(blob.subarray(0, IV)), additionalData: own(aad) },
      key,
      own(blob.subarray(IV)),
    );
    return new Uint8Array(pt);
  } catch {
    throw new E2eError("decrypt");
  }
}

/**
 * Error codes only, never content: these surface in GlitchTip (design §8).
 */
export type E2eErrorCode =
  | "freshLogin"
  | "decrypt"
  | "signature"
  | "untrustedSender"
  | "format"
  | "recoveryCode"
  | "binding"
  | "mismatch"
  | "pending";

export class E2eError extends Error {
  constructor(readonly code: E2eErrorCode) {
    super(`e2e:${code}`);
    this.name = "E2eError";
  }
}

/** bytea as PostgREST sends and accepts it: "\x0a1b…". */
export function toPgBytea(b: Uint8Array): string {
  let s = "\\x";
  for (let i = 0; i < b.byteLength; i++) s += b[i].toString(16).padStart(2, "0");
  return s;
}

export function fromPgBytea(s: string): Bytes {
  if (typeof s !== "string" || !s.startsWith("\\x") || s.length % 2 !== 0) throw new E2eError("format");
  const out = new Uint8Array((s.length - 2) / 2);
  for (let i = 0; i < out.length; i++) {
    const v = parseInt(s.substr(2 + i * 2, 2), 16);
    if (Number.isNaN(v)) throw new E2eError("format");
    out[i] = v;
  }
  return out;
}
