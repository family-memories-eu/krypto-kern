// =============================================================================
// Encrypted rows (docs/e2e-design.md §4.3, §4.4). All content fields of a row
// (title, text, caption, dates, …) travel as ONE padded JSON blob in an `enc`
// column. The AAD binds the blob to its table, row, family and key version, so
// the server cannot paste one photo's caption onto another photo, into another
// family, or replay it under a different key version.
//
// Wire format: 0x01 || iv(12) || AES-GCM(ct+tag)
// Plaintext:   u32 jsonLength || json || zero padding up to the size bucket
// =============================================================================

import { aesOpen, aesSeal, concat, E2eError, encodeFields, fromUtf8, utf8, type Bytes } from "./bytes";

const FORMAT = 1;

export type RowBinding = {
  table: string;
  rowId: string;
  /** family_id, or story_id for collaborative-story rows */
  scopeId: string;
  keyVersion: number;
};

function aad(b: RowBinding): Bytes {
  return encodeFields("fm/row/v1", FORMAT, b.table, b.rowId, b.scopeId, b.keyVersion);
}

/** Size bucket so a title's length does not give its content away. */
export function paddedLength(n: number): number {
  const step = n <= 256 ? 64 : n <= 4096 ? 512 : 4096;
  return Math.max(step, Math.ceil(n / step) * step);
}

export function pad(json: Bytes): Bytes {
  const body = 4 + json.byteLength;
  const out = new Uint8Array(paddedLength(body));
  new DataView(out.buffer).setUint32(0, json.byteLength);
  out.set(json, 4);
  return out;
}

export function unpad(p: Uint8Array): Uint8Array {
  if (p.byteLength < 4) throw new E2eError("format");
  const n = new DataView(p.buffer, p.byteOffset, p.byteLength).getUint32(0);
  if (4 + n > p.byteLength) throw new E2eError("format");
  for (let i = 4 + n; i < p.byteLength; i++) if (p[i] !== 0) throw new E2eError("format");
  return p.subarray(4, 4 + n);
}

export async function encryptRow<T extends Record<string, unknown>>(
  key: CryptoKey,
  binding: RowBinding,
  fields: T,
): Promise<Bytes> {
  const sealed = await aesSeal(key, pad(utf8(JSON.stringify(fields))), aad(binding));
  return concat(new Uint8Array([FORMAT]), sealed);
}

export async function decryptRow<T extends Record<string, unknown>>(
  key: CryptoKey,
  binding: RowBinding,
  blob: Uint8Array,
): Promise<T> {
  if (blob.byteLength < 1 || blob[0] !== FORMAT) throw new E2eError("format");
  const p = await aesOpen(key, blob.subarray(1), aad(binding));
  const value: unknown = JSON.parse(fromUtf8(unpad(p)));
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new E2eError("format");
  }
  return value as T;
}
