// =============================================================================
// Encrypted rows, format v2 (docs/e2e-design.md §4.3, AP-Zeilen v2, Q10).
//
// v1 bound a blob to its table, row, scope and key version. v2 also binds the
// row's REFERENCES (a comment's target, a chapter's story and position, …),
// its AUTHOR, the person who SIGNED this version and a REVISION counter, and
// the signer signs every version with the Ed25519 half of their account key.
// So the server cannot hang a comment under another photo, move a chapter or
// replay an older version unnoticed, and a member cannot write as another.
//
// Key separation: the row key is HKDF(FMK_v / SK_v, "fm/row-key/v2") — the raw
// scope key itself encrypts nothing in v2.
//
// Wire format:
//   0x02 ‖ signer identity (16, uuid) ‖ rev (u32) ‖ flags (u8) ‖ iv(12) ‖ ct+tag ‖ sig(64)
// AAD = enc("fm/row/v2", table, row, scope, key version, enc(refs…),
//           signer identity, rev, flags)
// pt  = pad(JSON {a: author, f: fields})
// sig = Ed25519(signer, enc("fm/row-sig/v2", AAD, signer user, iv ‖ ct+tag))
// flags bit 0 = "Bestand": an old row sealed anew by the owner (Q18).
//
// The AAD holds only what a reader knows WITHOUT looking anything up — the row
// and the blob's own head. The author and the signer's user id are checked
// after opening (author: inside the ciphertext, compared with the row's
// column; user: in the signature). So a row still OPENS with the scope key
// after its author's account is gone (0026 sets author columns to null and
// the identity goes with the account) — the owner can then take it over as
// "Bestand" instead of losing it (openRowV2Unchecked, resealing only).
//
// Who MAY sign (author or owner, Z1) is not decided here — openRowV2 returns
// the verified signer and the caller applies the rule (rowVerify.ts).
// =============================================================================

import { aesOpen, aesSeal, concat, E2eError, encodeFields, fromUtf8, hkdf, importAesKey, utf8, type Bytes } from "./bytes";
import { sign, verify } from "./identity";
import { pad, unpad } from "./rowCrypto";

export const ROW_FORMAT_V2 = 2;
export const FLAG_LEGACY = 1;

const HEAD = 1 + 16 + 4 + 1;
const SIG = 64;
const CTX_ROW = "fm/row/v2";
const CTX_SIG = "fm/row-sig/v2";

/** The v2 row key of one scope version. Derived while the raw key is at hand. */
export async function rowKeyV2(rawScopeKey: Uint8Array): Promise<CryptoKey> {
  return importAesKey(await hkdf(rawScopeKey, new Uint8Array(0), encodeFields("fm/row-key/v2")));
}

export type RowBindingV2 = {
  table: string;
  rowId: string;
  /** family_id, or story_id for collaborative-story rows */
  scopeId: string;
  keyVersion: number;
  /** The row's references in a fixed order per table (rowFields.ts ROW_V2). */
  refs: readonly string[];
};

export type RowSigner = { userId: string; identityId: string; edSk: Uint8Array };

export type OpenedRowV2 = {
  fields: Record<string, unknown>;
  /** The author sealed inside ("" for none) — the caller compares it with the row's column. */
  author: string;
  signer: { userId: string; identityId: string };
  rev: number;
  legacy: boolean;
};

/** The public part the reader trusts for a signer identity, or null (unknown). */
export type SignerLookup = (identityId: string) => Promise<{ userId: string; edPk: Uint8Array } | null>;

export function uuidBytes(id: string): Bytes {
  const hex = id.replace(/-/g, "");
  if (!/^[0-9a-f]{32}$/i.test(hex)) throw new E2eError("format");
  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

export function bytesUuid(b: Uint8Array): string {
  const h = Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

function aad(b: RowBindingV2, signerIdentity: string, rev: number, flags: number): Bytes {
  return encodeFields(CTX_ROW, b.table, b.rowId, b.scopeId, b.keyVersion, encodeFields(...b.refs), signerIdentity, rev, flags);
}

function head(signerIdentity: string, rev: number, flags: number): Bytes {
  const h = new Uint8Array(HEAD);
  h[0] = ROW_FORMAT_V2;
  h.set(uuidBytes(signerIdentity), 1);
  new DataView(h.buffer).setUint32(17, rev);
  h[21] = flags;
  return h;
}

/**
 * What a blob's plaintext head says, unchecked — enough for the resealing
 * planner to decide what to do without opening the row: the format, and for
 * v2 the signing identity, revision and "Bestand" flag. null: neither format.
 */
export function rowHeadOf(
  blob: Uint8Array,
): { format: 1 } | { format: 2; identityId: string; rev: number; legacy: boolean } | null {
  if (blob[0] === 1) return { format: 1 };
  if (blob[0] !== ROW_FORMAT_V2 || blob.byteLength < HEAD) return null;
  try {
    return { format: 2, identityId: bytesUuid(blob.subarray(1, 17)), rev: rowRevOf(blob), legacy: (blob[21] & FLAG_LEGACY) !== 0 };
  } catch {
    return null;
  }
}

/** The revision in a v2 blob's head (unchecked — a writer counts on from it), else 0. */
export function rowRevOf(blob: Uint8Array): number {
  if (blob.byteLength < HEAD || blob[0] !== ROW_FORMAT_V2) return 0;
  return new DataView(blob.buffer, blob.byteOffset, blob.byteLength).getUint32(17);
}

/** The format byte of a stored blob (1 or 2), or null when it is neither. */
export function rowFormat(blob: Uint8Array): 1 | 2 | null {
  return blob[0] === 1 ? 1 : blob[0] === ROW_FORMAT_V2 ? 2 : null;
}

export async function encryptRowV2(
  key: CryptoKey,
  binding: RowBindingV2 & { author: string },
  fields: Record<string, unknown>,
  signer: RowSigner,
  rev: number,
  opts: { legacy?: boolean } = {},
): Promise<Bytes> {
  if (!Number.isInteger(rev) || rev < 1 || rev > 0xffffffff) throw new RangeError("encryptRowV2: rev");
  const flags = opts.legacy ? FLAG_LEGACY : 0;
  const a = aad(binding, signer.identityId, rev, flags);
  const sealed = await aesSeal(key, pad(utf8(JSON.stringify({ a: binding.author, f: fields }))), a);
  const sig = sign(signer.edSk, CTX_SIG, a, signer.userId, sealed);
  return concat(head(signer.identityId, rev, flags), sealed, sig);
}

type Parsed = { identityId: string; rev: number; flags: number; sealed: Uint8Array; sig: Uint8Array };

function parse(blob: Uint8Array): Parsed {
  if (blob.byteLength < HEAD + 12 + 16 + SIG || blob[0] !== ROW_FORMAT_V2) throw new E2eError("format");
  const identityId = bytesUuid(blob.subarray(1, 17));
  const rev = new DataView(blob.buffer, blob.byteOffset, blob.byteLength).getUint32(17);
  const flags = blob[21];
  if (rev < 1 || (flags & ~FLAG_LEGACY) !== 0) throw new E2eError("format");
  return { identityId, rev, flags, sealed: blob.subarray(HEAD, blob.byteLength - SIG), sig: blob.subarray(blob.byteLength - SIG) };
}

async function openPayload(key: CryptoKey, sealed: Uint8Array, a: Uint8Array): Promise<{ author: string; fields: Record<string, unknown> }> {
  const p = await aesOpen(key, sealed, a);
  const value: unknown = JSON.parse(fromUtf8(unpad(p)));
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new E2eError("format");
  const { a: author, f: fields } = value as { a?: unknown; f?: unknown };
  if (typeof author !== "string" || fields === null || typeof fields !== "object" || Array.isArray(fields)) {
    throw new E2eError("format");
  }
  return { author, fields: fields as Record<string, unknown> };
}

/**
 * Open a v2 blob. Throws E2eError: "format" (not v2 / malformed), "untrustedSender"
 * (signer unknown to this device), "signature", "decrypt" (wrong key or a
 * binding that does not match — the server moved or changed something).
 * The returned author is NOT yet compared with the row — the caller does.
 */
export async function decryptRowV2(
  key: CryptoKey,
  binding: RowBindingV2,
  blob: Uint8Array,
  lookup: SignerLookup,
): Promise<OpenedRowV2> {
  const { identityId, rev, flags, sealed, sig } = parse(blob);
  const signer = await lookup(identityId);
  if (!signer) throw new E2eError("untrustedSender");
  const a = aad(binding, identityId, rev, flags);
  if (!verify(signer.edPk, sig, CTX_SIG, a, signer.userId, sealed)) throw new E2eError("signature");
  const { author, fields } = await openPayload(key, sealed, a);
  return { fields, author, signer: { userId: signer.userId, identityId }, rev, legacy: (flags & FLAG_LEGACY) !== 0 };
}

/**
 * Open a v2 blob WITHOUT checking who signed it — for resealing only (the
 * owner taking over rows whose signer this device cannot check, e.g. after the
 * author's account was deleted). Never for display: the result is only as
 * trustworthy as "someone holding the scope key wrote it", which is exactly
 * what the "Bestand" flag says once the owner signs it anew.
 */
export async function openRowV2Unchecked(
  key: CryptoKey,
  binding: RowBindingV2,
  blob: Uint8Array,
): Promise<{ fields: Record<string, unknown>; author: string; signerIdentity: string; rev: number; legacy: boolean }> {
  const { identityId, rev, flags, sealed } = parse(blob);
  const { author, fields } = await openPayload(key, sealed, aad(binding, identityId, rev, flags));
  return { fields, author, signerIdentity: identityId, rev, legacy: (flags & FLAG_LEGACY) !== 0 };
}
