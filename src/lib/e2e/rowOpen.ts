// =============================================================================
// Opening encrypted rows on read (E2E Etappe 2 · E2.4, docs/e2e-design.md §4.3).
//
// A loader keeps a row's ciphertext as `Sealed` (the `enc` column as PostgREST
// returns it, plus `enc_key_version`); the screen's data hook opens it with the
// family's row keys (lib/clientApp/rowKeys.ts). Light on purpose — WebCrypto
// only, no HPKE or curves — so the data layer may import it statically.
//
// A row that cannot be opened (no key for its version on this device, vault
// locked, or a blob that does not belong to this row) yields null, never an
// exception: the screen shows a placeholder instead of failing the whole list.
// =============================================================================

import { fromPgBytea } from "./bytes";
import { decryptRow } from "./rowCrypto";
import { ROW_V2, v2BindingOf, type V2Table } from "./rowFields";
import type { LinkTable } from "./linkSig";
import type { RowRevisions, SignerBook, SignerContext } from "./rowVerify";

/**
 * A row's ciphertext as stored: `enc` (bytea, `\x…` hex) and its key version —
 * plus, for format v2, the references the AAD binds and the author column it is compared with, taken from the
 * SAME raw row the server sent (a changed column makes the row not open).
 */
export type Sealed = { enc: string; v: number; refs?: string[]; author?: string };

/** Every key version this device can open, as one kind of key. */
export type VersionKeys = ReadonlyMap<number, CryptoKey>;

/** What a v2 row is checked against (AP-Zeilen v2, rowVerify.ts). */
export type RowCheck = {
  signers: SignerBook;
  ctx: SignerContext;
  revisions: RowRevisions;
  /** The family said "v2 only" (owner-signed, sticky on this device): v1 no longer counts. */
  v2Only: boolean;
};

/**
 * The keys a reader opens rows with: v1 (the raw scope key), v2 (its HKDF row
 * key) and the check for v2. Without a check, v2 rows are "unverified".
 */
export type OpenKeys = {
  v1: VersionKeys;
  v2: VersionKeys;
  check: RowCheck | null;
  /** Media-seal keys for cover/logo in format v2 (`….s2.e2e.v<N>.enc`). */
  seal?: VersionKeys;
};

export const NO_OPEN_KEYS: OpenKeys = { v1: new Map(), v2: new Map(), check: null };

/**
 * The ciphertext of a raw row, or null for a plaintext row. With `table`, the
 * v2 binding (references, author) is read off the same row.
 */
export function sealedOf(row: Record<string, unknown>, table?: V2Table): Sealed | null {
  if (typeof row.enc !== "string" || typeof row.enc_key_version !== "number") return null;
  return { enc: row.enc, v: row.enc_key_version, ...(table ? v2BindingOf(table, row) : {}) };
}

/** Opened, no key on this device (yet), or present but failing a check (Z2). */
export type OpenState =
  // signedBy (v2 only): who signed it — the author, or the owner taking it over (S-10).
  | { state: "open"; fields: Record<string, unknown>; signedBy?: string }
  | { state: "locked" }
  | { state: "unverified" };

const LOCKED: OpenState = { state: "locked" };
const UNVERIFIED: OpenState = { state: "unverified" };

/**
 * Open one row for display. `table`, `rowId` and `scopeId` must be the row's
 * own. v1: opens with the raw key — unless the family is v2 only, or this
 * device has seen the row as v2 (rollback). v2: signature, signer rule and
 * revision must hold, else "unverified" — never the text.
 */
export async function openSealed(
  sealed: Sealed,
  keys: OpenKeys,
  at: { table: V2Table; rowId: string; scopeId: string },
): Promise<OpenState> {
  let blob: Uint8Array;
  try {
    blob = fromPgBytea(sealed.enc);
  } catch {
    return UNVERIFIED;
  }
  if (blob[0] === 1) {
    if (keys.check && (keys.check.v2Only || keys.check.revisions.seeV1(at.table, at.rowId) === "rollback")) {
      return UNVERIFIED;
    }
    const key = keys.v1.get(sealed.v);
    if (!key) return LOCKED;
    try {
      return { state: "open", fields: await decryptRow(key, { ...at, keyVersion: sealed.v }, blob) };
    } catch {
      return LOCKED;
    }
  }
  if (blob[0] !== 2) return UNVERIFIED;
  const key = keys.v2.get(sealed.v);
  if (!key) return LOCKED;
  const check = keys.check;
  if (!check || !sealed.refs || sealed.author === undefined) return UNVERIFIED;
  // Ed25519 and the checks only load once a v2 row is actually there.
  const [{ decryptRowV2 }, { signerAllowed }] = await Promise.all([import("./rowCryptoV2"), import("./rowVerify")]);
  const status = new Map<string, "current" | "previous">();
  try {
    const opened = await decryptRowV2(
      key,
      { ...at, keyVersion: sealed.v, refs: sealed.refs },
      blob,
      async (identityId) => {
        const s = await check.signers(identityId);
        if (s) status.set(identityId, s.status);
        return s;
      },
    );
    // The author sealed inside must be the row's: the server cannot hand a text
    // to someone else. A column emptied by an account deletion (0026) does not
    // match either — such rows wait for the owner to take them over (Bestand).
    if (opened.author !== sealed.author) return UNVERIFIED;
    const signer = { userId: opened.signer.userId, status: status.get(opened.signer.identityId) ?? "previous" };
    const row = { author: sealed.author, keyVersion: sealed.v, legacy: opened.legacy };
    if (!signerAllowed(ROW_V2[at.table].signers, signer, row, check.ctx)) return UNVERIFIED;
    if (check.revisions.seeV2(at.table, at.rowId, opened.rev) === "rollback") return UNVERIFIED;
    return { state: "open", fields: opened.fields, signedBy: opened.signer.userId };
  } catch {
    return UNVERIFIED;
  }
}

/**
 * Open a row to seal it anew (rotation re-index, resealing to v2) — NOT for
 * display. Like openSealed, except that a v2 row's signer need not be allowed
 * to sign it today: after a member was removed (the usual reason to rotate),
 * their tags no longer pass the member rule, yet must move to the new key.
 * The signature must still hold for a person this device knows, the author
 * must match, and an older revision is still refused; v1 opens as v1 does.
 */
export async function openForReseal(
  sealed: Sealed,
  keys: OpenKeys,
  at: { table: V2Table; rowId: string; scopeId: string },
): Promise<Record<string, unknown> | null> {
  let blob: Uint8Array;
  try {
    blob = fromPgBytea(sealed.enc);
  } catch {
    return null;
  }
  if (blob[0] === 1) {
    if (keys.check?.revisions.seeV1(at.table, at.rowId) === "rollback") return null;
    return openRow(sealed, keys.v1, at);
  }
  const key = keys.v2.get(sealed.v);
  const check = keys.check;
  if (blob[0] !== 2 || !key || !check || !sealed.refs || sealed.author === undefined) return null;
  const { decryptRowV2 } = await import("./rowCryptoV2");
  try {
    const opened = await decryptRowV2(key, { ...at, keyVersion: sealed.v, refs: sealed.refs }, blob, check.signers);
    if (opened.author !== sealed.author) return null;
    if (check.revisions.seeV2(at.table, at.rowId, opened.rev) === "rollback") return null;
    return opened.fields;
  } catch {
    return null;
  }
}

/**
 * Decrypt one v1 row (the writers' read-modify-write until they write v2).
 * Readers use openSealed. `table` and `rowId` must be the row's own — the AAD binds
 * the blob to them, so a ciphertext moved onto another row does not open.
 * `scopeId` is the family id (or the story id for collaborative stories, E2.8).
 */
export async function openRow(
  sealed: Sealed,
  keys: VersionKeys,
  binding: { table: string; rowId: string; scopeId: string },
): Promise<Record<string, unknown> | null> {
  const key = keys.get(sealed.v);
  if (!key) return null;
  try {
    return await decryptRow(key, { ...binding, keyVersion: sealed.v }, fromPgBytea(sealed.enc));
  } catch {
    return null;
  }
}

/** A link's signature as stored (0153): both null for an unsigned link. */
export type LinkSig = { sig: string | null; sigIdentity: string | null };

/**
 * Does a link (tag on a photo/story/album, timeline link) count? Signed: the
 * signature must hold and the signer may sign it (linkSig.ts). Unsigned: only
 * while the family is not v2 only. Without a check a signed link does not
 * count — it is never taken unchecked.
 */
export async function linkHolds(
  table: LinkTable,
  row: Record<string, unknown>,
  s: LinkSig,
  keys: OpenKeys,
): Promise<boolean> {
  const check = keys.check;
  if (!s.sig || !s.sigIdentity) return !check?.v2Only;
  if (!check) return false;
  const signer = await check.signers(s.sigIdentity);
  if (!signer) return false;
  const { linkSignerAllowed, verifyLink } = await import("./linkSig");
  if (!linkSignerAllowed(table, row, signer, check.ctx)) return false;
  try {
    return verifyLink(table, row, { userId: signer.userId, identityId: s.sigIdentity, edPk: signer.edPk }, fromPgBytea(s.sig));
  } catch {
    return false;
  }
}

/** A string field of an opened row, or null (absent or not a string). */
export function textField(fields: Record<string, unknown>, name: string): string | null {
  const v = fields[name];
  return typeof v === "string" ? v : null;
}

/** A calendar date field ("YYYY-MM-DD"), or null — never a malformed value. */
export function dateField(fields: Record<string, unknown>, name: string): string | null {
  const v = textField(fields, name);
  return v !== null && /^\d{4}-\d{2}-\d{2}$/.test(v) ? v : null;
}

/** A whole, non-negative number field, or null. */
export function countField(fields: Record<string, unknown>, name: string): number | null {
  const v = fields[name];
  return typeof v === "number" && Number.isInteger(v) && v >= 0 ? v : null;
}
