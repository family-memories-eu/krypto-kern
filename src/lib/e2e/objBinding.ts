// =============================================================================
// Media objects bound to their signed row (interne Prüfung K-03, P1 Teil C,
// docs/security-review/p1-teilc-karte.md). An object's key is derived from
// the scope key, its path and its row (objectKey.ts) — so anyone holding an
// old scope key (a former member, handing it to the server) could write a
// valid object for any row. The signed row therefore carries
//
//   obj: { <role>: <b64url SHA-256 of the stored ciphertext> }
//
// roles: full, thumb (photo; a video's poster), blocks (a video's block list),
// audio (story, chapter), cover, logo (family head).
//
// The check sits in ONE place instead of in every reader: objectKeyFor (the
// only source of object keys for reading) ties each key to its row here, the
// row openers note each opened row's `obj`, and the decrypt primitives
// (decryptBlob, the FMV2 chunk decrypt) ask `objectAllowed` before opening:
//
//   • key not tied to a row (writing, link keys)        → no check;
//   • row opened with `obj`                             → the hash must be one of them;
//   • row did not open (bad signature, rollback, …)     → refused;
//   • row without `obj` / never opened on this page     → only while the scope
//     is not yet "Medien gebunden" (owner-signed mark, sticky per device).
//
// Pure module state, no imports from the app: it sits under crypto.ts.
// =============================================================================

import { sha256, toB64url } from "@/lib/e2e/bytes";

export const OBJ_ROLES = ["full", "thumb", "blocks", "audio", "cover", "logo"] as const;
export type ObjRole = (typeof OBJ_ROLES)[number];
export type ObjHashes = Partial<Record<ObjRole, string>>;

/** The binding hash of a stored object: SHA-256 over its ciphertext, base64url. */
export async function cipherHash(bytes: Uint8Array): Promise<string> {
  return toB64url(await sha256(bytes));
}

/** `cipherHash` of a ciphertext blob (as uploaded). */
export async function blobHash(b: Blob): Promise<string> {
  return cipherHash(new Uint8Array(await b.arrayBuffer()));
}

const HASH_RE = /^[A-Za-z0-9_-]{43}$/;

/** The `obj` field of an opened row — null when absent or malformed (malformed counts as absent). */
export function objField(v: unknown): ObjHashes | null {
  if (!v || typeof v !== "object" || Array.isArray(v)) return null;
  const out: ObjHashes = {};
  for (const role of OBJ_ROLES) {
    const h = (v as Record<string, unknown>)[role];
    if (typeof h === "string" && HASH_RE.test(h)) out[role] = h;
  }
  return Object.keys(out).length ? out : null;
}

type RowEntry =
  | { state: "bound"; roles: ObjHashes; hashes: Set<string>; blocks?: BlockList }
  | { state: "none" }
  | { state: "refused" };

/** A video's verified block list: SHA-256 of the FMV2 header and of each chunk's ciphertext. */
export type BlockList = { header: string; chunks: string[] };

/** What a reading key was derived for: its row and scope, and where the object lies. */
export type KeyRow = { rowId: string; scopeId: string; path?: string; familyId?: string; collabStoryId?: string | null };

/**
 * Fetches, checks and opens a video's block list for a key's row (installed
 * by the app, lib/videoBlocks.ts): the list object's ciphertext must hash to
 * `expected`. Null when it cannot be had.
 */
export type BlockListLoader = (k: KeyRow, expected: string) => Promise<BlockList | null>;

const rows = new Map<string, RowEntry>();
const keyRows = new WeakMap<CryptoKey, KeyRow>();
const boundScopes = new Set<string>();
let loader: BlockListLoader | null = null;
const loading = new Map<string, Promise<BlockList | null>>();

/**
 * What an opened row says about its objects: its `obj` (null: none), or
 * "refused" when the row did not open — its objects are not shown either.
 */
export function noteRowObjects(rowId: string, obj: ObjHashes | null | "refused"): void {
  if (obj === "refused") {
    rows.set(rowId, { state: "refused" });
    return;
  }
  if (!obj) {
    rows.set(rowId, { state: "none" });
    return;
  }
  const prev = rows.get(rowId);
  const hashes = new Set(Object.values(obj));
  // A list already checked stays as long as the row still binds it.
  const blocks = prev?.state === "bound" && obj.blocks && prev.roles.blocks === obj.blocks ? prev.blocks : undefined;
  if (!blocks) loading.delete(rowId);
  rows.set(rowId, { state: "bound", roles: { ...obj }, hashes, ...(blocks ? { blocks } : {}) });
}

/** The scope is "Medien gebunden": from now on an object without a binding is refused. */
export function noteScopeMediaBound(scopeId: string): void {
  boundScopes.add(scopeId);
}

export function isScopeMediaBound(scopeId: string): boolean {
  return boundScopes.has(scopeId);
}

/** Tie a reading key to the row (and scope) of the object it was derived for. */
export function bindKeyToRow(key: CryptoKey, rowId: string, scopeId: string, at: Omit<KeyRow, "rowId" | "scopeId"> = {}): void {
  keyRows.set(key, { rowId, scopeId, ...at });
}

/** The row and scope a key was derived for (null: a key not tied to a row). */
export function rowOfKey(key: CryptoKey): KeyRow | null {
  return keyRows.get(key) ?? null;
}

/** Install the block-list loader (once, by the app). */
export function setBlockListLoader(fn: BlockListLoader): void {
  loader = fn;
}

/** The hashes the opened row binds (null: no binding, or the row is not known here). */
export function boundHashes(rowId: string): ReadonlySet<string> | null {
  const e = rows.get(rowId);
  return e?.state === "bound" ? e.hashes : null;
}

/** Without a binding: allowed only while the scope is not bound, and never for a refused row. */
function unboundAllowed(rowId: string, scopeId: string): boolean {
  const e = rows.get(rowId);
  if (e?.state === "refused") return false;
  return !boundScopes.has(scopeId);
}

/** May `bytes` (a whole stored object) be opened with `key`? */
export async function objectAllowed(key: CryptoKey, bytes: Uint8Array): Promise<boolean> {
  const k = keyRows.get(key);
  if (!k) return true;
  const e = rows.get(k.rowId);
  if (e?.state === "bound") return e.hashes.has(await cipherHash(bytes));
  return unboundAllowed(k.rowId, k.scopeId);
}

/** Note a video's checked block list (the loader, or a test). */
export function noteBlockList(rowId: string, list: BlockList): void {
  const e = rows.get(rowId);
  if (e?.state === "bound") e.blocks = list;
}

/**
 * The block list a reader must check a video's chunks against:
 *   "unbound" — no check (a key not tied to a row, or an unbound row in a scope not yet bound);
 *   a list    — checked against the row's signed `obj.blocks` (loaded once per row);
 *   null      — refused: the row did not open, binds no list, or the list cannot be had.
 */
export async function blockListForKey(key: CryptoKey): Promise<BlockList | "unbound" | null> {
  const k = keyRows.get(key);
  if (!k) return "unbound";
  const e = rows.get(k.rowId);
  if (e?.state !== "bound") return unboundAllowed(k.rowId, k.scopeId) ? "unbound" : null;
  if (e.blocks) return e.blocks;
  const expected = e.roles.blocks;
  if (!expected || !loader) return null;
  let p = loading.get(k.rowId);
  if (!p) {
    p = loader(k, expected).catch(() => null);
    loading.set(k.rowId, p);
    // A miss is not kept: the next attempt may get the list.
    void p.then((l) => {
      if (!l) loading.delete(k.rowId);
    });
  }
  const list = await p;
  const now = rows.get(k.rowId);
  if (!list || now?.state !== "bound" || now.roles.blocks !== expected) return null;
  now.blocks = list;
  return list;
}

/** The checked block list of a row's video (null: none checked yet). */
export function blockListOf(rowId: string): BlockList | null {
  const e = rows.get(rowId);
  return e?.state === "bound" ? (e.blocks ?? null) : null;
}

/**
 * May chunk `index` of an FMV2 video (header bytes `header`) be opened with
 * `key`? A bound row needs its checked block list (loaded on the first chunk,
 * blockListForKey) — without it nothing opens.
 */
export async function chunkAllowed(key: CryptoKey, header: Uint8Array, index: number, bytes: Uint8Array): Promise<boolean> {
  const list = await blockListForKey(key);
  if (list === "unbound") return true;
  if (!list || index < 0 || index >= list.chunks.length) return false;
  if (list.header !== (await cipherHash(header))) return false;
  return list.chunks[index] === (await cipherHash(bytes));
}

/** Tests only: forget everything. */
export function resetObjBindingForTests(): void {
  rows.clear();
  boundScopes.clear();
  loading.clear();
  loader = null;
}
