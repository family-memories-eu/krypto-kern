// =============================================================================
// The vault on this device (docs/e2e-design.md §5, §6) — the glue between the
// crypto core, the device store and Supabase (0117/0118). Browser-only.
//
// It gives every person an account key and the ways to carry it to a new
// device; the content keys themselves live in keyRing.ts.
//
// Every public key that comes back from the server is checked against what
// THIS device knows before use: our own identity against the account key we
// hold (a server that swaps it is detected as "locked", not trusted), other
// people's keys through the trust store.
// =============================================================================

import type { SupabaseClient } from "@supabase/supabase-js";

import { IS_APP_BUILD } from "@/lib/clientApp/buildTarget";

import { passkeyWrapKey, unwrapAccountKey, wrapAccountKey } from "./akWrap";
import {
  aesOpen,
  aesSeal,
  E2eError,
  encodeFields,
  fromB64url,
  fromPgBytea,
  fromUtf8,
  importAesKey,
  randomBytes,
  sha256,
  toB64url,
  toPgBytea,
  utf8,
  type Bytes,
} from "./bytes";
import {
  forgetDevice,
  indexedDbStore,
  loadAccountKey,
  loadTrustStore,
  saveAccountKey,
  mergeIntoTrustStore,
  type KeyValueStore,
} from "./deviceStore";
import { generateAccountKey, selfSign, sign, verify, type AccountKey } from "./identity";
import {
  generateRecoveryCode,
  newRecoverySalt,
  RECOVERY_ARGON2,
  recoveryWrapKey,
  type Argon2Params,
} from "./recoveryCode";
import { hpkeOpen, hpkeSeal } from "./hpke";
import { openPairingTransfer, sealPairingTransfer, signBackup, signStartOverCancel, verifyBackup } from "./statements";
import { newEphemeralKeyPair, pairingCode, pairingCommitment, requestCode } from "./trustCodes";
import { mergeTrustStores, parseTrustStore, type TrustStore } from "./trustStore";


export type VaultDeps = {
  supabase: SupabaseClient;
  userId: string;
  kv?: KeyValueStore;
};

export type VaultReady = { kind: "ready"; ak: AccountKey; identityId: string; created: boolean };
/** `replaced`: this device holds an account key that is no longer the account's (KP-04, e.g. after „Neu anfangen“ elsewhere). */
export type VaultLocked = { kind: "locked"; recovery: boolean; passkeys: number; replaced?: boolean };
/** „Neu anfangen“ from THIS device: its new key waits until `activatesAt` (0151). */
/** `code`: the request code of the waiting key (S-08) — the mail shows the same. */
export type VaultWaiting = { kind: "waiting"; activatesAt: string; code: string };
/**
 * No account key on the server and none here, but the account already belongs
 * to a family or story (S-02): before a new key is made, the person is asked
 * whether this is really their first device — a server that hides an existing
 * key would otherwise get a fresh one accepted without a word.
 */
export type VaultFirstDevice = { kind: "first-device" };
export type VaultStatus = VaultReady | VaultLocked | VaultWaiting | VaultFirstDevice;

// --- Where this device's account key came from (S-02, P1-3) -----------------------
//
// "first": made here as the person's very first key — a newcomer device, the
// only one that may take senders on first use (keyRing pass 2). "later": taken
// over (pairing, recovery code, passkey) or made by starting over — such a
// device trusts nobody on first use: unknown senders become cards. Absent: a
// device from before 18.10.2026 (kept as it was).
export type AkOrigin = "first" | "later";
const originKey = (userId: string) => `akOrigin:${userId}`;

export async function akOriginOf(kv: KeyValueStore, userId: string): Promise<AkOrigin | null> {
  return (await kv.get<AkOrigin>(originKey(userId))) ?? null;
}

async function setAkOrigin(d: VaultDeps, origin: AkOrigin): Promise<void> {
  await kvOf(d).set(originKey(d.userId), origin);
}

/** Whether the account already belongs to a family or a collaborative story. */
async function accountHasScopes(d: VaultDeps): Promise<boolean> {
  const [{ count: fam, error: e1 }, { count: col, error: e2 }] = await Promise.all([
    d.supabase.from("family_members").select("family_id", { count: "exact", head: true }).eq("user_id", d.userId),
    d.supabase.from("story_collaborators").select("story_id", { count: "exact", head: true }).eq("user_id", d.userId),
  ]);
  if (e1 || e2) throw e1 ?? e2;
  return (fam ?? 0) + (col ?? 0) > 0;
}

const kvOf = (d: VaultDeps) => (d.kv ??= indexedDbStore());

type IdentityRow = { id: string; x25519_pub: string; ed25519_pub: string };

async function activeIdentity(d: VaultDeps): Promise<IdentityRow | null> {
  const { data, error } = await d.supabase
    .from("user_identity_keys")
    .select("id, x25519_pub, ed25519_pub")
    .eq("user_id", d.userId)
    .is("replaced_at", null)
    .maybeSingle();
  if (error) throw error;
  return (data as IdentityRow | null) ?? null;
}

function matches(row: { x25519_pub: string; ed25519_pub: string }, ak: AccountKey): boolean {
  return (
    toB64url(fromPgBytea(row.x25519_pub)) === toB64url(ak.x25519Pub) &&
    toB64url(fromPgBytea(row.ed25519_pub)) === toB64url(ak.edPk)
  );
}

/** Placeholder id of a key saved on this device before the server has it. */
const PENDING_ID = "pending";

/**
 * Save a new account key on this device FIRST, then publish it, then save it
 * again under its real id. The other way round, a publish that got through
 * with a save that did not left the account on a key no device holds — every
 * device locked, a rescue and a rotation forced (finding k, 12.10.2026).
 */
async function saveThenPublish(d: VaultDeps, ak: AccountKey): Promise<string> {
  const kv = kvOf(d);
  await saveAccountKey(kv, d.userId, ak, PENDING_ID);
  const identityId = await publish(d, ak);
  await saveAccountKey(kv, d.userId, ak, identityId);
  return identityId;
}

async function publish(d: VaultDeps, ak: AccountKey): Promise<string> {
  const { data, error } = await d.supabase.rpc("e2e_publish_identity_key", {
    _x25519_pub: toPgBytea(ak.x25519Pub),
    _ed25519_pub: toPgBytea(ak.edPk),
    _self_sig: toPgBytea(selfSign(ak, d.userId)),
  });
  if (error) throw error;
  return data as string;
}

/** Which ways back exist for this account key (recovery code, passkeys). */
type BackupRow = {
  kind: "recovery" | "passkey";
  credential_id: string;
  identity_id: string;
  wrapped_ak: string;
  sig: string | null;
};

/**
 * The backup rows that count (S-11, 0171): signed by the account key they
 * belong to — or unsigned, which since 0171 only a row from before can be (the
 * database refuses a new one without a signature). A row someone put in with
 * only my session carries no valid signature: it neither silences the
 * reminder nor is offered for unlocking.
 */
async function countingBackups<T extends BackupRow>(d: VaultDeps, rows: T[]): Promise<T[]> {
  const pubs = new Map<string, Uint8Array | null>();
  const out: T[] = [];
  for (const r of rows) {
    if (r.sig == null) {
      out.push(r);
      continue;
    }
    if (!pubs.has(r.identity_id)) {
      const { data } = await d.supabase.from("user_identity_keys").select("ed25519_pub").eq("id", r.identity_id).maybeSingle();
      const edPub = (data as { ed25519_pub: string } | null)?.ed25519_pub;
      pubs.set(r.identity_id, edPub ? fromPgBytea(edPub) : null);
    }
    const edPk = pubs.get(r.identity_id);
    if (!edPk) continue;
    try {
      const statement = {
        userId: d.userId,
        kind: r.kind,
        credentialId: r.credential_id,
        identityId: r.identity_id,
        wrappedHash: await sha256(fromPgBytea(r.wrapped_ak)),
      };
      if (verifyBackup(edPk, statement, fromPgBytea(r.sig))) out.push(r);
    } catch {
      // malformed: does not count
    }
  }
  return out;
}

/** My signature over a backup row (S-11). */
async function backupSig(
  d: VaultDeps,
  ready: VaultReady,
  kind: "recovery" | "passkey",
  credentialId: string,
  wrapped: Uint8Array,
): Promise<string> {
  const wrappedHash = await sha256(wrapped);
  return toPgBytea(signBackup(ready.ak, { userId: d.userId, kind, credentialId, identityId: ready.identityId, wrappedHash }));
}

async function myBackups(d: VaultDeps, identityId: string): Promise<(BackupRow & { created_at: string })[]> {
  const { data, error } = await d.supabase
    .from("ak_backups")
    .select("kind, credential_id, identity_id, wrapped_ak, sig, created_at")
    .eq("user_id", d.userId)
    .eq("identity_id", identityId);
  if (error) throw error;
  return countingBackups(d, (data ?? []) as (BackupRow & { created_at: string })[]);
}

export async function backupSummary(d: VaultDeps, identityId: string): Promise<{ recovery: boolean; passkeys: number }> {
  const rows = await myBackups(d, identityId);
  return {
    recovery: rows.some((r) => r.kind === "recovery"),
    passkeys: rows.filter((r) => r.kind === "passkey").length,
  };
}

/** My passkeys for this account key, oldest first (S-11c: each can be removed). */
export async function listPasskeys(d: VaultDeps, identityId: string): Promise<{ credentialId: string; createdAt: string }[]> {
  return (await myBackups(d, identityId))
    .filter((r) => r.kind === "passkey")
    .map((r) => ({ credentialId: r.credential_id, createdAt: r.created_at }))
    .sort((a, b) => a.createdAt.localeCompare(b.createdAt));
}

/**
 * Remove one passkey as a way to unlock (S-11c, decision P3-6): only through
 * the server route — fresh login, and a mail every time. E2eError("freshLogin")
 * → the person signs in again first.
 */
export async function removePasskey(d: VaultDeps, credentialId: string, locale?: string): Promise<void> {
  const res = await postApi(d, "/api/e2e/passkey/remove", { credentialId, locale });
  if (res.error === "freshLogin") throw new E2eError("freshLogin");
  if (res.ok !== true) throw new E2eError("format");
}

async function lockedStatus(d: VaultDeps, identityId: string, replaced = false): Promise<VaultLocked> {
  return { kind: "locked", ...(await backupSummary(d, identityId)), ...(replaced ? { replaced: true } : {}) };
}

/**
 * Called once per page load of the private area.
 *   device key matches server  → ready
 *   no key anywhere            → create, publish, ready (created: true)
 *   server has a different key → locked (unlock or pair this device)
 */
export async function bootstrapVault(d: VaultDeps): Promise<VaultStatus> {
  const kv = kvOf(d);
  const [onDevice, server] = await Promise.all([loadAccountKey(kv, d.userId), activeIdentity(d)]);

  if (onDevice && server && matches(server, onDevice.ak)) {
    // Saved before publishing (PENDING_ID) and the publish got through: now
    // the real id goes with it.
    if (server.id !== onDevice.identityId) await saveAccountKey(kv, d.userId, onDevice.ak, server.id);
    return { kind: "ready", ak: onDevice.ak, identityId: server.id, created: false };
  }
  if (!server) {
    // The server lost the row: republish what we hold.
    if (onDevice) {
      const identityId = await saveThenPublish(d, onDevice.ak);
      return { kind: "ready", ak: onDevice.ak, identityId, created: false };
    }
    // First device ever — unless the account is already in a family: then ask
    // first (S-02), a key may exist on another device that the server hides.
    if (await accountHasScopes(d)) return { kind: "first-device" };
    return createFirstAccountKey(d);
  }
  // This device asked for a new key that still waits its 24 hours (0151).
  const pending = onDevice ? await ownPendingRequest(d) : null;
  if (pending && onDevice && matches(pending, onDevice.ak)) {
    return { kind: "waiting", activatesAt: pending.activates_at, code: await requestCode(d.userId, onDevice.ak.edPk) };
  }
  // The server's current key is not the one on this device: replaced from
  // another device (rescue), or swapped by someone. Either way: not trusted.
  return lockedStatus(d, server.id, !!onDevice);
}

async function adopt(d: VaultDeps, ak: AccountKey): Promise<VaultReady> {
  const server = await activeIdentity(d);
  // A backup or pairing that delivers a key the server no longer lists as ours
  // is stale (or the server lies) — refuse rather than resurrect it.
  if (!server || !matches(server, ak)) throw new E2eError("binding");
  await saveAccountKey(kvOf(d), d.userId, ak, server.id);
  await setAkOrigin(d, "later");
  return { kind: "ready", ak, identityId: server.id, created: false };
}

/**
 * Make and publish the person's very first account key on this device — after
 * bootstrapVault found none, or after the person answered „yes, my first
 * device“ (first-device). A key that turned up on the server meanwhile wins:
 * then this device is locked (pair it), nothing is replaced.
 */
export async function createFirstAccountKey(d: VaultDeps): Promise<VaultStatus> {
  const server = await activeIdentity(d);
  if (server) return lockedStatus(d, server.id);
  const ak = generateAccountKey();
  const identityId = await saveThenPublish(d, ak);
  await setAkOrigin(d, "first");
  return { kind: "ready", ak, identityId, created: true };
}

// --- Recovery code (design §6.3) ---------------------------------------------

export async function hasRecoveryCode(d: VaultDeps, identityId: string): Promise<boolean> {
  return (await myBackups(d, identityId)).some((r) => r.kind === "recovery");
}

/** A recovery code made on this device, not stored yet. */
export type PreparedRecoveryCode = {
  code: string;
  row: { identity_id: string; salt: string; kdf_params: Argon2Params; wrapped_ak: string; sig: string };
};

/**
 * Make a recovery code — NOT stored yet: the person first shows they wrote it
 * down (two groups typed back), then storeRecoveryCode replaces the old one.
 * Storing first would have made the old code invalid even when the person
 * gave up half way (finding, 12.10.2026).
 */
export async function prepareRecoveryCode(
  d: VaultDeps,
  ready: VaultReady,
  params: Argon2Params = RECOVERY_ARGON2,
): Promise<PreparedRecoveryCode> {
  const code = generateRecoveryCode();
  const salt = newRecoverySalt();
  const blob = await wrapAccountKey(await recoveryWrapKey(code, salt, params), ready.ak, "recovery", d.userId);
  return {
    code,
    row: {
      identity_id: ready.identityId,
      salt: toPgBytea(salt),
      kdf_params: params,
      wrapped_ak: toPgBytea(blob),
      sig: await backupSig(d, ready, "recovery", "", blob),
    },
  };
}

/**
 * The FIRST recovery code goes in directly; REPLACING one only through the
 * server route (0151): fresh login, then a mail "your recovery code was
 * renewed". E2eError("freshLogin") → the person signs in again first.
 */
export async function storeRecoveryCode(d: VaultDeps, prepared: PreparedRecoveryCode, locale?: string): Promise<void> {
  const { error } = await d.supabase
    .from("ak_backups")
    .insert({ user_id: d.userId, kind: "recovery", credential_id: "", ...prepared.row });
  if (!error) return;
  if ((error as { code?: string }).code !== "23505") throw error;
  const res = await postApi(d, "/api/e2e/recovery", {
    identityId: prepared.row.identity_id,
    salt: prepared.row.salt,
    kdfParams: prepared.row.kdf_params,
    wrappedAk: prepared.row.wrapped_ak,
    sig: prepared.row.sig,
    locale,
  });
  if (res.error === "freshLogin") throw new E2eError("freshLogin");
  if (res.ok !== true) throw new E2eError("format");
}

/** POST to one of our API routes (cookie on the web, bearer in the app). */
async function postApi(d: VaultDeps, path: string, body: unknown): Promise<{ ok?: boolean; error?: string } & Record<string, unknown>> {
  const { apiFetch } = await import("@/lib/clientApp/apiFetch");
  const res = await apiFetch(d.supabase, path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  return (await res.json().catch(() => ({ ok: false }))) as { ok?: boolean; error?: string };
}

/** Make and store at once (tests, and nothing a person has to read). */
export async function createRecoveryCode(d: VaultDeps, ready: VaultReady, params: Argon2Params = RECOVERY_ARGON2): Promise<string> {
  const prepared = await prepareRecoveryCode(d, ready, params);
  await storeRecoveryCode(d, prepared);
  return prepared.code;
}

/**
 * The Argon2 parameters a device accepts from the server row (finding 4,
 * 12.10.2026): never weaker than the ones it writes, never so large that the
 * service could hang the device. Tests pass their own (fast) bounds.
 */
export type Argon2Bounds = { min: Argon2Params; max: Argon2Params };
export const RECOVERY_ARGON2_BOUNDS: Argon2Bounds = {
  min: RECOVERY_ARGON2,
  max: { memoryKiB: 256 * 1024, iterations: 10, parallelism: 4 },
};

function withinBounds(p: Argon2Params | null | undefined, b: Argon2Bounds): p is Argon2Params {
  const ok = (k: keyof Argon2Params) =>
    !!p && Number.isInteger(p[k]) && p[k] >= b.min[k] && p[k] <= b.max[k];
  return ok("memoryKiB") && ok("iterations") && ok("parallelism");
}

export async function unlockWithRecoveryCode(
  d: VaultDeps,
  code: string,
  bounds: Argon2Bounds = RECOVERY_ARGON2_BOUNDS,
): Promise<VaultReady> {
  const { data, error } = await d.supabase
    .from("ak_backups")
    .select("kind, credential_id, identity_id, salt, kdf_params, wrapped_ak, sig")
    .eq("user_id", d.userId)
    .eq("kind", "recovery")
    .maybeSingle();
  if (error) throw error;
  type RecoveryRow = BackupRow & { salt: string; kdf_params: Argon2Params };
  const [row] = data ? await countingBackups(d, [data as RecoveryRow]) : [];
  if (!row) throw new E2eError("recoveryCode");
  if (!withinBounds(row.kdf_params, bounds)) throw new E2eError("format");
  const key = await recoveryWrapKey(code, fromPgBytea(row.salt), row.kdf_params);
  const ak = await unwrapAccountKey(key, fromPgBytea(row.wrapped_ak), "recovery", d.userId);
  return adopt(d, ak);
}

// --- Passkey (design §6.4) ----------------------------------------------------

type PrfResults = { prf?: { enabled?: boolean; results?: { first?: ArrayBuffer } } };

export function passkeySupported(): boolean {
  // AP-Android (A2): not in the app — its WebView origin is https://localhost,
  // so a passkey would be bound to "localhost" instead of family-memories.eu
  // and be of no use anywhere else. The app unlocks through the Keystore.
  if (IS_APP_BUILD) return false;
  return typeof window !== "undefined" && "PublicKeyCredential" in window && !!navigator.credentials;
}

/**
 * Does this browser say it can do PRF? `getClientCapabilities` (where it
 * exists) answers before a passkey is made — without it, an authenticator
 * without PRF only shows up after `create`, leaving an unusable passkey behind
 * (finding k, 12.10.2026). Unknown → true: try, as before.
 */
export async function passkeyPrfLikely(): Promise<boolean> {
  if (!passkeySupported()) return false;
  const pkc = PublicKeyCredential as unknown as { getClientCapabilities?: () => Promise<Record<string, boolean>> };
  if (typeof pkc.getClientCapabilities !== "function") return true;
  try {
    return (await pkc.getClientCapabilities())["extension:prf"] !== false;
  } catch {
    return true;
  }
}

export class PasskeyUnsupportedError extends Error {
  constructor() {
    super("passkey-prf-unsupported");
    this.name = "PasskeyUnsupportedError";
  }
}

async function prfFor(credentialId: Uint8Array, salt: Uint8Array): Promise<ArrayBuffer> {
  const assertion = (await navigator.credentials.get({
    publicKey: {
      challenge: randomBytes(32),
      rpId: location.hostname,
      allowCredentials: [{ type: "public-key", id: credentialId as BufferSource }],
      userVerification: "required",
      extensions: { prf: { eval: { first: salt } } } as AuthenticationExtensionsClientInputs,
    },
  })) as PublicKeyCredential | null;
  const out = (assertion?.getClientExtensionResults() as PrfResults | undefined)?.prf?.results?.first;
  if (!out) throw new PasskeyUnsupportedError();
  return out;
}

export async function registerPasskey(d: VaultDeps, ready: VaultReady, label: string): Promise<void> {
  if (!(await passkeyPrfLikely())) throw new PasskeyUnsupportedError();
  const salt = randomBytes(32);
  const cred = (await navigator.credentials.create({
    publicKey: {
      rp: { name: "Family Memories", id: location.hostname },
      user: { id: utf8(d.userId), name: label, displayName: label },
      challenge: randomBytes(32),
      pubKeyCredParams: [
        { type: "public-key", alg: -7 },
        { type: "public-key", alg: -257 },
      ],
      authenticatorSelection: { residentKey: "required", userVerification: "required" },
      extensions: { prf: { eval: { first: salt } } } as AuthenticationExtensionsClientInputs,
    },
  })) as PublicKeyCredential | null;
  if (!cred) throw new PasskeyUnsupportedError();
  const ext = cred.getClientExtensionResults() as PrfResults;
  if (!ext.prf?.enabled && !ext.prf?.results?.first) throw new PasskeyUnsupportedError();
  const rawId = new Uint8Array(cred.rawId);
  // Some authenticators return the PRF output at creation, most only on use.
  const out = ext.prf.results?.first ?? (await prfFor(rawId, salt));
  const credentialId = toB64url(rawId);
  const blob = await wrapAccountKey(
    await passkeyWrapKey(new Uint8Array(out), credentialId),
    ready.ak,
    "passkey",
    d.userId,
    credentialId,
  );
  const { error } = await d.supabase.from("ak_backups").insert({
    user_id: d.userId,
    kind: "passkey",
    credential_id: credentialId,
    identity_id: ready.identityId,
    salt: toPgBytea(salt),
    wrapped_ak: toPgBytea(blob),
    sig: await backupSig(d, ready, "passkey", credentialId, blob),
  });
  if (error) throw error;
}

export async function unlockWithPasskey(d: VaultDeps): Promise<VaultReady> {
  if (!passkeySupported()) throw new PasskeyUnsupportedError();
  const { data, error } = await d.supabase
    .from("ak_backups")
    .select("kind, credential_id, identity_id, salt, wrapped_ak, sig")
    .eq("user_id", d.userId)
    .eq("kind", "passkey");
  if (error) throw error;
  const rows = await countingBackups(d, (data ?? []) as (BackupRow & { salt: string })[]);
  if (rows.length === 0) throw new PasskeyUnsupportedError();

  const evalByCredential: Record<string, { first: Bytes }> = {};
  for (const r of rows) evalByCredential[r.credential_id] = { first: fromPgBytea(r.salt) };
  const assertion = (await navigator.credentials.get({
    publicKey: {
      challenge: randomBytes(32),
      rpId: location.hostname,
      allowCredentials: rows.map((r) => ({ type: "public-key" as const, id: fromB64url(r.credential_id) })),
      userVerification: "required",
      extensions: { prf: { evalByCredential } } as AuthenticationExtensionsClientInputs,
    },
  })) as PublicKeyCredential | null;
  if (!assertion) throw new PasskeyUnsupportedError();
  const used = toB64url(new Uint8Array(assertion.rawId));
  const row = rows.find((r) => r.credential_id === used);
  const out = (assertion.getClientExtensionResults() as PrfResults).prf?.results?.first;
  if (!row || !out) throw new PasskeyUnsupportedError();
  const ak = await unwrapAccountKey(
    await passkeyWrapKey(new Uint8Array(out), used),
    fromPgBytea(row.wrapped_ak),
    "passkey",
    d.userId,
    used,
  );
  return adopt(d, ak);
}

// --- Pairing (design §5.2) ------------------------------------------------------

const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

export function newPairingShortCode(): string {
  return Array.from(randomBytes(8), (b) => CROCKFORD[b & 31]).join("");
}

export function normalizePairingShortCode(input: string): string {
  return input.toUpperCase().replace(/[\s-]/g, "").replace(/O/g, "0").replace(/[IL]/g, "1");
}

type PairingRow = {
  id: string;
  /** H(new device key, nonce) — null only in rows of an app from before 12.10.2026. */
  commitment: string | null;
  /** Revealed by the new device only after the old one has put down its key. */
  new_device_pub: string | null;
  nonce: string;
  old_device_pub: string | null;
  enc: string | null;
  ct: string | null;
};

const PAIRING_COLUMNS = "id, commitment, new_device_pub, nonce, old_device_pub, enc, ct";

export type NewDevicePairing = {
  id: string;
  shortCode: string;
  /** Fragment for the QR link — the server never sees it. */
  fragment: string;
  /** Resolves with the six-digit code once the old device has answered. */
  waitForCode(signal: AbortSignal): Promise<string>;
  /**
   * The human said "the codes match" on THIS device too (P1-4, K-02). Until
   * then a key that arrives is not taken: only comparing on both screens shows
   * that nobody sat between the two devices.
   */
  confirm(): void;
  /**
   * Resolves when the old device has sent the key AND this device confirmed.
   * The old device's trust store comes along and is merged in (S-02).
   */
  waitForKey(signal: AbortSignal): Promise<VaultReady>;
};

const POLL_MS = 2000;

async function poll<T>(signal: AbortSignal, step: () => Promise<T | null>): Promise<T> {
  for (;;) {
    if (signal.aborted) throw new DOMException("aborted", "AbortError");
    const v = await step();
    if (v !== null) return v;
    await new Promise((r) => setTimeout(r, POLL_MS));
  }
}

const sameBytes = (a: Uint8Array, b: Uint8Array) => toB64url(a) === toB64url(b);

/**
 * The new device (design §5.2, commitment: trustCodes.ts). It puts down only
 * H(key, nonce); once the old device's key is in the row it remembers THAT key
 * and only then reveals its own. Everything after uses the key it saw first.
 */
export async function startPairingAsNewDevice(d: VaultDeps): Promise<NewDevicePairing> {
  const eph = newEphemeralKeyPair();
  const nonce = randomBytes(16);
  const shortCode = newPairingShortCode();
  const { data, error } = await d.supabase
    .from("device_pairings")
    .insert({
      user_id: d.userId,
      commitment: toPgBytea(await pairingCommitment(eph.pub, nonce)),
      nonce: toPgBytea(nonce),
      code: shortCode,
    })
    .select("id")
    .single();
  if (error) throw error;
  const id = (data as { id: string }).id;

  const fetchRow = async () => {
    const { data: row, error: e } = await d.supabase.from("device_pairings").select(PAIRING_COLUMNS).eq("id", id).maybeSingle();
    if (e) throw e;
    if (!row) throw new E2eError("binding"); // expired or deleted
    return row as PairingRow;
  };

  let oldPub: Bytes | null = null;
  let confirmedHere = false;
  /** The old device's key as first seen, revealing ours right after; null while it has not answered. */
  const answered = async (row: PairingRow): Promise<Bytes | null> => {
    if (!row.old_device_pub) return null;
    const seen = fromPgBytea(row.old_device_pub);
    if (oldPub && !sameBytes(oldPub, seen)) throw new E2eError("mismatch");
    if (!oldPub) {
      oldPub = seen;
      const { error: e } = await d.supabase
        .from("device_pairings")
        .update({ new_device_pub: toPgBytea(eph.pub) })
        .eq("id", id)
        .is("new_device_pub", null);
      if (e) throw e;
    }
    return oldPub;
  };

  return {
    id,
    shortCode,
    fragment: `p=${id}&k=${toB64url(eph.pub)}&n=${toB64url(nonce)}`,
    waitForCode: (signal) =>
      poll(signal, async () => {
        const old = await answered(await fetchRow());
        return old ? pairingCode(eph.priv, old, eph.pub, old, nonce) : null;
      }),
    confirm: () => {
      confirmedHere = true;
    },
    waitForKey: (signal) =>
      poll(signal, async () => {
        if (!confirmedHere) return null;
        const row = await fetchRow();
        const old = await answered(row);
        if (!old || !row.enc || !row.ct) return null;
        const { ak, trust } = await openPairingTransfer({
          newDevicePriv: eph.priv,
          userId: d.userId,
          nonce,
          newDevicePub: eph.pub,
          oldDevicePub: old,
          enc: fromPgBytea(row.enc),
          ct: fromPgBytea(row.ct),
        });
        const ready = await adopt(d, ak);
        // Start with whom my other device trusts — authenticated by the compared code.
        if (trust) await mergeIntoTrustStore(kvOf(d), d.userId, parseTrustStore(trust)).catch(() => undefined);
        await d.supabase.from("device_pairings").delete().eq("id", id);
        return ready;
      }),
  };
}

export type OldDevicePairing = { code: string; confirm(): Promise<void> };

/**
 * On the device that already has the key.
 *   QR: the new device's key and nonce come straight from its screen and must
 *       match the row's commitment (or, in an old row, its key).
 *   Short code: both keys travel through the server, so a row WITHOUT a
 *       commitment is refused; after putting down our key we wait for the new
 *       device to reveal its own and check it against the commitment — whoever
 *       relays has had to fix their key before seeing ours.
 */
export async function answerPairingAsOldDevice(
  d: VaultDeps,
  ready: VaultReady,
  target: { shortCode: string } | { fragment: string },
  signal: AbortSignal = AbortSignal.timeout(10 * 60_000),
): Promise<OldDevicePairing> {
  let query = d.supabase.from("device_pairings").select(PAIRING_COLUMNS);
  let qrPub: Bytes | null = null;
  let qrNonce: Bytes | null = null;
  if ("fragment" in target) {
    const p = new URLSearchParams(target.fragment.replace(/^#/, ""));
    const id = p.get("p");
    if (!id || !p.get("k") || !p.get("n")) throw new E2eError("format");
    qrPub = fromB64url(p.get("k")!);
    qrNonce = fromB64url(p.get("n")!);
    query = query.eq("id", id);
  } else {
    query = query.eq("code", normalizePairingShortCode(target.shortCode));
  }
  const { data, error } = await query.maybeSingle();
  if (error) throw error;
  if (!data) throw new E2eError("binding");
  const row = data as PairingRow;
  const nonce = fromPgBytea(row.nonce);
  const commitment = row.commitment ? fromPgBytea(row.commitment) : null;
  if (row.old_device_pub) throw new E2eError("binding"); // answered already

  if (qrPub) {
    // The screen of the new device and the server must agree.
    const fits = commitment
      ? sameBytes(qrNonce!, nonce) && sameBytes(await pairingCommitment(qrPub, qrNonce!), commitment)
      : !!row.new_device_pub && sameBytes(qrPub, fromPgBytea(row.new_device_pub)) && sameBytes(qrNonce!, nonce);
    if (!fits) throw new E2eError("mismatch");
  } else if (!commitment) {
    throw new E2eError("binding"); // an old row: the short code is only safe with a commitment
  }

  const eph = newEphemeralKeyPair();
  const { data: put, error: e1 } = await d.supabase
    .from("device_pairings")
    .update({ old_device_pub: toPgBytea(eph.pub) })
    .eq("id", row.id)
    .is("old_device_pub", null)
    .select("id");
  if (e1) throw e1;
  if (!put || (put as unknown[]).length !== 1) throw new E2eError("binding");

  const newPub =
    qrPub ??
    (await poll(signal, async () => {
      const { data: now, error: e } = await d.supabase.from("device_pairings").select(PAIRING_COLUMNS).eq("id", row.id).maybeSingle();
      if (e) throw e;
      if (!now) throw new E2eError("binding");
      const r = now as PairingRow;
      if (!r.new_device_pub) return null;
      const revealed = fromPgBytea(r.new_device_pub);
      if (!sameBytes(await pairingCommitment(revealed, nonce), commitment!)) throw new E2eError("mismatch");
      return revealed;
    }));
  const code = await pairingCode(eph.priv, newPub, newPub, eph.pub, nonce);

  return {
    code,
    async confirm() {
      const trust = await loadTrustStore(kvOf(d), d.userId).catch(() => null);
      const { enc, ct } = await sealPairingTransfer({
        ak: ready.ak,
        trust: trust ? JSON.stringify(trust) : null,
        userId: d.userId,
        nonce,
        oldDevicePriv: eph.priv,
        newDevicePub: newPub,
        oldDevicePub: eph.pub,
      });
      const { error: e2 } = await d.supabase
        .from("device_pairings")
        .update({ enc: toPgBytea(enc), ct: toPgBytea(ct) })
        .eq("id", row.id);
      if (e2) throw e2;
    },
  };
}

// --- Start over / forget ----------------------------------------------------------

/**
 * Nothing left to unlock with: a NEW account key. Other members will see
 * "has a new device" and must confirm before anything is shared again
 * (design §6.2).
 */
type PendingRow = { x25519_pub: string; ed25519_pub: string; activates_at: string };

/** My waiting new account key, if any (0151; RLS: own row only). */
export async function ownPendingRequest(d: VaultDeps): Promise<PendingRow | null> {
  const { data, error } = await d.supabase
    .from("pending_identity_keys")
    .select("x25519_pub, ed25519_pub, activates_at")
    .eq("user_id", d.userId)
    .maybeSingle();
  if (error) return null; // before 0151 the table is missing: nothing waits
  return (data as PendingRow | null) ?? null;
}

/** The request code of a waiting key as the server lists it (S-08). */
export async function pendingRequestCode(userId: string, row: PendingRow): Promise<string> {
  return requestCode(userId, fromPgBytea(row.ed25519_pub));
}

/**
 * „Das war ich nicht“ from one of my own devices (0151, S-08): signed with my
 * CURRENT account key over exactly this waiting key — a session alone cannot
 * cancel (0171). False when nothing waits (any more).
 */
export async function cancelOwnPendingRequest(d: VaultDeps, ready: VaultReady): Promise<boolean> {
  const pending = await ownPendingRequest(d);
  if (!pending) return false;
  const sig = signStartOverCancel(ready.ak, d.userId, fromPgBytea(pending.ed25519_pub));
  const res = await postApi(d, "/api/e2e/start-over/withdraw", { sig: toB64url(sig) });
  if (res.ok !== true) throw new E2eError("format");
  return true;
}

/**
 * „Neu anfangen“ (design §6.2, 0151): a NEW account key, saved on this device
 * first, then requested through the server route — it becomes the account's
 * key only after 24 hours, and a mail lets the person cancel. Needs a fresh
 * login (E2eError("freshLogin")). Until then the old key stays valid.
 */
export async function requestStartOver(d: VaultDeps, locale?: string): Promise<VaultWaiting> {
  const ak = generateAccountKey();
  await saveAccountKey(kvOf(d), d.userId, ak, PENDING_ID);
  await setAkOrigin(d, "later");
  const res = await postApi(d, "/api/e2e/start-over", {
    x25519Pub: toB64url(ak.x25519Pub),
    ed25519Pub: toB64url(ak.edPk),
    selfSig: toB64url(selfSign(ak, d.userId)),
    locale,
  });
  if (res.error === "freshLogin") throw new E2eError("freshLogin");
  if (res.error === "pending") throw new E2eError("pending");
  if (res.ok !== true || typeof res.activatesAt !== "string") throw new E2eError("format");
  return { kind: "waiting", activatesAt: res.activatesAt, code: await requestCode(d.userId, ak.edPk) };
}

/**
 * A new account key published AT ONCE — only possible while the account has
 * none active (0151 refuses a replacement). The app replaces through
 * requestStartOver; the tests use this to stand in for a key that became
 * active after its waiting time.
 */
export async function startOver(d: VaultDeps): Promise<VaultReady> {
  const ak = generateAccountKey();
  const identityId = await saveThenPublish(d, ak);
  await setAkOrigin(d, "later");
  return { kind: "ready", ak, identityId, created: true };
}

export async function forgetThisDevice(d: VaultDeps): Promise<void> {
  await forgetDevice(kvOf(d), d.userId);
}

// --- Trust store sync between my own devices (design §5.4, 0118, 0149) --------------
//
// One row per person: the trust store, sealed under a RANDOM sync key that is
// itself sealed (HPKE) to my current account key — not derived from my signing
// key (one key, one purpose). Every write carries a version that only grows
// (0149) and is part of the blob's AAD, so the service cannot relabel a state;
// this device remembers the highest version it has seen and never takes an
// older state (a rollback). Writes are conditional on the version read; whoever
// comes second reads again, merges and tries again. A blob of MY current key
// that does not open is never overwritten silently — the error stands. A row
// of a previous account key (start over) or of an older format is replaced.
//
// The store inside is SIGNED with my account key (format v3, K-01/S-01,
// security review 17.10.2026): the sync key is sealed to my PUBLIC key, so
// anyone — the service, or a thief holding only my session — could build a
// blob that opens. Only the signature says it came from one of my devices. An
// unsigned (v2) state is never merged, only replaced.

const syncKeyInfo = (userId: string, identityId: string) => encodeFields("fm/trust-sync-key/v1", userId, identityId);
const syncAad = (userId: string, identityId: string, version: number) =>
  encodeFields("fm/trust-sync/v3", userId, identityId, version);
const syncAadV2 = (userId: string, identityId: string, version: number) =>
  encodeFields("fm/trust-sync/v2", userId, identityId, version);
const CTX_TRUST_SYNC = "fm/trust-sync-sig/v1";
const seenKey = (userId: string) => `trustSyncSeen:${userId}`;

/** The signed payload of a v3 sync blob: the store as JSON and my signature over it. */
function signedStore(ak: AccountKey, userId: string, identityId: string, version: number, store: TrustStore): Uint8Array {
  const json = JSON.stringify(store);
  const sig = sign(ak.edSk, CTX_TRUST_SYNC, userId, identityId, version, utf8(json));
  return utf8(JSON.stringify({ store: json, sig: toB64url(sig) }));
}

/** The store of a v3 payload — null unless my own account key signed exactly this state. */
function verifiedStore(ak: AccountKey, userId: string, identityId: string, version: number, payload: Uint8Array): TrustStore | null {
  try {
    const { store, sig } = JSON.parse(fromUtf8(payload)) as { store?: unknown; sig?: unknown };
    if (typeof store !== "string" || typeof sig !== "string") return null;
    if (!verify(ak.edPk, fromB64url(sig), CTX_TRUST_SYNC, userId, identityId, version, utf8(store))) return null;
    return parseTrustStore(store);
  } catch {
    return null;
  }
}

type SyncRow = { blob: string; version: number; identity_id: string | null; key_enc: string | null; key_ct: string | null };

export async function syncTrustStore(d: VaultDeps, ready: VaultReady, attempts = 3): Promise<TrustStore> {
  const kv = kvOf(d);
  let store = await loadTrustStore(kv, d.userId);
  for (let i = 0; i < attempts; i++) {
    const { data, error } = await d.supabase
      .from("trust_store_sync")
      .select("blob, version, identity_id, key_enc, key_ct")
      .eq("user_id", d.userId)
      .maybeSingle();
    if (error) throw error;
    const row = data as SyncRow | null;
    const remoteVersion = row ? Number(row.version) : 0;
    const seen = (await kv.get<number>(seenKey(d.userId))) ?? 0;

    let key: CryptoKey;
    let keyEnc: string;
    let keyCt: string;
    if (row && row.identity_id === ready.identityId && row.key_enc && row.key_ct) {
      // Mine: open the sync key and — unless it is older than what this device
      // has seen — the store. Either failing throws: nothing is overwritten.
      const raw = await hpkeOpen(
        ready.ak.x25519Priv,
        fromPgBytea(row.key_enc),
        syncKeyInfo(d.userId, ready.identityId),
        fromPgBytea(row.key_ct),
      );
      key = await importAesKey(raw);
      keyEnc = row.key_enc;
      keyCt = row.key_ct;
      if (remoteVersion >= seen) {
        const sealed = fromPgBytea(row.blob);
        let payload: Uint8Array | null = null;
        try {
          payload = await aesOpen(key, sealed, syncAad(d.userId, ready.identityId, remoteVersion));
        } catch {
          // An unsigned state of the old format (v2): never merged — it may come
          // from anyone who knows my public key. It is replaced below. Anything
          // else that does not open is an error, and nothing is overwritten.
          await aesOpen(key, sealed, syncAadV2(d.userId, ready.identityId, remoteVersion));
        }
        if (payload) {
          const remote = verifiedStore(ready.ak, d.userId, ready.identityId, remoteVersion, payload);
          if (!remote) throw new Error("syncTrustStore: the synced state is not signed by my account key");
          store = mergeTrustStores(store, remote);
        }
      }
    } else {
      // No row yet, the old format, or a previous account key: a fresh sync key.
      const raw = randomBytes(32);
      const sealed = await hpkeSeal(ready.ak.x25519Pub, syncKeyInfo(d.userId, ready.identityId), raw);
      key = await importAesKey(raw);
      keyEnc = toPgBytea(sealed.enc);
      keyCt = toPgBytea(sealed.ct);
    }
    store = await mergeIntoTrustStore(kv, d.userId, store);

    const next = Math.max(seen, remoteVersion) + 1;
    const values = {
      blob: toPgBytea(
        await aesSeal(key, signedStore(ready.ak, d.userId, ready.identityId, next, store), syncAad(d.userId, ready.identityId, next)),
      ),
      version: next,
      identity_id: ready.identityId,
      key_enc: keyEnc,
      key_ct: keyCt,
      updated_at: new Date().toISOString(),
    };
    const res = row
      ? await d.supabase.from("trust_store_sync").update(values).eq("user_id", d.userId).eq("version", row.version).select("version")
      : await d.supabase.from("trust_store_sync").insert({ user_id: d.userId, ...values }).select("version");
    if (!res.error && (res.data?.length ?? 0) === 1) {
      await kv.set(seenKey(d.userId), next);
      return store;
    }
    if (res.error && (res.error as { code?: string }).code !== "23505") throw res.error;
    // Another of my devices wrote in between: read again, merge, try again.
  }
  throw new Error("syncTrustStore: too many concurrent writers");
}
