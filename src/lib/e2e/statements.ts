// =============================================================================
// Signed statements and the tag blind index.
//
// Invitation (docs/e2e-design.md §5.3): the INVITER's device signs who was
// invited to what. Since 12.10.2026 this only names the inviter on the
// confirmation card — a human says yes to every newcomer (Q14).
//
// Vouch (§5.4, 0148): a person who confirmed someone's account key says so,
// signed, so that the rest of the family need not ask again: "this key (user,
// identity, fingerprint) belongs to this person". Another device takes it only
// from someone IT trusts.
//
// Pairing transfer (§5.2): the old device seals the account key (and its trust
// store) under a key from the pairing's Diffie-Hellman secret — the one the
// compared code comes from — bound to user, nonce and both ephemeral keys.
//
// Tag index (§4.5): tags stay unique per family without a plaintext name.
// =============================================================================

import { x25519 } from "@noble/curves/ed25519.js";

import {
  aesOpen,
  aesSeal,
  E2eError,
  encodeFields,
  fromB64url,
  fromUtf8,
  hkdf,
  importAesKey,
  randomBytes,
  toB64url,
  utf8,
  type Bytes,
} from "./bytes";
import {
  deserializeAccountKey,
  serializeAccountKey,
  sign,
  verify,
  type AccountKey,
  type PublicAccountKey,
} from "./identity";

// --- Invitations ------------------------------------------------------------

export type InvitationStatement = {
  scope: "family" | "story";
  scopeId: string;
  invitationId: string;
  email: string;
  role: string;
  expiresAt: string; // ISO-8601, as stored
};

const CTX_INVITE = "fm/invite/v1";

export function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

function inviteFields(s: InvitationStatement) {
  return [s.scope, s.scopeId, s.invitationId, normalizeEmail(s.email), s.role, s.expiresAt] as const;
}

export function signInvitation(inviterAk: AccountKey, s: InvitationStatement): Bytes {
  return sign(inviterAk.edSk, CTX_INVITE, ...inviteFields(s));
}

export function verifyInvitation(
  inviterPub: PublicAccountKey,
  s: InvitationStatement,
  sig: Uint8Array,
): boolean {
  return verify(inviterPub.edPk, sig, CTX_INVITE, ...inviteFields(s));
}

// --- Vouches ---------------------------------------------------------------------

export type VouchStatement = { subject: string; subjectIdentity: string; fingerprint: string };

const CTX_VOUCH = "fm/vouch/v1";

export function signVouch(voucherAk: AccountKey, v: VouchStatement): Bytes {
  return sign(voucherAk.edSk, CTX_VOUCH, v.subject, v.subjectIdentity, v.fingerprint);
}

export function verifyVouch(voucherPub: PublicAccountKey, v: VouchStatement, sig: Uint8Array): boolean {
  return verify(voucherPub.edPk, sig, CTX_VOUCH, v.subject, v.subjectIdentity, v.fingerprint);
}

/**
 * A vouch for ONE scope and version (0164, P1-2): "a human here confirmed
 * this key for this family / story while version v was current". Only such a
 * vouch lets another device release exactly that version without asking
 * again — after a rotation it counts for nothing (someone who left).
 */
export type ScopeVouchStatement = VouchStatement & { scope: "family" | "story"; scopeId: string; version: number };
const CTX_SCOPE_VOUCH = "fm/vouch/v2";

export function signScopeVouch(voucherAk: AccountKey, v: ScopeVouchStatement): Bytes {
  return sign(voucherAk.edSk, CTX_SCOPE_VOUCH, v.scope, v.scopeId, v.version, v.subject, v.subjectIdentity, v.fingerprint);
}

export function verifyScopeVouch(voucherPub: PublicAccountKey, v: ScopeVouchStatement, sig: Uint8Array): boolean {
  return verify(voucherPub.edPk, sig, CTX_SCOPE_VOUCH, v.scope, v.scopeId, v.version, v.subject, v.subjectIdentity, v.fingerprint);
}

/**
 * A version's key commitment (0170, S-07, P3-5): the device that made version
 * v of a scope says which key it is — `commit` is fm/key-commit/v1 over the
 * key (keyRing.ts). A recipient takes only a key that matches, whoever sealed
 * the envelope: a member slipping in another key for a newcomer gets nowhere.
 */
export type KeyCommitStatement = { scope: "family" | "story" | "avatar"; scopeId: string; version: number; commit: Uint8Array };
const CTX_KEY_COMMIT = "fm/key-commit-sig/v1";

export function signKeyCommit(creatorAk: AccountKey, c: KeyCommitStatement): Bytes {
  return sign(creatorAk.edSk, CTX_KEY_COMMIT, c.scope, c.scopeId, c.version, c.commit);
}

export function verifyKeyCommit(creatorPub: PublicAccountKey, c: KeyCommitStatement, sig: Uint8Array): boolean {
  return verify(creatorPub.edPk, sig, CTX_KEY_COMMIT, c.scope, c.scopeId, c.version, c.commit);
}

/**
 * Withdrawing a waiting account key from one of my devices (S-08): signed with
 * my CURRENT account key over the waiting key — a stolen session alone cannot
 * cancel my rescue any more. The mail link stays the other way.
 */
const CTX_START_OVER_CANCEL = "fm/start-over-cancel/v1";

export function signStartOverCancel(currentAk: AccountKey, userId: string, pendingEdPk: Uint8Array): Bytes {
  return sign(currentAk.edSk, CTX_START_OVER_CANCEL, userId, pendingEdPk);
}

export function verifyStartOverCancel(currentEdPk: Uint8Array, userId: string, pendingEdPk: Uint8Array, sig: Uint8Array): boolean {
  return verify(currentEdPk, sig, CTX_START_OVER_CANCEL, userId, pendingEdPk);
}

/**
 * A backup of my account key (S-11, 0171): my device signs that THIS row —
 * kind, passkey, identity and the exact wrapped key — is mine. A row someone
 * put in with only my session (junk that would silence the recovery-code
 * reminder) carries no valid signature and counts for nothing. `wrappedHash`
 * is SHA-256 of `wrapped_ak`.
 */
export type BackupStatement = { userId: string; kind: "recovery" | "passkey"; credentialId: string; identityId: string; wrappedHash: Uint8Array };
const CTX_BACKUP = "fm/backup/v1";

export function signBackup(ak: AccountKey, b: BackupStatement): Bytes {
  return sign(ak.edSk, CTX_BACKUP, b.userId, b.kind, b.credentialId, b.identityId, b.wrappedHash);
}

export function verifyBackup(edPk: Uint8Array, b: BackupStatement, sig: Uint8Array): boolean {
  return verify(edPk, sig, CTX_BACKUP, b.userId, b.kind, b.credentialId, b.identityId, b.wrappedHash);
}

// --- Pairing transfer (K-02, 18.10.2026) -------------------------------------------
//
// The account key travels sealed under a key from the SAME Diffie-Hellman
// secret both six-digit codes come from (trustCodes.pairingCode): only who
// holds the private key behind the code a human compared can send a transfer
// the new device accepts. Before, it was HPKE to the new device's PUBLIC key —
// the service could have built one itself. With it travels the old device's
// trust store, so the new device starts with whom my devices trust (S-02).
// `enc` (32 bytes, the column's size) is a fresh salt.

function pairTransferInfo(userId: string, nonce: Uint8Array, newDevicePub: Uint8Array, oldDevicePub: Uint8Array) {
  return encodeFields("fm/pair-transfer/v1", userId, nonce, newDevicePub, oldDevicePub);
}

async function pairTransferKey(
  myPriv: Uint8Array,
  theirPub: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array,
): Promise<CryptoKey> {
  const shared = x25519.getSharedSecret(myPriv, theirPub);
  return importAesKey(await hkdf(shared, salt, info, 32));
}

export type PairTransfer = { ak: AccountKey; trust: string | null };

export async function sealPairingTransfer(args: {
  ak: AccountKey;
  /** The old device's trust store as JSON (trustStore.ts), or null. */
  trust: string | null;
  userId: string;
  nonce: Uint8Array;
  oldDevicePriv: Uint8Array;
  newDevicePub: Uint8Array;
  oldDevicePub: Uint8Array;
}): Promise<{ enc: Bytes; ct: Bytes }> {
  const salt = randomBytes(32);
  const info = pairTransferInfo(args.userId, args.nonce, args.newDevicePub, args.oldDevicePub);
  const key = await pairTransferKey(args.oldDevicePriv, args.newDevicePub, salt, info);
  const payload = utf8(JSON.stringify({ ak: toB64url(serializeAccountKey(args.ak)), trust: args.trust }));
  return { enc: salt, ct: await aesSeal(key, payload, info) };
}

export async function openPairingTransfer(args: {
  newDevicePriv: Uint8Array;
  userId: string;
  nonce: Uint8Array;
  newDevicePub: Uint8Array;
  oldDevicePub: Uint8Array;
  enc: Uint8Array;
  ct: Uint8Array;
}): Promise<PairTransfer> {
  const info = pairTransferInfo(args.userId, args.nonce, args.newDevicePub, args.oldDevicePub);
  const key = await pairTransferKey(args.newDevicePriv, args.oldDevicePub, args.enc, info);
  const parsed = JSON.parse(fromUtf8(await aesOpen(key, args.ct, info))) as { ak?: unknown; trust?: unknown };
  if (typeof parsed.ak !== "string") throw new E2eError("format");
  return {
    ak: deserializeAccountKey(fromB64url(parsed.ak)),
    trust: typeof parsed.trust === "string" ? parsed.trust : null,
  };
}

// --- Tag blind index ------------------------------------------------------------
// Lives in ./tagIndex (light: no HPKE, no curves), so the tag writes may import
// it statically. Re-exported here for the existing importers.
export { normalizeTag, tagIndex, tagIndexKey } from "./tagIndex";
