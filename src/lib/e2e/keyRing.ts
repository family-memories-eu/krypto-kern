// =============================================================================
// Content keys of a scope (family / collaborative story) on this device
// (docs/e2e-design.md §4.2, §5.3, §6.2, §7):
//
//   loadScopeKeys      open MY envelopes of a scope, every version, verifying
//                      each sender against the trust store
//   decideRelease      may a waiting person get the key without a human? (pure)
//   releasePending     seal all versions I hold for those who may
//   fillVersion        seal one (new) version for everyone allowed; complete it
//                      once nobody is missing
//   createScopeKeyVersion   first key of a scope, or a rotation
//   ensureScopeKey     make sure a scope HAS a current key (first key of a
//                      pilot family, or finish one an earlier run left open)
//   loadRowKeys        the scope's keys as non-extractable AES keys, for the
//                      encrypted rows of Etappe 2 (rowCrypto.ts)
//   confirmPerson      a human said yes (newcomer, or rescue): adopt their key
//                      in the trust store, release, and vouch for it (0148)
//   adoptVouched       take a key someone THIS device trusts has vouched for —
//                      one human yes is enough for the whole family
//
// The rule (12.10.2026, docs/e2e-pruefung.md Q14): a person whose key this
// device has never trusted gets NOTHING without a human — not even with a
// signed invitation. The service sends the invitation mails and could accept
// one itself; the signature does not bind the person or their key. It only
// feeds the card's "invited by …". Such people are NOT written to the trust
// store (a later run would find them "known" and release silently). Only a
// key this device already trusts (confirmed here, or known from elsewhere) is
// released to without asking.
// =============================================================================

import type { SupabaseClient } from "@supabase/supabase-js";

import { encodeFields, fromB64url, fromPgBytea, importAesKey, toB64url, toPgBytea, type Bytes } from "./bytes";
import { loadTrustStore, mergeIntoTrustStore, type KeyValueStore } from "./deviceStore";
import { envelopeSignedBy, generateContentKey, openEnvelope, sealEnvelope, type Envelope, type KeyScope } from "./envelope";
import { fingerprint, verifySelf, type PublicAccountKey } from "./identity";
import {
  normalizeEmail,
  signKeyCommit,
  signScopeVouch,
  signVouch,
  verifyInvitation,
  verifyKeyCommit,
  verifyScopeVouch,
  verifyVouch,
} from "./statements";
import { mediaSealKeyV2 } from "./mediaSeal";
import { rowKeyV2 } from "./rowCryptoV2";
import { tagIndexKey } from "./tagIndex";
import { mediaBaseKey } from "./objectKey";
import { safetyCode, safetyCodeHalf } from "./trustCodes";
import {
  acceptChange,
  earnsSilentTrust,
  markVerified,
  observe,
  restoreRolledBack,
  rolledBackTo,
  trustedKey,
  withOrigin,
  type TrustStore,
} from "./trustStore";
import { akOriginOf, type VaultReady } from "./vault";

export type RingDeps = { supabase: SupabaseClient; userId: string; kv: KeyValueStore };
export type ContentScope = Exclude<KeyScope, "avatar">;

type IdentityRow = { id: string; user_id: string; x25519_pub: string; ed25519_pub: string; self_sig: string };

export type PendingRow = {
  user_id: string;
  identity_id: string;
  x25519_pub: string;
  ed25519_pub: string;
  self_sig: string;
  had_previous_key: boolean;
  invitation_id: string | null;
  invitation_email: string | null;
  invitation_role: string | null;
  invitation_expires_at: string | null;
  inviter: string | null;
  inviter_sig: string | null;
};

const pubOf = (r: { x25519_pub: string; ed25519_pub: string }): PublicAccountKey => ({
  x25519Pub: fromPgBytea(r.x25519_pub),
  edPk: fromPgBytea(r.ed25519_pub),
});

/** Same string on both sides of the signature, whatever precision PostgREST sends. */
export function normalizeExpiry(v: string | null | undefined): string {
  return v ? new Date(v).toISOString() : "";
}

// --- Decision (pure) ------------------------------------------------------------

const selfOf = (d: RingDeps, ready: VaultReady) => ({
  userId: d.userId,
  pub: { x25519Pub: ready.ak.x25519Pub, edPk: ready.ak.edPk },
});

export type Decision =
  | { kind: "release"; store: TrustStore; pub: PublicAccountKey }
  | {
      kind: "confirm";
      reason: "changed" | "unsigned" | "new";
      fingerprint: string;
      pub: PublicAccountKey;
      /** reason "new": the person whose signed invitation this is (a hint, never a release). */
      invitedBy?: string;
    }
  | { kind: "invalid" };

export async function decideRelease(
  row: PendingRow,
  scope: KeyScope,
  scopeId: string,
  store: TrustStore,
  /** This device's own person — not in its own trust store, but trusted as inviter. */
  self?: { userId: string; pub: PublicAccountKey },
  /**
   * Identities this scope may go to without a human (P1-2, 17.10.2026): in a
   * rotation, those who provably held the previous version (holdersOf); later,
   * those vouched for in THIS scope by a holder (scopeVouchedFor). A known key
   * alone no longer earns a silent release — joining a second family, coming
   * back after leaving, a key taken on first use: a human decides. Absent = no
   * proof = a card.
   */
  heldPrior?: ReadonlySet<string>,
): Promise<Decision> {
  const pub = pubOf(row);
  const seen = await observe(store, {
    userId: row.user_id,
    identityId: row.identity_id,
    pub,
    selfSig: fromPgBytea(row.self_sig),
  });
  if (seen.status === "invalid") return { kind: "invalid" };
  if (seen.status === "known") {
    // A profile picture has no versions per family; it goes to anyone known (E3.6).
    if (scope === "avatar") return { kind: "release", store: seen.store, pub };
    if (earnsSilentTrust(seen.store, row.user_id) && heldPrior?.has(row.identity_id)) {
      return { kind: "release", store: seen.store, pub };
    }
    // Known, but not in this scope before (or only taken on first use): the
    // newcomer card below — never silently (S-05, S-18).
  }
  const fp = await fingerprint(pub);
  if (seen.status === "changed") return { kind: "confirm", reason: "changed", fingerprint: fp, pub };

  // A profile picture has no invitations (E3.6): a newcomer is never released
  // to without a human — and avatars never ask one (releaseOwnAvatar).
  if (scope === "avatar") return { kind: "confirm", reason: "unsigned", fingerprint: fp, pub };

  // status "new": always a human. A valid invitation signed by someone this
  // device trusts only names the inviter on the card.
  const inviter = !row.inviter
    ? null
    : self && row.inviter === self.userId
      ? self.pub
      : trustedKey(store, row.inviter);
  const ok =
    !!inviter &&
    !!row.inviter_sig &&
    !!row.invitation_id &&
    !!row.invitation_email &&
    !!row.invitation_role &&
    verifyInvitation(
      inviter,
      {
        scope: scope as ContentScope,
        scopeId,
        invitationId: row.invitation_id,
        email: normalizeEmail(row.invitation_email),
        role: row.invitation_role,
        expiresAt: normalizeExpiry(row.invitation_expires_at),
      },
      fromPgBytea(row.inviter_sig),
    );
  return ok
    ? { kind: "confirm", reason: "new", fingerprint: fp, pub, invitedBy: row.inviter! }
    : { kind: "confirm", reason: "unsigned", fingerprint: fp, pub };
}

// --- Who held a version (P1-2, 0164) ------------------------------------------------

type Holder = { userId: string; identityId: string; x25519Pub: Uint8Array };
type PriorRow = {
  recipient: string;
  recipient_identity: string;
  sender: string;
  sender_identity: string;
  enc: string;
  ct: string;
  sig: string;
};

/**
 * The identities among `people` that provably held `version` of the scope: an
 * envelope to exactly that key, signed by me or by someone this device trusts
 * as more than a first use (0164 hands releasers the envelopes, without the
 * keys inside). The server can leave a proof out — then a card follows — but
 * cannot forge one. Any error: no proof at all.
 */
async function holdersOf(
  d: RingDeps,
  ready: VaultReady,
  scope: KeyScope,
  scopeId: string,
  version: number | null,
  people: Holder[],
  store: TrustStore,
): Promise<Set<string>> {
  const out = new Set<string>();
  if (version === null || version < 1 || people.length === 0 || scope === "avatar") return out;
  const { data, error } = await d.supabase.rpc("e2e_prior_envelopes", {
    _scope: scope,
    _scope_id: scopeId,
    _version: version,
    _recipients: [...new Set(people.map((p) => p.userId))],
  });
  if (error || !Array.isArray(data)) return out;
  for (const r of data as PriorRow[]) {
    const who = people.find((p) => p.userId === r.recipient && p.identityId === r.recipient_identity);
    if (!who) continue;
    let senderPub: PublicAccountKey | null = null;
    if (r.sender === d.userId && r.sender_identity === ready.identityId) {
      senderPub = { x25519Pub: ready.ak.x25519Pub, edPk: ready.ak.edPk };
    } else if (earnsSilentTrust(store, r.sender) && store.entries[r.sender].identityId === r.sender_identity) {
      senderPub = trustedKey(store, r.sender);
    }
    if (!senderPub) continue;
    try {
      const env: Envelope = {
        scope,
        scopeId,
        version,
        recipient: r.recipient,
        enc: fromPgBytea(r.enc),
        ct: fromPgBytea(r.ct),
        sender: r.sender,
        sig: fromPgBytea(r.sig),
      };
      if (envelopeSignedBy(env, who.x25519Pub, senderPub)) out.add(who.identityId);
    } catch {
      // a malformed row proves nothing
    }
  }
  return out;
}

const holderOf = (row: PendingRow): Holder => ({
  userId: row.user_id,
  identityId: row.identity_id,
  x25519Pub: pubOf(row).x25519Pub,
});

/**
 * The waiting identities a human confirmed FOR THIS SCOPE AND VERSION (0164, fm/vouch/v2):
 * on one of my own devices, or by someone this device trusts (more than a
 * first use) who provably holds `version` of the scope. That vouch is what
 * lets a device release silently AFTER a rotation — e.g. a newcomer one member
 * confirmed while not holding the current version. Somebody who left and is
 * brought back by the server has none: a card.
 */
async function scopeVouchedFor(
  d: RingDeps,
  ready: VaultReady,
  scope: KeyScope,
  scopeId: string,
  version: number | null,
  rows: PendingRow[],
  store: TrustStore,
): Promise<Set<string>> {
  const out = new Set<string>();
  if (scope === "avatar" || rows.length === 0 || version === null) return out;
  const { data, error } = await d.supabase
    .from("key_scope_vouches")
    .select("voucher, voucher_identity, subject, subject_identity, sig")
    .eq("scope", scope)
    .eq("scope_id", scopeId)
    .eq("version", version)
    .in("subject_identity", [...new Set(rows.map((r) => r.identity_id))]);
  if (error || !Array.isArray(data) || data.length === 0) return out;
  const vouches = data as { voucher: string; voucher_identity: string; subject: string; subject_identity: string; sig: string }[];
  const vouchers: Holder[] = [];
  for (const id of new Set(vouches.map((v) => v.voucher))) {
    if (id === d.userId || !earnsSilentTrust(store, id)) continue;
    const e = store.entries[id];
    vouchers.push({ userId: id, identityId: e.identityId, x25519Pub: fromB64url(e.x25519Pub) });
  }
  const holding = await holdersOf(d, ready, scope, scopeId, version, vouchers, store);
  const me = { x25519Pub: ready.ak.x25519Pub, edPk: ready.ak.edPk };
  for (const v of vouches) {
    const row = rows.find((r) => r.user_id === v.subject && r.identity_id === v.subject_identity);
    if (!row || v.voucher === v.subject) continue;
    const mine = v.voucher === d.userId && v.voucher_identity === ready.identityId;
    if (!mine && !holding.has(v.voucher_identity)) continue;
    const voucherPub = mine ? me : trustedKey(store, v.voucher);
    if (!voucherPub) continue;
    const statement = {
      scope: scope as ContentScope,
      scopeId,
      version,
      subject: v.subject,
      subjectIdentity: v.subject_identity,
      fingerprint: await fingerprint(pubOf(row)),
    };
    try {
      if (verifyScopeVouch(voucherPub, statement, fromPgBytea(v.sig))) out.add(v.subject_identity);
    } catch {
      // a malformed row proves nothing
    }
  }
  return out;
}

// --- Opening my envelopes -----------------------------------------------------------

type EnvelopeRow = {
  version: number;
  enc: string;
  ct: string;
  sender: string;
  sender_identity: string;
  sig: string;
};

export type UntrustedSender = { userId: string; identityId: string; fingerprint: string };
export type ScopeKeys = {
  keys: Map<number, Bytes>;
  /** The version to write with — null when none is complete, the server turned it back, or it came only through an old key. */
  current: number | null;
  untrustedSenders: UntrustedSender[];
  /** Versions opened only through a person's EARLIER key: for reading, never for writing or passing on (K-05). */
  readOnly: Set<number>;
};

// --- What this device has seen of a scope (S-04/K-05, 17.10.2026) -------------------
//
// Per scope, kept on the device: the highest version ever reported as current,
// and a fingerprint of each version's key. A server reporting a LOWER current
// version (a rollback, or a restored database) gets no write; a SECOND, other
// key for a version already seen is refused (a relabelled or re-made version).

type KeyMemory = { high: number; commits: Record<string, string> };
const memoryKey = (userId: string, scope: KeyScope, scopeId: string) => `keyver:${userId}:${scope}:${scopeId}`;

async function keyCommitBytes(scope: KeyScope, scopeId: string, version: number, raw: Bytes): Promise<Bytes> {
  const digest = await globalThis.crypto.subtle.digest(
    "SHA-256",
    encodeFields("fm/key-commit/v1", scope, scopeId, version, raw) as Uint8Array<ArrayBuffer>,
  );
  return new Uint8Array(digest) as Bytes;
}

async function keyCommit(scope: KeyScope, scopeId: string, version: number, raw: Bytes): Promise<string> {
  return toB64url(await keyCommitBytes(scope, scopeId, version, raw));
}

/**
 * Publish the commitment of a version this device made (0170, S-07, P3-5):
 * recipients take only a key that matches it. Best effort — a version without
 * one is read by the older rule (the creator's envelope wins a conflict).
 */
async function publishKeyCommit(d: RingDeps, ready: VaultReady, scope: KeyScope, scopeId: string, version: number, raw: Bytes) {
  try {
    const commit = await keyCommitBytes(scope, scopeId, version, raw);
    const sig = signKeyCommit(ready.ak, { scope, scopeId, version, commit });
    const { error } = await d.supabase.rpc("e2e_set_key_commit", {
      _scope: scope,
      _scope_id: scopeId,
      _version: version,
      _commit: toPgBytea(commit),
      _sig: toPgBytea(sig),
      _identity: ready.identityId,
    });
    if (error && !/no version of yours/.test(error.message ?? "")) console.warn("key commit not stored:", error.message);
  } catch (e) {
    console.warn("key commit not stored:", e);
  }
}

type VersionInfo = {
  version: number;
  created_by: string | null;
  commit: string | null;
  commit_sig: string | null;
  commit_identity: string | null;
};

/**
 * KP-05 (Klickprobe 26.10.2026): before the fix, a device could fall back to a
 * key the person had moved away from. Such an entry gets back the key this
 * device had adopted last — fetched by its fingerprint, which comes from this
 * device, so the server cannot choose it. No such entry: no query.
 */
async function healRolledBack(d: RingDeps, store: TrustStore): Promise<TrustStore> {
  let next = store;
  for (const [userId, e] of Object.entries(store.entries)) {
    const target = rolledBackTo(e);
    if (!target) continue;
    const { data } = await d.supabase
      .from("user_identity_keys")
      .select("id, user_id, x25519_pub, ed25519_pub, self_sig")
      .eq("user_id", userId);
    for (const row of (data ?? []) as IdentityRow[]) {
      const pub = pubOf(row);
      if (row.user_id !== userId || (await fingerprint(pub)) !== target) continue;
      if (!verifySelf(pub, userId, fromPgBytea(row.self_sig))) continue;
      next = restoreRolledBack(next, userId, {
        identityId: row.id,
        x25519Pub: toB64url(pub.x25519Pub),
        edPk: toB64url(pub.edPk),
        fingerprint: target,
      });
      break;
    }
  }
  return next === store ? store : mergeIntoTrustStore(d.kv, d.userId, next);
}

/**
 * Every version of the scope's key I can open.
 *
 * Pass 1 accepts only senders this device already trusts. A sender's OLD key
 * (fingerprint in `previous`, from before a rescue) counts only for versions
 * older than the current one: what they sealed back then stays readable, but a
 * thief of their old device cannot, together with the server, bring in a key
 * for the current or a newer version (12.10.2026, finding h).
 *
 * Pass 2 runs ONLY for a newcomer (pass 1 found nothing at all): senders never
 * seen before are taken on first use and remembered — there is nothing to
 * compare against yet (design §10.3; the safety code is the answer there).
 *
 * Everyone else NEVER accepts an unknown sender, not even for one call: a
 * server could plant an invented member with an envelope for a version this
 * device does not have yet — and if that version is current, new content would
 * be encrypted under the server's key. Such senders come back as
 * `untrustedSenders` for a human to confirm (confirmPerson, reason "sender").
 */
export async function loadScopeKeys(
  d: RingDeps,
  ready: VaultReady,
  scope: KeyScope,
  scopeId: string,
): Promise<ScopeKeys> {
  const [{ data: envs, error: e1 }, { data: st, error: e2 }, { data: vers }] = await Promise.all([
    d.supabase
      .from("key_envelopes")
      .select("version, enc, ct, sender, sender_identity, sig")
      .eq("scope", scope)
      .eq("scope_id", scopeId)
      .eq("recipient_identity", ready.identityId),
    d.supabase.from("key_scope_state").select("current_version").eq("scope", scope).eq("scope_id", scopeId).maybeSingle(),
    // Without 0170 the columns are missing: then every version reads by the older rule.
    d.supabase
      .from("key_versions")
      .select("version, created_by, commit, commit_sig, commit_identity")
      .eq("scope", scope)
      .eq("scope_id", scopeId),
  ]);
  if (e1) throw e1;
  if (e2) throw e2;
  const versionInfo = new Map(((vers ?? []) as VersionInfo[]).map((v) => [v.version, v]));
  // A profile picture's key comes from its person and nobody else (E3.6):
  // another holder could only hand on what that person sealed, and accepting
  // them would let a forged member slip in a picture under someone's name.
  const rows = ((envs ?? []) as EnvelopeRow[]).filter((r) => scope !== "avatar" || r.sender === scopeId);
  const stored = await healRolledBack(d, await loadTrustStore(d.kv, d.userId));
  const currentVersion = (st as { current_version: number | null } | null)?.current_version ?? null;
  const memKey = memoryKey(d.userId, scope, scopeId);
  const mem: KeyMemory = (await d.kv.get<KeyMemory>(memKey)) ?? { high: 0, commits: {} };
  const keys = new Map<number, Bytes>();
  const readOnly = new Set<number>();
  const identities = new Map<string, IdentityRow | null>();
  // Every key each version opened to, with its sender (S-07: there may be more than one).
  const candidates = new Map<number, { raw: Bytes; sender: string; oldKey: boolean }[]>();

  async function identity(id: string): Promise<IdentityRow | null> {
    if (!identities.has(id)) {
      const { data, error } = await d.supabase
        .from("user_identity_keys")
        .select("id, user_id, x25519_pub, ed25519_pub, self_sig")
        .eq("id", id)
        .maybeSingle();
      if (error) throw error;
      identities.set(id, (data as IdentityRow | null) ?? null);
    }
    return identities.get(id)!;
  }

  async function tryOpen(r: EnvelopeRow, senderPub: PublicAccountKey, oldKey = false): Promise<boolean> {
    try {
      const raw = await openEnvelope({
          envelope: {
            scope,
            scopeId,
            version: r.version,
            recipient: d.userId,
            enc: fromPgBytea(r.enc),
            ct: fromPgBytea(r.ct),
            sender: r.sender,
            sig: fromPgBytea(r.sig),
          },
          me: d.userId,
          myAk: ready.ak,
          senderPub,
        });
      if (!keys.has(r.version)) keys.set(r.version, raw);
      candidates.set(r.version, [...(candidates.get(r.version) ?? []), { raw, sender: r.sender, oldKey }]);
      return true;
    } catch {
      return false; // a bad envelope is skipped; another sender may have one
    }
  }

  // Pass 1: trusted senders (and myself) — EVERY envelope, not just the first
  // that opens: two senders may have sealed different keys (S-07).
  const unknown: { r: EnvelopeRow; idRow: IdentityRow }[] = [];
  const changed: { r: EnvelopeRow; idRow: IdentityRow }[] = [];
  for (const r of rows) {
    if (r.sender === d.userId && r.sender_identity === ready.identityId) {
      await tryOpen(r, { x25519Pub: ready.ak.x25519Pub, edPk: ready.ak.edPk });
      continue;
    }
    const idRow = await identity(r.sender_identity);
    if (!idRow || idRow.user_id !== r.sender) continue;
    const pub = pubOf(idRow);
    const fp = await fingerprint(pub);
    const entry = stored.entries[r.sender];
    // Unknown or changed senders only matter for a version still without a key.
    if (keys.has(r.version) && (!entry || (entry.fingerprint !== fp && !entry.previous.includes(fp)))) continue;
    // An earlier key only for versions older than the current one AND not newer
    // than what this device has ever seen as current — and only to read (K-05).
    const oldKeyForOldVersion =
      currentVersion !== null &&
      r.version < currentVersion &&
      (mem.high === 0 || r.version <= mem.high) &&
      !!entry?.previous.includes(fp);
    if (entry && entry.fingerprint === fp) await tryOpen(r, pub);
    else if (entry && oldKeyForOldVersion) await tryOpen(r, pub, true);
    else if (!entry) unknown.push({ r, idRow });
    // A key the person moved away from (rescue): only the read above, never
    // adopted again — not even through my own vouch from back then (KP-05).
    else if (entry.previous.includes(fp)) continue;
    else changed.push({ r, idRow }); // a KNOWN person with a DIFFERENT key: only if vouched for
  }

  // Pass 1b: senders new to this device, or with a new key, that someone this
  // device trusts has confirmed (0148) — adopted, then opened like pass 1.
  let store = stored;
  if (unknown.length + changed.length > 0) {
    store = await adoptVouched(
      d,
      ready,
      stored,
      [...unknown, ...changed].map(({ idRow }) => ({
        userId: idRow.user_id,
        identityId: idRow.id,
        pub: pubOf(idRow),
        selfSig: fromPgBytea(idRow.self_sig),
      })),
      { scope, scopeId, version: currentVersion },
    );
    if (store !== stored) {
      await mergeIntoTrustStore(d.kv, d.userId, store);
      // Every envelope, as in pass 1 — a conflict must be seen (S-07).
      for (const { r, idRow } of [...unknown, ...changed]) {
        const pub = pubOf(idRow);
        if (store.entries[r.sender]?.fingerprint === (await fingerprint(pub))) await tryOpen(r, pub);
      }
    }
  }
  const stillUnknown = unknown.filter(({ r }) => !store.entries[r.sender]);

  // Pass 2: newcomer only — and never for a profile picture: seeing someone's
  // picture must not be how this device first comes to trust their key. Since
  // 18.10.2026 (S-02, P1-3) "newcomer" means: this device has never held this
  // scope's key, AND its account key was made here as the person's first one.
  // A device that took its key over (pairing, recovery, passkey) or started
  // over trusts nobody on first use — its trust comes from my other devices
  // (signed sync) or from a human (cards).
  const untrustedSenders: UntrustedSender[] = [];
  const beforePass2 = store;
  const heldKey = `held:${d.userId}:${scope}:${scopeId}`;
  const newcomer =
    keys.size === 0 && !(await d.kv.get<boolean>(heldKey)) && (await akOriginOf(d.kv, d.userId)) !== "later";
  if (scope === "avatar") {
    // Unknown person: initials instead of a picture, nothing to confirm.
  } else if (newcomer) {
    // Every envelope, as in pass 1: with two senders for one version, the
    // commitment (or the creator) must pick — not whichever came first (S-07).
    for (const { r, idRow } of stillUnknown) {
      // Taken on first use — marked so: it opens this envelope, but never earns
      // a silent release or counts as a voucher anywhere (S-18).
      const seen = await observe(
        store,
        { userId: r.sender, identityId: idRow.id, pub: pubOf(idRow), selfSig: fromPgBytea(idRow.self_sig) },
        new Date(),
        "tofu",
      );
      if (seen.status !== "new" && seen.status !== "known") continue;
      if (await tryOpen(r, pubOf(idRow))) store = seen.store;
    }
    if (store !== beforePass2) await mergeIntoTrustStore(d.kv, d.userId, store);
  } else {
    for (const { r, idRow } of stillUnknown) {
      if (keys.has(r.version) || untrustedSenders.some((u) => u.identityId === idRow.id)) continue;
      untrustedSenders.push({ userId: r.sender, identityId: idRow.id, fingerprint: await fingerprint(pubOf(idRow)) });
    }
  }
  // Several keys for one version (S-07, P3-5): the creator's signed commitment
  // decides; without one (versions from before 0170), a single key is taken,
  // and of several different ones only the creator's — otherwise none.
  for (const [v, cands] of candidates) {
    const info = versionInfo.get(v);
    const commit = await usableCommit(info, v);
    let chosen: Bytes | null = null;
    if (commit) {
      for (const c of cands) {
        if (toB64url(await keyCommitBytes(scope, scopeId, v, c.raw)) === commit) chosen = c.raw;
      }
    } else {
      const distinct = new Map<string, { raw: Bytes; sender: string; oldKey: boolean }[]>();
      for (const c of cands) {
        const k = await keyCommit(scope, scopeId, v, c.raw);
        distinct.set(k, [...(distinct.get(k) ?? []), c]);
      }
      if (distinct.size === 1) chosen = cands[0].raw;
      else chosen = cands.find((c) => info?.created_by && c.sender === info.created_by)?.raw ?? null;
    }
    if (chosen) {
      keys.set(v, chosen);
      // Read only if this key came ONLY through a sender's earlier key (K-05).
      const same = await keyCommit(scope, scopeId, v, chosen);
      const via = [];
      for (const c of cands) if ((await keyCommit(scope, scopeId, v, c.raw)) === same) via.push(c);
      if (via.every((c) => c.oldKey)) readOnly.add(v);
      else readOnly.delete(v);
    } else {
      keys.delete(v);
      readOnly.delete(v);
    }
  }

  /**
   * The commitment of version v as base64url, if there is one this device may
   * go by: signed by the version's creator with a key this device knows (or by
   * itself). One that does not verify against a known key is dropped — the
   * version then reads by the older rule. One from a creator this device has
   * no key for still filters (it can only refuse keys, never bring one in).
   */
  async function usableCommit(info: VersionInfo | undefined, v: number): Promise<string | null> {
    if (!info?.commit || !info.commit_sig || !info.commit_identity || !info.created_by) return null;
    let commitBytes: Bytes;
    try {
      commitBytes = fromPgBytea(info.commit);
    } catch {
      return null;
    }
    let pub: PublicAccountKey | null = null;
    if (info.commit_identity === ready.identityId) pub = { x25519Pub: ready.ak.x25519Pub, edPk: ready.ak.edPk };
    else {
      const idRow = await identity(info.commit_identity);
      if (idRow && idRow.user_id === info.created_by) {
        const candidate = pubOf(idRow);
        const fp = await fingerprint(candidate);
        const entry = store.entries[info.created_by];
        if (entry && (entry.fingerprint === fp || entry.previous.includes(fp))) pub = candidate;
      }
    }
    if (pub && !verifyKeyCommit(pub, { scope, scopeId, version: v, commit: commitBytes }, fromPgBytea(info.commit_sig))) {
      return null;
    }
    return toB64url(commitBytes);
  }

  // A version I made whose commitment is missing (the founding version, or one
  // from before 0170): published now, from the key in my own envelope.
  for (const [v, cands] of candidates) {
    const info = versionInfo.get(v);
    if (!info || info.commit || info.created_by !== d.userId || readOnly.has(v)) continue;
    const own = cands.find((c) => c.sender === d.userId);
    if (own && keys.get(v) === own.raw) await publishKeyCommit(d, ready, scope, scopeId, v, own.raw);
  }

  // The version memory: a second, other key for a version seen before is refused.
  for (const [v, raw] of keys) {
    const c = await keyCommit(scope, scopeId, v, raw);
    const seen = mem.commits[String(v)];
    if (seen && seen !== c) keys.delete(v);
    else if (!readOnly.has(v)) mem.commits[String(v)] = c;
  }
  let current = currentVersion;
  if (current !== null && current < mem.high) current = null; // turned back: no write
  else if (current !== null) mem.high = Math.max(mem.high, current);
  if (current !== null && readOnly.has(current)) current = null;
  await d.kv.set(memKey, mem);
  // Held once: never a newcomer here again, whatever the server leaves out later.
  if (keys.size > 0 && scope !== "avatar") await d.kv.set(heldKey, true);
  await sendReceipts(d, ready, scope, scopeId, [...keys.keys()]);
  return { keys, current, untrustedSenders, readOnly };
}

/**
 * Tell the others this device opened and checked these versions (0170): the
 * waiting lists go by it, so a junk envelope from someone else no longer makes
 * me look served. Once per version and device; best effort.
 */
async function sendReceipts(d: RingDeps, ready: VaultReady, scope: KeyScope, scopeId: string, versions: number[]) {
  for (const v of versions) {
    const mark = `rcpt:${d.userId}:${ready.identityId}:${scope}:${scopeId}:${v}`;
    if (await d.kv.get<boolean>(mark)) continue;
    const { error } = await d.supabase.from("key_receipts").insert({
      scope,
      scope_id: scopeId,
      version: v,
      recipient: d.userId,
      recipient_identity: ready.identityId,
    });
    if (!error || (error as { code?: string }).code === "23505") await d.kv.set(mark, true);
  }
}

// --- Sealing ----------------------------------------------------------------------------

async function insertEnvelope(
  d: RingDeps,
  ready: VaultReady,
  scope: KeyScope,
  scopeId: string,
  version: number,
  key: Bytes,
  recipient: { userId: string; identityId: string; pub: PublicAccountKey },
) {
  const env = await sealEnvelope({
    scope,
    scopeId,
    version,
    contentKey: key,
    recipient: recipient.userId,
    recipientPub: recipient.pub,
    sender: d.userId,
    senderAk: ready.ak,
  });
  const { error } = await d.supabase.from("key_envelopes").insert({
    scope,
    scope_id: scopeId,
    version,
    recipient: recipient.userId,
    recipient_identity: recipient.identityId,
    enc: toPgBytea(env.enc),
    ct: toPgBytea(env.ct),
    sender: d.userId,
    sender_identity: ready.identityId,
    sig: toPgBytea(env.sig),
  });
  // 23505: since 0170 one envelope per SENDER — this device sealed it already.
  if (error && (error as { code?: string }).code !== "23505") throw error;
}

/**
 * Whom to ask the waiting list for: the current version — or, while there is
 * none yet (a first version whose completion did not get through), the newest
 * one this device holds. Without that, a first key left open asked for the
 * current version, got an empty list, and every confirmation failed
 * ("no longer pending") — found live 12.10.2026 (Familie Stark, app before
 * 0147: v1 waited for exactly the confirmations that could not be given).
 */
function waitingVersion(current: number | null, keys: Map<number, unknown>): number | undefined {
  if (current !== null) return undefined;
  return keys.size > 0 ? Math.max(...keys.keys()) : undefined;
}

async function pendingFor(d: RingDeps, scope: KeyScope, scopeId: string, version?: number): Promise<PendingRow[]> {
  const { data, error } = await d.supabase.rpc("e2e_pending_recipients", {
    _scope: scope,
    _scope_id: scopeId,
    ...(version !== undefined ? { _version: version } : {}),
  });
  if (error) throw error;
  return (data ?? []) as PendingRow[];
}

export type ConfirmCase = {
  scope: ContentScope;
  scopeId: string;
  userId: string;
  identityId: string;
  /** changed: known person, new key · new: newcomer with an invitation signed
   *  by someone this device trusts · unsigned: newcomer without one · sender:
   *  unknown person who sent us a key version */
  reason: "changed" | "unsigned" | "new" | "sender";
  fingerprint: string;
  /** reason "new": who invited them (user id). */
  invitedBy?: string;
  /**
   * A newer key version of this scope waits for exactly this yes (S-13): until
   * then the rotation is not complete — whoever left can still read along.
   */
  urgent?: boolean;
};

/**
 * Give every waiting person of the scope all versions I hold — where the rules
 * allow it without a human. Returns who needs a human decision.
 */
export async function releasePending(
  d: RingDeps,
  ready: VaultReady,
  scope: ContentScope,
  scopeId: string,
): Promise<{ released: string[]; confirm: ConfirmCase[] }> {
  const { keys, current, untrustedSenders } = await loadScopeKeys(d, ready, scope, scopeId);
  // A version newer than the current one is a rotation still waiting (S-13).
  const waiting = [...keys.keys()].some((v) => v > (current ?? 0));
  const confirm: ConfirmCase[] = untrustedSenders.map((u) => ({ scope, scopeId, ...u, reason: "sender" as const }));
  const pending = await pendingFor(d, scope, scopeId, waitingVersion(current, keys));
  if (pending.length === 0 || keys.size === 0) return { released: [], confirm };
  // The version the waiting people lack; a silent release needs proof they held the one before.
  const target = waitingVersion(current, keys) ?? current;
  let store = await adoptVouched(d, ready, await loadTrustStore(d.kv, d.userId), pending.map(candidateOf), {
    scope,
    scopeId,
    version: target,
  });
  // After a rotation, holding an earlier version proves nothing (someone who
  // left held it too): only a vouch for THIS scope by a holder of the current
  // version lets the key go without a card (P1-2, S-05).
  const allowed = await scopeVouchedFor(d, ready, scope, scopeId, target, pending, store);
  const released: string[] = [];
  for (const row of pending) {
    const dec = await decideRelease(row, scope, scopeId, store, selfOf(d, ready), allowed);
    if (dec.kind === "invalid") continue;
    if (dec.kind === "confirm") {
      confirm.push({
        scope,
        scopeId,
        userId: row.user_id,
        identityId: row.identity_id,
        reason: dec.reason,
        fingerprint: dec.fingerprint,
        ...(dec.invitedBy ? { invitedBy: dec.invitedBy } : {}),
        ...(waiting ? { urgent: true } : {}),
      });
      continue;
    }
    store = dec.store;
    for (const [version, key] of keys) {
      await insertEnvelope(d, ready, scope, scopeId, version, key, {
        userId: row.user_id,
        identityId: row.identity_id,
        pub: dec.pub,
      });
    }
    released.push(row.user_id);
  }
  await mergeIntoTrustStore(d.kv, d.userId, store);
  return { released, confirm };
}

/**
 * Seal `version` (whose key I hold) for everyone allowed, and make it current.
 * People still waiting for a human do not hold it up (0147 counts only those
 * already admitted): they get it with the confirmation. Returns who still
 * needs a human decision.
 */
export async function fillVersion(
  d: RingDeps,
  ready: VaultReady,
  scope: ContentScope,
  scopeId: string,
  version: number,
  key: Bytes,
): Promise<ConfirmCase[]> {
  const pending = await pendingFor(d, scope, scopeId, version);
  // Vouchers must hold the version before this one; so must everyone released to silently (P1-2).
  let store = await adoptVouched(d, ready, await loadTrustStore(d.kv, d.userId), pending.map(candidateOf), {
    scope,
    scopeId,
    version: version - 1,
  });
  // The rotation itself: whoever held the version before keeps the key; a
  // newcomer confirmed for this scope (vouch) too. Everyone else: a card.
  const heldPrior = await holdersOf(d, ready, scope, scopeId, version - 1, pending.map(holderOf), store);
  for (const id of await scopeVouchedFor(d, ready, scope, scopeId, version - 1, pending, store)) heldPrior.add(id);
  const confirm: ConfirmCase[] = [];
  for (const row of pending) {
    const dec = await decideRelease(row, scope, scopeId, store, selfOf(d, ready), heldPrior);
    if (dec.kind === "invalid") continue;
    if (dec.kind === "confirm") {
      confirm.push({
        scope,
        scopeId,
        userId: row.user_id,
        identityId: row.identity_id,
        reason: dec.reason,
        fingerprint: dec.fingerprint,
        ...(dec.invitedBy ? { invitedBy: dec.invitedBy } : {}),
      });
      continue;
    }
    store = dec.store;
    await insertEnvelope(d, ready, scope, scopeId, version, key, { userId: row.user_id, identityId: row.identity_id, pub: dec.pub });
  }
  await mergeIntoTrustStore(d.kv, d.userId, store);
  const { error } = await d.supabase.rpc("e2e_complete_key_version", {
    _scope: scope,
    _scope_id: scopeId,
    _version: version,
  });
  // Someone admitted before whom THIS device does not trust (yet) has no
  // envelope: their card is in `confirm`, and the confirmation completes it —
  // urgently (S-13): until then whoever left can still read along.
  if (error && !/still without an envelope/.test(error.message ?? "")) throw error;
  return error ? confirm.map((c) => ({ ...c, urgent: true })) : confirm;
}

/** First key of a scope, or a new one after someone left (design §7). */
export async function createScopeKeyVersion(
  d: RingDeps,
  ready: VaultReady,
  scope: ContentScope,
  scopeId: string,
): Promise<{ version: number; confirm: ConfirmCase[] }> {
  const { data, error } = await d.supabase.rpc("e2e_begin_key_version", { _scope: scope, _scope_id: scopeId });
  if (error) throw error;
  const version = data as number;
  const key = generateContentKey();
  await publishKeyCommit(d, ready, scope, scopeId, version, key);
  await insertEnvelope(d, ready, scope, scopeId, version, key, {
    userId: d.userId,
    identityId: ready.identityId,
    pub: { x25519Pub: ready.ak.x25519Pub, edPk: ready.ak.edPk },
  });
  return { version, confirm: await fillVersion(d, ready, scope, scopeId, version, key) };
}

/**
 * The first key of a family that does not exist yet (Schritt 3, G1): this
 * device founds it, so it makes FMK_1 and wraps it for its own account key.
 * e2e_create_family (0159) stores family, version 1 and this envelope in one
 * transaction — the name never reaches the server unsealed.
 */
export async function foundingKey(
  userId: string,
  ready: VaultReady,
  familyId: string,
): Promise<{ rowKeys: RowKeys; envelope: { enc: string; ct: string; sig: string } }> {
  const key = generateContentKey();
  const env = await sealEnvelope({
    scope: "family",
    scopeId: familyId,
    version: 1,
    contentKey: key,
    recipient: userId,
    recipientPub: { x25519Pub: ready.ak.x25519Pub, edPk: ready.ak.edPk },
    sender: userId,
    senderAk: ready.ak,
  });
  return {
    rowKeys: await rowKeysOfRaw(new Map([[1, key]]), 1),
    envelope: { enc: toPgBytea(env.enc), ct: toPgBytea(env.ct), sig: toPgBytea(env.sig) },
  };
}

/**
 * Make sure the scope HAS a current key that nobody who left knows — the
 * owner's device creates the first family key of a pilot family when it opens
 * (Etappe 2, 0133), and the next one after someone left (Etappe 4, design §7).
 *   no version yet            → create the first one;
 *   current, nothing due      → nothing to do;
 *   a version newer than the current one that I hold and that was begun after
 *   the last departure (0143: same epoch)
 *                             → an earlier run stopped half way (tab closed, or
 *                               waiting for a confirmation): seal it for whoever
 *                               is still missing;
 *   rotation due              → a new version — but only from a device that
 *                               holds the current one: a device in the middle of
 *                               a rescue would hand out a key from an account
 *                               key the others do not trust yet;
 *   none current, none held   → nothing (a release for a device that has it).
 * Callers serialise per scope (Web Lock), because e2e_begin_key_version always
 * hands out the NEXT number. Two owners on two devices may both rotate: they get
 * v+1 and v+2, the higher one becomes current.
 */
export async function ensureScopeKey(
  d: RingDeps,
  ready: VaultReady,
  scope: ContentScope,
  scopeId: string,
): Promise<ConfirmCase[]> {
  const [{ data: versions, error: e1 }, { data: st, error: e2 }] = await Promise.all([
    d.supabase.from("key_versions").select("version, epoch").eq("scope", scope).eq("scope_id", scopeId),
    d.supabase
      .from("key_scope_state")
      .select("current_version, rotation_pending, rotation_epoch")
      .eq("scope", scope)
      .eq("scope_id", scopeId)
      .maybeSingle(),
  ]);
  if (e1 || e2) throw e1 ?? e2;
  const all = (versions ?? []) as { version: number; epoch: number }[];
  if (all.length === 0) return (await createScopeKeyVersion(d, ready, scope, scopeId)).confirm;
  const state = st as { current_version: number | null; rotation_pending: boolean; rotation_epoch: number } | null;
  const current = state?.current_version ?? null;
  const due = state?.rotation_pending === true;
  if (current !== null && !due) return [];

  const { keys, readOnly } = await loadScopeKeys(d, ready, scope, scopeId);
  // A version this device may only read is never handed on to everyone (K-05).
  const unfinished = all
    .filter((v) => keys.has(v.version) && !readOnly.has(v.version) && (current === null || v.version > current))
    .filter((v) => !due || v.epoch === state!.rotation_epoch)
    .map((v) => v.version);
  if (unfinished.length > 0) {
    const newest = Math.max(...unfinished);
    return fillVersion(d, ready, scope, scopeId, newest, keys.get(newest)!);
  }
  if (due && (current === null ? keys.size > 0 : keys.has(current))) {
    return (await createScopeKeyVersion(d, ready, scope, scopeId)).confirm;
  }
  return [];
}

export type RowKeys = {
  /** Every version this device can open, as non-extractable AES-256-GCM keys (row format v1). */
  keys: Map<number, CryptoKey>;
  /** The HKDF row key of each version (format v2, AP-Zeilen v2), non-extractable. */
  v2Keys: Map<number, CryptoKey>;
  /** The HKDF media-seal key of each version (cover/logo in format v2, mediaSeal.ts). */
  sealKeys: Map<number, CryptoKey>;
  /** The tag blind-index key of each version (design §4.5), non-extractable. */
  tagKeys: Map<number, CryptoKey>;
  /** The media base key of each version (E5.1, objectKey.ts) — derives only. */
  mediaBases: Map<number, CryptoKey>;
  /** The version new rows are written with (null: no complete key yet). */
  current: number | null;
  /** Versions this device may only read (opened through an earlier key, K-05). */
  readOnly?: ReadonlySet<number>;
};

/**
 * The scope's keys for encrypted rows (Etappe 2, design §4.3): reading needs
 * every version a row may carry, writing the current one. Same trust rules as
 * loadScopeKeys — this only turns the raw bytes into keys that cannot be read
 * back out of WebCrypto.
 */
export async function loadRowKeys(
  d: RingDeps,
  ready: VaultReady,
  scope: ContentScope,
  scopeId: string,
): Promise<RowKeys> {
  const { keys, current, readOnly } = await loadScopeKeys(d, ready, scope, scopeId);
  return rowKeysOfRaw(keys, current, readOnly);
}

/**
 * Everything rows and media need from a scope's raw keys — also for a key this
 * device made a moment ago and the server has not seen yet (founding a family,
 * Schritt 3).
 */
export async function rowKeysOfRaw(
  keys: ReadonlyMap<number, Bytes>,
  current: number | null,
  readOnly: ReadonlySet<number> = new Set(),
): Promise<RowKeys> {
  const out = new Map<number, CryptoKey>();
  const tagKeys = new Map<number, CryptoKey>();
  const mediaBases = new Map<number, CryptoKey>();
  const v2Keys = new Map<number, CryptoKey>();
  const sealKeys = new Map<number, CryptoKey>();
  for (const [v, raw] of keys) {
    out.set(v, await importAesKey(raw));
    v2Keys.set(v, await rowKeyV2(raw));
    sealKeys.set(v, await mediaSealKeyV2(raw));
    // Derived while the raw bytes are at hand — the AES key cannot give them back.
    tagKeys.set(v, await tagIndexKey(raw));
    mediaBases.set(v, await mediaBaseKey(raw));
  }
  return {
    keys: out,
    v2Keys,
    sealKeys,
    tagKeys,
    mediaBases,
    current: current !== null && out.has(current) && !readOnly.has(current) ? current : null,
    readOnly,
  };
}

/**
 * A human confirmed this person's key (design §6.2) — after a call, in person,
 * or by comparing the safety code. Adopts exactly the fingerprint that was on
 * screen, then releases.
 */
export async function confirmPerson(d: RingDeps, ready: VaultReady, c: ConfirmCase): Promise<void> {
  if (c.reason === "sender") return confirmSender(d, ready, c);
  const held = await loadScopeKeys(d, ready, c.scope, c.scopeId);
  const pending = (await pendingFor(d, c.scope, c.scopeId, waitingVersion(held.current, held.keys))).find(
    (r) => r.user_id === c.userId,
  );
  if (!pending || pending.identity_id !== c.identityId) throw new Error("confirmPerson: no longer pending");
  const pub = pubOf(pending);
  if ((await fingerprint(pub)) !== c.fingerprint) throw new Error("confirmPerson: key changed meanwhile");
  let store = await loadTrustStore(d.kv, d.userId);
  if (store.entries[c.userId]?.pendingChange?.fingerprint === c.fingerprint) {
    store = acceptChange(store, c.userId, c.fingerprint);
  } else {
    const seen = await observe(store, {
      userId: c.userId,
      identityId: c.identityId,
      pub,
      selfSig: fromPgBytea(pending.self_sig),
    });
    if (seen.status === "changed") store = acceptChange(seen.store, c.userId, c.fingerprint);
    else if (seen.status === "invalid") throw new Error("confirmPerson: invalid self-signature");
    else store = withOrigin(seen.store, c.userId, "confirmed");
  }
  await mergeIntoTrustStore(d.kv, d.userId, store);
  await publishVouch(d, ready, c.userId, c.identityId, c.fingerprint, {
    scope: c.scope,
    scopeId: c.scopeId,
    version: waitingVersion(held.current, held.keys) ?? held.current,
  });
  // A human said yes HERE, for this scope: release now, even without proof of
  // an earlier version (that proof is only what a SILENT release needs).
  await releaseConfirmed(d, ready, c.scope, c.scopeId, pending, pub);
  await releasePending(d, ready, c.scope, c.scopeId);
  // A rotation that was waiting for exactly this person can finish now.
  const { keys, current } = await loadScopeKeys(d, ready, c.scope, c.scopeId);
  for (const v of [...keys.keys()].filter((v) => v > (current ?? 0)).sort((a, b) => a - b)) {
    await d.supabase.rpc("e2e_complete_key_version", { _scope: c.scope, _scope_id: c.scopeId, _version: v });
  }
}

/** Trust an unknown sender after a human confirmed them (no release involved). */
async function confirmSender(d: RingDeps, ready: VaultReady, c: ConfirmCase): Promise<void> {
  const { data, error } = await d.supabase
    .from("user_identity_keys")
    .select("id, user_id, x25519_pub, ed25519_pub, self_sig")
    .eq("id", c.identityId)
    .maybeSingle();
  if (error) throw error;
  const row = data as IdentityRow | null;
  if (!row || row.user_id !== c.userId || (await fingerprint(pubOf(row))) !== c.fingerprint) {
    throw new Error("confirmPerson: sender key changed meanwhile");
  }
  const store = await loadTrustStore(d.kv, d.userId);
  const seen = await observe(store, { userId: c.userId, identityId: row.id, pub: pubOf(row), selfSig: fromPgBytea(row.self_sig) });
  if (seen.status === "invalid") throw new Error("confirmPerson: invalid self-signature");
  await mergeIntoTrustStore(
    d.kv,
    d.userId,
    seen.status === "changed" ? acceptChange(seen.store, c.userId, c.fingerprint) : withOrigin(seen.store, c.userId, "confirmed"),
  );
  await publishVouch(d, ready, c.userId, c.identityId, c.fingerprint);
}

/** Seal every version this device holds for one person a human just confirmed for this scope. */
async function releaseConfirmed(
  d: RingDeps,
  ready: VaultReady,
  scope: ContentScope,
  scopeId: string,
  row: PendingRow,
  pub: PublicAccountKey,
): Promise<void> {
  const { keys } = await loadScopeKeys(d, ready, scope, scopeId);
  for (const [version, key] of keys) {
    await insertEnvelope(d, ready, scope, scopeId, version, key, { userId: row.user_id, identityId: row.identity_id, pub });
  }
}

// --- Vouches (0148, design §5.4) ---------------------------------------------------

type Candidate = { userId: string; identityId: string; pub: PublicAccountKey; selfSig: Uint8Array };

const candidateOf = (row: PendingRow): Candidate => ({
  userId: row.user_id,
  identityId: row.identity_id,
  pub: pubOf(row),
  selfSig: fromPgBytea(row.self_sig),
});

/**
 * A human here confirmed this key: say so, signed, for the rest of the family
 * (0148). Best effort — the confirmation on this device stands either way, and
 * the database refuses it from people who may not release (Q19).
 */
async function publishVouch(
  d: RingDeps,
  ready: VaultReady,
  subject: string,
  subjectIdentity: string,
  fp: string,
  scope?: { scope: ContentScope; scopeId: string; version: number | null },
) {
  if (subject === d.userId) return;
  const sig = signVouch(ready.ak, { subject, subjectIdentity, fingerprint: fp });
  await d.supabase
    .from("key_vouches")
    .insert({ voucher: d.userId, voucher_identity: ready.identityId, subject, subject_identity: subjectIdentity, sig: toPgBytea(sig) })
    .then(
      () => undefined,
      () => undefined,
    );
  if (!scope || scope.version === null) return;
  // The yes was for THIS scope and version: other holders may then release
  // exactly that version silently (0164).
  const scoped = signScopeVouch(ready.ak, {
    scope: scope.scope,
    scopeId: scope.scopeId,
    version: scope.version,
    subject,
    subjectIdentity,
    fingerprint: fp,
  });
  await d.supabase
    .from("key_scope_vouches")
    .insert({
      scope: scope.scope,
      scope_id: scope.scopeId,
      version: scope.version,
      voucher: d.userId,
      voucher_identity: ready.identityId,
      subject,
      subject_identity: subjectIdentity,
      sig: toPgBytea(scoped),
    })
    .then(
      () => undefined,
      () => undefined,
    );
}

/**
 * Keys new to this device (or a person's NEW key) that someone this device
 * trusts has vouched for are adopted — the one human yes counts for everyone.
 * A vouch only counts from a voucher whose CURRENT key this device holds (or
 * this person's own other device), never from the person themselves, and only
 * for exactly the identity and fingerprint presented. And (S-05, 17.10.2026)
 * only from someone who provably holds `ctx.version` of THIS scope — somebody
 * who left, or was only ever met on first use, vouches for nothing. Without
 * `ctx` only my own devices count. Returns the store as it is then (unchanged
 * when nothing applied); the caller saves it.
 */
export async function adoptVouched(
  d: RingDeps,
  ready: VaultReady,
  store: TrustStore,
  candidates: Candidate[],
  ctx?: { scope: KeyScope; scopeId: string; version: number | null },
): Promise<TrustStore> {
  const others = candidates.filter((c) => c.userId !== d.userId);
  if (others.length === 0) return store;
  const { data, error } = await d.supabase
    .from("key_vouches")
    .select("voucher, subject, subject_identity, sig")
    .in("subject_identity", [...new Set(others.map((c) => c.identityId))]);
  if (error || !data || data.length === 0) return store;
  const rows = data as { voucher: string; subject: string; subject_identity: string; sig: string }[];
  const me = { x25519Pub: ready.ak.x25519Pub, edPk: ready.ak.edPk };

  // Vouchers other than me must hold the scope's current version (and be more than a first use).
  const vouchers: Holder[] = [];
  for (const id of new Set(rows.map((r) => r.voucher))) {
    if (id === d.userId || !earnsSilentTrust(store, id)) continue;
    const e = store.entries[id];
    vouchers.push({ userId: id, identityId: e.identityId, x25519Pub: fromB64url(e.x25519Pub) });
  }
  const holding = ctx ? await holdersOf(d, ready, ctx.scope, ctx.scopeId, ctx.version, vouchers, store) : new Set<string>();
  const mayVouch = (id: string) => id === d.userId || vouchers.some((v) => v.userId === id && holding.has(v.identityId));

  let next = store;
  for (const c of others) {
    // A key this person moved away from stays behind, whoever vouched for it
    // back then — me included (KP-05: the server may hand it out as pending).
    if (next.entries[c.userId]?.previous.includes(await fingerprint(c.pub))) continue;
    const seen = await observe(
      next,
      { userId: c.userId, identityId: c.identityId, pub: c.pub, selfSig: c.selfSig },
      new Date(),
      "vouched",
    );
    if (seen.status !== "new" && seen.status !== "changed") continue;
    const fp = await fingerprint(c.pub);
    const vouched = rows.some((r) => {
      if (r.subject !== c.userId || r.subject_identity !== c.identityId || r.voucher === c.userId) return false;
      if (!mayVouch(r.voucher)) return false;
      const voucher = r.voucher === d.userId ? me : trustedKey(next, r.voucher);
      return !!voucher && verifyVouch(voucher, { subject: c.userId, subjectIdentity: c.identityId, fingerprint: fp }, fromPgBytea(r.sig));
    });
    if (vouched) next = seen.status === "changed" ? acceptChange(seen.store, c.userId, fp, "vouched") : seen.store;
  }
  return next;
}

/**
 * Scopes this person may hold keys for (RLS returns only those) — also one
 * whose first version is not current yet: its waiting people must still get
 * their card (live 12.10.2026). A scope this device holds nothing of returns
 * at once in releasePending.
 */
export async function myScopes(d: RingDeps): Promise<{ scope: ContentScope; scopeId: string }[]> {
  const { data, error } = await d.supabase.from("key_scope_state").select("scope, scope_id").in("scope", ["family", "story"]);
  if (error) throw error;
  return ((data ?? []) as { scope: ContentScope; scope_id: string }[]).map((r) => ({ scope: r.scope, scopeId: r.scope_id }));
}

/** Run on every unlocked page load: release what may be released, collect the rest. */
export async function processPendingReleases(d: RingDeps, ready: VaultReady): Promise<ConfirmCase[]> {
  const out: ConfirmCase[] = [];
  for (const s of await myScopes(d)) {
    try {
      out.push(...(await releasePending(d, ready, s.scope, s.scopeId)).confirm);
    } catch {
      // One scope failing (e.g. just left the family) must not stop the others.
    }
  }
  // My profile picture's key to people who became known since (E3.6). Silent:
  // it never asks a human (see releaseOwnAvatar).
  await releaseOwnAvatar(d, ready).catch(() => {});
  return out;
}

// --- Profile pictures (E2E Etappe 3 · E3.6, design §3) ------------------------------
//
// One key per person (scope "avatar", scope id = the person), made by their
// own device and sealed by it for everyone allowed to see the picture
// (e2e_may_hold: shares a family or a collaborative story). Stricter than the
// family and story keys, on purpose:
//   • only the person's own envelopes count (loadScopeKeys filters by sender);
//   • no trust on first use and no confirmation cards — the key goes to people
//     this device already trusts, the rest see initials until a family or
//     story key has made them known (then the next release picks them up).
// A version is therefore rarely "complete"; the newest held version is used.

/** The newest avatar key version of `ownerId` this device can open, or null. */
export async function avatarKey(
  d: RingDeps,
  ready: VaultReady,
  ownerId: string,
): Promise<{ version: number; key: Bytes; all: Map<number, Bytes> } | null> {
  const { keys } = await loadScopeKeys(d, ready, "avatar", ownerId);
  if (keys.size === 0) return null;
  const version = Math.max(...keys.keys());
  return { version, key: keys.get(version)!, all: keys };
}

/** My own avatar key — the first one is made here (needs a pilot family, 0133). */
export async function ensureOwnAvatarKey(d: RingDeps, ready: VaultReady): Promise<{ version: number; key: Bytes }> {
  const have = await avatarKey(d, ready, d.userId);
  if (have) return { version: have.version, key: have.key };
  return newOwnAvatarVersion(d, ready);
}

/**
 * Etappe 4 (0143): someone I shared a family or story with left, or my account
 * key was replaced — my next picture gets a key they never held. The picture
 * that is up stays under its version (they saw it already, Q14); begin clears
 * the marking for avatars. Only when I had a key before: no picture, nothing to
 * rotate. Callers hold the same Web Lock as uploadE2eAvatar.
 */
export async function rotateOwnAvatarIfDue(d: RingDeps, ready: VaultReady): Promise<boolean> {
  const { data, error } = await d.supabase
    .from("key_scope_state")
    .select("rotation_pending")
    .eq("scope", "avatar")
    .eq("scope_id", d.userId)
    .maybeSingle();
  if (error) throw error;
  if (!(data as { rotation_pending: boolean } | null)?.rotation_pending) return false;
  if (!(await avatarKey(d, ready, d.userId))) return false;
  await newOwnAvatarVersion(d, ready);
  return true;
}

async function newOwnAvatarVersion(d: RingDeps, ready: VaultReady): Promise<{ version: number; key: Bytes }> {
  const { data, error } = await d.supabase.rpc("e2e_begin_key_version", { _scope: "avatar", _scope_id: d.userId });
  if (error) throw error;
  const version = data as number;
  const key = generateContentKey();
  await publishKeyCommit(d, ready, "avatar", d.userId, version, key);
  await insertEnvelope(d, ready, "avatar", d.userId, version, key, {
    userId: d.userId,
    identityId: ready.identityId,
    pub: { x25519Pub: ready.ak.x25519Pub, edPk: ready.ak.edPk },
  });
  return { version, key };
}

/** Seal my newest avatar key for everyone allowed whom this device already trusts. */
export async function releaseOwnAvatar(d: RingDeps, ready: VaultReady): Promise<string[]> {
  const mine = await avatarKey(d, ready, d.userId);
  if (!mine) return [];
  const store = await loadTrustStore(d.kv, d.userId);
  const released: string[] = [];
  for (const row of await pendingFor(d, "avatar", d.userId, mine.version)) {
    const pub = pubOf(row);
    const seen = await observe(store, {
      userId: row.user_id,
      identityId: row.identity_id,
      pub,
      selfSig: fromPgBytea(row.self_sig),
    });
    if (seen.status !== "known") continue;
    await insertEnvelope(d, ready, "avatar", d.userId, mine.version, mine.key, {
      userId: row.user_id,
      identityId: row.identity_id,
      pub,
    });
    released.push(row.user_id);
  }
  return released;
}

// --- Safety codes (design §5.5) ------------------------------------------------------

/** The 60-digit code between me and `userId`'s key `identityId`, and its fingerprint. */
export async function safetyCodeWith(
  d: RingDeps,
  ready: VaultReady,
  userId: string,
  identityId: string,
): Promise<{ code: string; fingerprint: string; ownFirst: boolean }> {
  const { data, error } = await d.supabase
    .from("user_identity_keys")
    .select("id, user_id, x25519_pub, ed25519_pub, self_sig")
    .eq("id", identityId)
    .maybeSingle();
  if (error) throw error;
  const row = data as IdentityRow | null;
  if (!row || row.user_id !== userId) throw new Error("safetyCodeWith: unknown identity");
  const pub = pubOf(row);
  const groups = await safetyCode({ userId: d.userId, edPk: ready.ak.edPk }, { userId, edPk: pub.edPk });
  const code = groups.join("");
  // The halves are sorted; which one is mine labels them (KP-06).
  const ownFirst = code.startsWith(await safetyCodeHalf(d.userId, ready.ak.edPk));
  return { code, fingerprint: await fingerprint(pub), ownFirst };
}

/** After comparing the code: remember that this person's CURRENT key was checked. */
export async function markPersonVerified(d: RingDeps, userId: string, fingerprintShown: string): Promise<void> {
  const store = await loadTrustStore(d.kv, d.userId);
  await mergeIntoTrustStore(d.kv, d.userId, markVerified(store, userId, fingerprintShown));
}

/**
 * The people of my families as the server lists them (KP-01, KP-08): the
 * families we share and the account key the server names for them now — only
 * with a valid self-signature, and for COMPARING only: nothing here is trusted.
 * A newcomer can so compare codes before the first envelope arrives.
 */
export async function familyPeople(
  d: RingDeps,
): Promise<Map<string, { familyIds: string[]; key: { identityId: string; fingerprint: string } | null }>> {
  const out = new Map<string, { familyIds: string[]; key: { identityId: string; fingerprint: string } | null }>();
  const { data: mine, error: e1 } = await d.supabase.from("family_members").select("family_id").eq("user_id", d.userId);
  if (e1) throw e1;
  const families = ((mine ?? []) as { family_id: string }[]).map((r) => r.family_id);
  if (families.length === 0) return out;
  const { data: members, error: e2 } = await d.supabase
    .from("family_members")
    .select("family_id, user_id")
    .in("family_id", families);
  if (e2) throw e2;
  for (const m of (members ?? []) as { family_id: string; user_id: string }[]) {
    if (m.user_id === d.userId) continue;
    const p = out.get(m.user_id) ?? { familyIds: [], key: null };
    if (!p.familyIds.includes(m.family_id)) p.familyIds.push(m.family_id);
    out.set(m.user_id, p);
  }
  if (out.size === 0) return out;
  const { data: keys, error: e3 } = await d.supabase
    .from("user_identity_keys")
    .select("id, user_id, x25519_pub, ed25519_pub, self_sig")
    .in("user_id", [...out.keys()])
    .is("replaced_at", null);
  if (e3) throw e3;
  for (const row of (keys ?? []) as IdentityRow[]) {
    const p = out.get(row.user_id);
    const pub = pubOf(row);
    if (!p || !verifySelf(pub, row.user_id, fromPgBytea(row.self_sig))) continue;
    p.key = { identityId: row.id, fingerprint: await fingerprint(pub) };
  }
  return out;
}

/** People this device trusts, for the safety code list. */
export async function trustedPeople(
  d: RingDeps,
): Promise<{ userId: string; identityId: string; fingerprint: string; verified: boolean; firstSeen: string }[]> {
  const store = await loadTrustStore(d.kv, d.userId);
  return Object.entries(store.entries).map(([userId, e]) => ({
    userId,
    identityId: e.identityId,
    fingerprint: e.fingerprint,
    verified: e.verified,
    // When my devices first saw this person (KP-08: tells two of the same name apart).
    firstSeen: e.firstSeen,
  }));
}
