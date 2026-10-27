// =============================================================================
// Trust store — whose account key do I believe? (docs/e2e-design.md §5.4)
//
// Trust On First Use: the first public key seen for a person is accepted. After
// that, a DIFFERENT key for the same person is never adopted silently. It is
// parked as `pendingChange` and the person shows "safety code changed" until a
// human confirms (`acceptChange`) — that is the one place an actively malicious
// server (design A3) would try to slip in its own key, so it is the one place
// a human has to say yes.
//
// Pure data + functions. Persistence (encrypted with the device storage key)
// lives in deviceStore.ts.
// =============================================================================

import { fromB64url, toB64url } from "./bytes";
import { fingerprint, verifySelf, type PublicAccountKey } from "./identity";

export type TrustedKey = {
  identityId: string;
  x25519Pub: string; // base64url
  edPk: string; // base64url
  fingerprint: string;
};

/**
 * How this device came to trust the key (P1, security review 17.10.2026):
 *   confirmed — a human said yes on one of my devices;
 *   vouched   — someone who holds the scope's current key confirmed it (0148);
 *   tofu      — taken on first use by a newcomer device, with nothing to compare.
 * Absent: an entry from before 17.10.2026 — kept as trusted (decision P1-1).
 * A "tofu" entry opens envelopes, but never earns a silent release or counts
 * as a voucher (S-18).
 */
export type TrustOrigin = "confirmed" | "vouched" | "tofu";

export type TrustEntry = TrustedKey & {
  firstSeen: string; // ISO
  origin?: TrustOrigin;
  /** Safety code compared in person (design §5.5). */
  verified: boolean;
  /** A different key the server presented, awaiting a human decision. */
  pendingChange?: TrustedKey & { seen: string };
  /** Fingerprints this person used before (for "key changed on …" display). */
  previous: string[];
};

export type TrustStore = { version: 1; entries: Record<string, TrustEntry> };

export function emptyTrustStore(): TrustStore {
  return { version: 1, entries: {} };
}

export type Observation =
  | { status: "new"; store: TrustStore }
  | { status: "known"; store: TrustStore }
  | { status: "changed"; store: TrustStore }
  | { status: "invalid"; store: TrustStore };

export type ObservedKey = {
  userId: string;
  identityId: string;
  pub: PublicAccountKey;
  selfSig: Uint8Array;
};

/**
 * Feed every public key the server hands us through here BEFORE using it.
 * Returns a new store (the input is not mutated).
 */
export async function observe(
  store: TrustStore,
  k: ObservedKey,
  now = new Date(),
  /** Recorded on a NEW entry; an existing entry keeps its own (see withOrigin). */
  origin?: TrustOrigin,
): Promise<Observation> {
  if (!verifySelf(k.pub, k.userId, k.selfSig)) return { status: "invalid", store };
  const fp = await fingerprint(k.pub);
  const key: TrustedKey = {
    identityId: k.identityId,
    x25519Pub: toB64url(k.pub.x25519Pub),
    edPk: toB64url(k.pub.edPk),
    fingerprint: fp,
  };
  const existing = store.entries[k.userId];

  if (!existing) {
    const entry: TrustEntry = {
      ...key,
      firstSeen: now.toISOString(),
      ...(origin ? { origin } : {}),
      verified: false,
      previous: [],
    };
    return { status: "new", store: withEntry(store, k.userId, entry) };
  }
  if (existing.fingerprint === fp) {
    // Same key; a stale pending change (server flip-flopping) is dropped.
    if (!existing.pendingChange && existing.identityId === k.identityId) return { status: "known", store };
    const { pendingChange: _drop, ...rest } = existing;
    return { status: "known", store: withEntry(store, k.userId, { ...rest, identityId: k.identityId }) };
  }
  if (existing.pendingChange?.fingerprint === fp) return { status: "changed", store };
  const entry: TrustEntry = { ...existing, pendingChange: { ...key, seen: now.toISOString() } };
  return { status: "changed", store: withEntry(store, k.userId, entry) };
}

/** A human confirmed the new key (rescue, design §6.2) — or a vouch did (origin "vouched"). */
export function acceptChange(
  store: TrustStore,
  userId: string,
  expectedFingerprint: string,
  origin: TrustOrigin = "confirmed",
): TrustStore {
  const e = store.entries[userId];
  if (!e?.pendingChange || e.pendingChange.fingerprint !== expectedFingerprint) {
    // The key on screen is not the key we would adopt — refuse rather than guess.
    throw new Error("acceptChange: no matching pending change");
  }
  const { seen: _seen, ...next } = e.pendingChange;
  return withEntry(store, userId, {
    ...next,
    firstSeen: e.firstSeen,
    origin,
    verified: false,
    // The adopted key is never among its own predecessors (KP-05).
    previous: [...new Set([...e.previous, e.fingerprint])].filter((f) => f !== next.fingerprint),
  });
}

/**
 * KP-05 (Klickprobe 26.10.2026): an entry that fell back to a key the person
 * had moved away from carries its own fingerprint among the previous ones.
 * Returns the fingerprint this device had adopted last after it — the key to
 * go back to — or null for a sound entry.
 */
export function rolledBackTo(e: TrustEntry): string | null {
  const at = e.previous.lastIndexOf(e.fingerprint);
  if (at < 0) return null;
  const later = e.previous.slice(at + 1).filter((f) => f !== e.fingerprint);
  return later.length > 0 ? later[later.length - 1] : null;
}

/** Puts back the key `rolledBackTo` named (the caller matched it by fingerprint). */
export function restoreRolledBack(store: TrustStore, userId: string, key: TrustedKey): TrustStore {
  const e = store.entries[userId];
  if (!e || rolledBackTo(e) !== key.fingerprint) throw new Error("restoreRolledBack: not that entry's key");
  const { pendingChange: _drop, ...rest } = e;
  return withEntry(store, userId, {
    ...rest,
    ...key,
    verified: false,
    previous: [...new Set([...e.previous, e.fingerprint])].filter((f) => f !== key.fingerprint),
  });
}

const RANK: Record<TrustOrigin | "legacy", number> = { tofu: 0, vouched: 1, confirmed: 2, legacy: 2 };
const rankOf = (o: TrustOrigin | undefined) => RANK[o ?? "legacy"];

/** The stronger of two origins (a confirmation outranks a vouch, a vouch first use). */
function strongerOrigin(a: TrustOrigin | undefined, b: TrustOrigin | undefined): TrustOrigin | undefined {
  return rankOf(a) >= rankOf(b) ? a : b;
}

/** Raise the origin of the CURRENT key of a person (never lowers it). */
export function withOrigin(store: TrustStore, userId: string, origin: TrustOrigin): TrustStore {
  const e = store.entries[userId];
  if (!e || rankOf(e.origin) >= rankOf(origin)) return store;
  return withEntry(store, userId, { ...e, origin });
}

/**
 * Whether this person's key may earn a silent release or count as a voucher
 * (S-18): anything but a first-use key. Entries from before 17.10.2026 count
 * (P1-1).
 */
export function earnsSilentTrust(store: TrustStore, userId: string): boolean {
  const e = store.entries[userId];
  return !!e && e.origin !== "tofu";
}

/** Safety code compared and matching (design §5.5). */
export function markVerified(store: TrustStore, userId: string, expectedFingerprint: string): TrustStore {
  const e = store.entries[userId];
  if (!e || e.fingerprint !== expectedFingerprint) throw new Error("markVerified: fingerprint mismatch");
  return withEntry(store, userId, { ...e, verified: true });
}

/**
 * The key to verify a sender's signature with. Only the ACCEPTED key — a
 * pending change is never used for verification.
 */
export function trustedKey(store: TrustStore, userId: string): (PublicAccountKey & { identityId: string }) | null {
  const e = store.entries[userId];
  if (!e) return null;
  return { identityId: e.identityId, x25519Pub: fromB64url(e.x25519Pub), edPk: fromB64url(e.edPk) };
}

export function pendingChanges(store: TrustStore): string[] {
  return Object.entries(store.entries)
    .filter(([, e]) => e.pendingChange)
    .map(([userId]) => userId);
}

function withEntry(store: TrustStore, userId: string, entry: TrustEntry): TrustStore {
  return { ...store, entries: { ...store.entries, [userId]: entry } };
}

export function parseTrustStore(json: string): TrustStore {
  const v = JSON.parse(json) as Partial<TrustStore>;
  if (v?.version !== 1 || typeof v.entries !== "object" || v.entries === null) {
    throw new Error("parseTrustStore: unknown format");
  }
  return v as TrustStore;
}

/**
 * Merge the trust store of another of MY devices (synced, design §5.4) into
 * this one. Conservative on conflict: if both devices trust different keys for
 * a person, this device keeps its own and parks the other as a pending change —
 * unless the other device ALREADY confirmed a change away from our key (our
 * fingerprint is in its `previous`), in which case a human said yes there.
 */
export function mergeTrustStores(local: TrustStore, remote: TrustStore): TrustStore {
  const entries: Record<string, TrustEntry> = { ...local.entries };
  for (const [userId, r] of Object.entries(remote.entries)) {
    const l = entries[userId];
    if (!l) {
      entries[userId] = r;
    } else if (l.fingerprint === r.fingerprint) {
      const { pendingChange: _drop, ...base } = l;
      const pending = l.pendingChange ?? r.pendingChange;
      const origin = strongerOrigin(l.origin, r.origin);
      const { origin: _o, ...rest } = base;
      entries[userId] = {
        ...rest,
        ...(origin ? { origin } : {}),
        firstSeen: l.firstSeen < r.firstSeen ? l.firstSeen : r.firstSeen,
        verified: l.verified || r.verified,
        previous: [...new Set([...l.previous, ...r.previous])],
        ...(pending ? { pendingChange: pending } : {}),
      };
    } else if (l.previous.includes(r.fingerprint) || r.previous.includes(l.fingerprint)) {
      // One side moved on from the other's key: it wins, and the key left
      // behind is never parked as a change back (KP-05). Both claiming it means
      // one side fell back — the side that did not.
      const lMoved = l.previous.includes(r.fingerprint);
      const rMoved = r.previous.includes(l.fingerprint);
      const w = lMoved && rMoved ? (rolledBackTo(l) && !rolledBackTo(r) ? r : l) : lMoved ? l : r;
      const previous = [...new Set([...l.previous, ...r.previous, l.fingerprint, r.fingerprint])].filter(
        (f) => f !== w.fingerprint,
      );
      const { pendingChange: pc, ...base } = w;
      entries[userId] = { ...base, previous, ...(pc && !previous.includes(pc.fingerprint) ? { pendingChange: pc } : {}) };
    } else {
      const { firstSeen: _f, verified: _v, previous: _p, pendingChange: _pc, ...key } = r;
      entries[userId] = { ...l, pendingChange: { ...key, seen: r.firstSeen } };
    }
  }
  return { version: 1, entries };
}
