// =============================================================================
// Checking a v2 row beyond its signature (AP-Zeilen v2, Z1/Z2):
//   1. Whose key is this? A signer identity counts only when its self-signature
//      names the user, and this device's trust store agrees: the accepted key,
//      or — for rows of an OLDER key version only — one this person used
//      before (same rule as for envelope senders, keyRing.ts). A person this
//      device has never seen is taken on first use (TOFU, trustStore.ts) — and
//      PINNED (K-08, 18.10.2026): that first key is kept, as origin "tofu" (it
//      never earns a release), and a second, other key of the same person no
//      longer counts. A key change still waiting for a human is never used.
//   2. May they sign this row? authorOrOwner / member / owner (rowFields.ts),
//      and the "Bestand" flag only from an owner.
//   3. Is it older than what this device already showed? Each device keeps the
//      highest revision per row; a lower one, or a v1 blob for a row it has
//      seen as v2, is a rollback.
// Anything that fails → the reader shows "could not be checked" (Z2), never
// the text.
// =============================================================================

import { fromPgBytea } from "./bytes";
import type { KeyValueStore } from "./deviceStore";
import { fingerprint, verifySelf } from "./identity";
import type { SignerRule } from "./rowFields";
import { observe, type ObservedKey, type TrustStore } from "./trustStore";

export type IdentityRow = { id: string; user_id: string; x25519_pub: string; ed25519_pub: string; self_sig: string };

export type TrustedSigner = { userId: string; edPk: Uint8Array; status: "current" | "previous" };

/** identity id → the signer this device believes, or null. */
export type SignerBook = (identityId: string) => Promise<TrustedSigner | null>;

export function makeSignerBook(
  fetchIdentity: (identityId: string) => Promise<IdentityRow | null>,
  store: TrustStore,
  me: { userId: string; identityId: string },
  /** Keep a first-use key (the caller merges it into the trust store). Absent: kept for this book only. */
  pin?: (store: TrustStore) => Promise<void>,
): SignerBook {
  const cache = new Map<string, Promise<TrustedSigner | null>>();
  // First-use keys taken by THIS book, per person — one key each.
  const pinned = new Map<string, string>();
  let current = store;
  async function resolve(identityId: string): Promise<TrustedSigner | null> {
    const row = await fetchIdentity(identityId).catch(() => null);
    if (!row || row.id !== identityId) return null;
    let pub;
    try {
      pub = { x25519Pub: fromPgBytea(row.x25519_pub), edPk: fromPgBytea(row.ed25519_pub) };
      if (!verifySelf(pub, row.user_id, fromPgBytea(row.self_sig))) return null;
    } catch {
      return null;
    }
    if (row.user_id === me.userId) {
      // My own keys: the one on this device, or an earlier one of mine.
      return { userId: me.userId, edPk: pub.edPk, status: identityId === me.identityId ? "current" : "previous" };
    }
    const fp = await fingerprint(pub);
    const entry = current.entries[row.user_id];
    if (!entry) {
      // First use: pinned — the same person with another key is refused from now on.
      const first = pinned.get(row.user_id);
      if (first !== undefined) return first === fp ? { userId: row.user_id, edPk: pub.edPk, status: "current" } : null;
      pinned.set(row.user_id, fp);
      const k: ObservedKey = { userId: row.user_id, identityId, pub, selfSig: fromPgBytea(row.self_sig) };
      const seen = await observe(current, k, new Date(), "tofu");
      if (seen.status === "new") {
        current = seen.store;
        await pin?.(seen.store).catch(() => undefined);
      }
      return { userId: row.user_id, edPk: pub.edPk, status: "current" };
    }
    if (entry.fingerprint === fp) return { userId: row.user_id, edPk: pub.edPk, status: "current" };
    if (entry.previous.includes(fp)) return { userId: row.user_id, edPk: pub.edPk, status: "previous" };
    return null; // a different key — pending a human, or never seen
  }
  return (identityId) => {
    let hit = cache.get(identityId);
    if (!hit) {
      hit = resolve(identityId);
      cache.set(identityId, hit);
    }
    return hit;
  };
}

export type SignerContext = {
  /** The family owner; in a collaborative story also the story's author. */
  owners: ReadonlySet<string>;
  /** Everyone in the family (any role) — for tags and translations. */
  members: ReadonlySet<string>;
  /** The scope's current key version (null: unknown → previous keys refused). */
  currentVersion: number | null;
};

export function signerAllowed(
  rule: SignerRule,
  signer: { userId: string; status: "current" | "previous" },
  row: { author: string; keyVersion: number; legacy: boolean },
  ctx: SignerContext,
): boolean {
  // An earlier key of a person signs only rows of an older key version: a
  // stolen old key cannot write into the version everyone uses now.
  if (signer.status === "previous" && !(ctx.currentVersion !== null && row.keyVersion < ctx.currentVersion)) {
    return false;
  }
  const isOwner = ctx.owners.has(signer.userId);
  if (row.legacy) return isOwner;
  switch (rule) {
    case "authorOrOwner":
      return (row.author !== "" && signer.userId === row.author) || isOwner;
    case "owner":
      return isOwner;
    case "member":
      return ctx.members.has(signer.userId) || isOwner;
  }
}

// ---------------------------------------------------------------------------
// Revisions seen on this device, and the families known to be v2 only.
// Plain (not sealed with the device key): row ids and counters the server
// knows anyway. One record per user, written back at most every few seconds.
// ---------------------------------------------------------------------------

type RevRecord = { rev: Record<string, number>; v2Only: string[]; mediaBound?: string[] };

export type Freshness = "ok" | "rollback";

export class RowRevisions {
  private rec: RevRecord = { rev: {}, v2Only: [] };
  private loaded: Promise<void> | null = null;
  private dirty = false;
  private timer: ReturnType<typeof setTimeout> | null = null;

  constructor(
    private readonly kv: KeyValueStore,
    private readonly userId: string,
    private readonly flushMs = 3000,
  ) {}

  private get key() {
    return `rowrev:${this.userId}`;
  }

  load(): Promise<void> {
    if (!this.loaded) {
      this.loaded = this.kv
        .get<RevRecord>(this.key)
        .then((r) => {
          if (r && typeof r === "object" && r.rev && Array.isArray(r.v2Only)) this.rec = r;
        })
        .catch(() => undefined);
    }
    return this.loaded;
  }

  /** A v2 row at `rev`: rollback if this device showed a higher one; else remember it. */
  seeV2(table: string, rowId: string, rev: number): Freshness {
    const k = `${table}:${rowId}`;
    const seen = this.rec.rev[k] ?? 0;
    if (rev < seen) return "rollback";
    if (rev > seen) {
      this.rec.rev[k] = rev;
      this.touch();
    }
    return "ok";
  }

  /** The highest revision this device has shown of a row (0: never as v2) — writers count on from it. */
  highest(table: string, rowId: string): number {
    return this.rec.rev[`${table}:${rowId}`] ?? 0;
  }

  /** A v1 row: rollback if this device has shown the row as v2 before. */
  seeV1(table: string, rowId: string): Freshness {
    return this.rec.rev[`${table}:${rowId}`] ? "rollback" : "ok";
  }

  isV2Only(scopeId: string): boolean {
    return this.rec.v2Only.includes(scopeId);
  }

  /** Sticky: once a family said "v2 only" (owner-signed), v1 never counts again here. */
  markV2Only(scopeId: string): void {
    if (this.rec.v2Only.includes(scopeId)) return;
    this.rec.v2Only.push(scopeId);
    this.touch();
  }

  isMediaBound(scopeId: string): boolean {
    return this.rec.mediaBound?.includes(scopeId) ?? false;
  }

  /** Sticky, like v2Only: once a scope said "Medien gebunden" (K-03), unbound media never open again here. */
  markMediaBound(scopeId: string): void {
    const list = (this.rec.mediaBound ??= []);
    if (list.includes(scopeId)) return;
    list.push(scopeId);
    this.touch();
  }

  private touch() {
    this.dirty = true;
    if (this.timer) return;
    this.timer = setTimeout(() => void this.flush(), this.flushMs);
  }

  async flush(): Promise<void> {
    if (this.timer) clearTimeout(this.timer);
    this.timer = null;
    if (!this.dirty) return;
    this.dirty = false;
    await this.kv.set(this.key, this.rec).catch(() => {
      this.dirty = true;
    });
  }
}
