// =============================================================================
// What one device keeps (docs/e2e-design.md §3, §5.1, §5.4), per signed-in user:
//
//   dsk:<user>    the device storage key — AES-256-GCM, NON-extractable. In the
//                 browser it is stored as a CryptoKey object (IndexedDB can hold
//                 those without ever exposing the bytes).
//   ak:<user>     the account key, wrapped with that DSK, plus its identity id
//   trust:<user>  the trust store, encrypted with that DSK
//
// Nothing here is readable from a copy of the IndexedDB files alone: every
// secret is either a non-extractable key or ciphertext under one.
//
// Storage sits behind `KeyValueStore` so the logic is testable in Node; the
// browser implementation is `indexedDbStore()`.
// =============================================================================

import { nativeDeviceKey, type NativeDeviceKey } from "@/lib/native/deviceKey";

import { akWrapAad, generateDeviceStorageKey } from "./akWrap";
import { aesOpen, aesSeal, E2eError, encodeFields, fromUtf8, utf8, type Bytes } from "./bytes";
import { deserializeAccountKey, serializeAccountKey, type AccountKey } from "./identity";
import { emptyTrustStore, mergeTrustStores, parseTrustStore, type TrustStore } from "./trustStore";

export interface KeyValueStore {
  get<T>(key: string): Promise<T | undefined>;
  set(key: string, value: unknown): Promise<void>;
  delete(key: string): Promise<void>;
}

// ---------------------------------------------------------------------------
// Who seals: the device storage key lives either in the browser (WebCrypto,
// non-extractable CryptoKey in IndexedDB) or — inside the Android app — in the
// Android Keystore (DeviceKeyPlugin, Etappe 1e). Every stored record says which
// one sealed it, so a device that later gets the app keeps reading old records.
//
// AP-Android (14.10.2026) and P6 (A-01): inside the app every record moves to
// the newest sealer on its next load — "web" (a browser key, raw on disk:
// IndexedDB's non-extractable flag is only an API barrier), "native" (Keystore
// key of apps up to 1.0.8, no unlock binding) and "native2" (bound, or after
// any Keystore error silently not) become "native3": generation 3, bound to
// the unlocked phone for certain. "native3u" is its fallback without the
// binding (Android 7–8.1, or a Keystore that refuses it); such records try the
// bound key again on every load. Once nothing of a person is sealed with an
// old one, its key is deleted.
// ---------------------------------------------------------------------------

export type SealerKind = "web" | "native" | "native2" | "native3" | "native3u";

type Sealed = { blob: Bytes; by?: SealerKind };
type StoredAk = Sealed & { identityId: string };

export interface DeviceSealer {
  /** Seals and says with what — inside the app that is decided per call (A-01). */
  seal(userId: string, pt: Uint8Array, aad: Uint8Array): Promise<Required<Sealed>>;
  open(userId: string, blob: Uint8Array, aad: Uint8Array): Promise<Bytes>;
  forget(userId: string): Promise<void>;
}

function webSealer(kv: KeyValueStore): DeviceSealer {
  return {
    async seal(userId, pt, aad) {
      return { blob: await aesSeal((await deviceKey(kv, userId, true))!, pt, aad), by: "web" };
    },
    async open(userId, blob, aad) {
      const dsk = await deviceKey(kv, userId, false);
      if (!dsk) throw new E2eError("decrypt");
      return aesOpen(dsk, blob, aad);
    },
    async forget(userId) {
      await kv.delete(`dsk:${userId}`);
    },
  };
}

/** Opens records of `kind`; seals always with generation 3, whatever `kind` is. */
function nativeSealer(n: NativeDeviceKey, kind: Exclude<SealerKind, "web">): DeviceSealer {
  const gen = kind === "native" ? 1 : kind === "native2" ? 2 : 3;
  return {
    async seal(userId, pt, aad) {
      const { blob, bound } = await n.seal(userId, pt, aad);
      return { blob, by: bound ? "native3" : "native3u" };
    },
    async open(userId, blob, aad) {
      try {
        return await n.open(userId, blob, aad, gen, kind !== "native3u");
      } catch {
        throw new E2eError("decrypt");
      }
    },
    forget: (userId) => n.forget(userId),
  };
}

let nativeOverride: NativeDeviceKey | null | undefined;
/** Tests only: pretend to run inside the app (or explicitly not). */
export function overrideNativeDeviceKeyForTests(n: NativeDeviceKey | null | undefined) {
  nativeOverride = n;
}

function native(): NativeDeviceKey | null {
  return nativeOverride !== undefined ? nativeOverride : nativeDeviceKey();
}

function sealerFor(kv: KeyValueStore, kind?: SealerKind): DeviceSealer {
  const n = native();
  if (kind === "web") return webSealer(kv);
  if (kind) {
    if (!n) throw new E2eError("decrypt"); // a native record outside the app
    return nativeSealer(n, kind);
  }
  return n ? nativeSealer(n, "native3") : webSealer(kv);
}

/**
 * Seal `pt` anew with this device's newest sealer and check that the result
 * opens again BEFORE the caller replaces the old record — a Keystore that
 * seals but will not open (a faulty phone) must not cost the person the key.
 */
async function resealChecked(kv: KeyValueStore, userId: string, pt: Bytes, aad: Bytes): Promise<Required<Sealed>> {
  const sealed = await sealerFor(kv).seal(userId, pt, aad);
  const back = await sealerFor(kv, sealed.by).open(userId, sealed.blob, aad);
  if (back.byteLength !== pt.byteLength || back.some((b, i) => b !== pt[i])) throw new E2eError("decrypt");
  return sealed;
}

/**
 * Inside the app, a record not yet sealed by the bound key of generation 3:
 * seal it anew, and replace it only when that brought something — a fallback
 * record that comes out as a fallback again stays as it is. A move that fails
 * leaves the old record too; the next load tries again.
 */
async function moveIfOld(kv: KeyValueStore, userId: string, by: SealerKind, pt: Bytes, aad: Bytes, write: (s: Required<Sealed>) => Promise<void>) {
  if (!native() || by === "native3") return;
  await resealChecked(kv, userId, pt, aad)
    .then((moved) => (moved.by === by ? undefined : write(moved).then(() => retireOldSealers(kv, userId))))
    .catch(() => undefined);
}

/**
 * Inside the app: once neither the account key nor the trust store of this
 * person is sealed with an old sealer, delete the browser device key and the
 * Keystore keys of generations 1 and 2 (finding j, A-01) — and the fallback of
 * generation 3 once nothing uses it either. Outside the app nothing happens.
 */
async function retireOldSealers(kv: KeyValueStore, userId: string): Promise<void> {
  const n = native();
  if (!n) return;
  const ak = await kv.get<StoredAk>(`ak:${userId}`);
  const trust = await kv.get<Sealed | Bytes>(`trust:${userId}`);
  const byOf = (rec: Sealed | Bytes | undefined) => (!rec ? undefined : rec instanceof Uint8Array ? "web" : (rec.by ?? "web"));
  const kinds = [byOf(ak), byOf(trust)];
  if (!kinds.every((k) => k === undefined || k === "native3" || k === "native3u")) return;
  await kv.delete(`dsk:${userId}`);
  await n.forgetLegacy(userId, !kinds.includes("native3u")).catch(() => undefined);
}

/**
 * How THIS device keeps the person's account key (shown under "Devices and
 * keys", A-01): in the Keystore bound to the unlocked phone, in the Keystore
 * without that binding, or in the browser. Null when the device holds none.
 */
export async function deviceKeyBinding(kv: KeyValueStore, userId: string): Promise<"bound" | "unbound" | "browser" | null> {
  const stored = await kv.get<StoredAk>(`ak:${userId}`);
  if (!stored) return null;
  const by = stored.by ?? "web";
  return by === "web" ? "browser" : by === "native3" ? "bound" : "unbound";
}

async function deviceKey(kv: KeyValueStore, userId: string, create: boolean): Promise<CryptoKey | null> {
  const existing = await kv.get<CryptoKey>(`dsk:${userId}`);
  if (existing) return existing;
  if (!create) return null;
  const dsk = await generateDeviceStorageKey();
  await kv.set(`dsk:${userId}`, dsk);
  return dsk;
}

export async function saveAccountKey(
  kv: KeyValueStore,
  userId: string,
  ak: AccountKey,
  identityId: string,
): Promise<void> {
  const sealed = await sealerFor(kv).seal(userId, serializeAccountKey(ak), akWrapAad("device", userId, identityId));
  await kv.set(`ak:${userId}`, { identityId, ...sealed } satisfies StoredAk);
}

/** The account key on THIS device, or null if the device has none (yet). */
export async function loadAccountKey(
  kv: KeyValueStore,
  userId: string,
): Promise<{ ak: AccountKey; identityId: string } | null> {
  const stored = await kv.get<StoredAk>(`ak:${userId}`);
  if (!stored) return null;
  const by = stored.by ?? "web";
  if (by === "web" && !(await deviceKey(kv, userId, false))) return null;
  const aad = akWrapAad("device", userId, stored.identityId);
  const pt = await sealerFor(kv, by).open(userId, stored.blob, aad);
  const ak = deserializeAccountKey(pt);
  await moveIfOld(kv, userId, by, pt, aad, (moved) =>
    kv.set(`ak:${userId}`, { ...moved, identityId: stored.identityId } satisfies StoredAk),
  );
  return { ak, identityId: stored.identityId };
}

function trustAad(userId: string): Bytes {
  return encodeFields("fm/trust/v1", userId);
}

export async function saveTrustStore(kv: KeyValueStore, userId: string, store: TrustStore): Promise<void> {
  const sealed = await sealerFor(kv).seal(userId, utf8(JSON.stringify(store)), trustAad(userId));
  await kv.set(`trust:${userId}`, sealed satisfies Sealed);
}

export async function loadTrustStore(kv: KeyValueStore, userId: string): Promise<TrustStore> {
  const raw = await kv.get<Sealed | Bytes>(`trust:${userId}`);
  if (!raw) return emptyTrustStore();
  // Records from before Etappe 1e were the bare blob.
  const rec: Sealed = raw instanceof Uint8Array ? { blob: raw, by: "web" } : raw;
  const by = rec.by ?? "web";
  if (by === "web" && !(await deviceKey(kv, userId, false))) return emptyTrustStore();
  const pt = await sealerFor(kv, by).open(userId, rec.blob, trustAad(userId));
  const store = parseTrustStore(fromUtf8(pt));
  await moveIfOld(kv, userId, by, pt, trustAad(userId), (moved) => kv.set(`trust:${userId}`, moved));
  return store;
}

/**
 * Write a changed trust store WITHOUT losing what another tab or flow wrote
 * meanwhile (S-12, security review 17.10.2026): under a Web Lock per person,
 * read the stored state, merge the new one into it, write the result. Only
 * this short read-merge-write is locked — Web Locks are not re-entrant, and
 * the flows around it call each other. Returns the merged store.
 */
export async function mergeIntoTrustStore(kv: KeyValueStore, userId: string, store: TrustStore): Promise<TrustStore> {
  const run = async () => {
    const merged = mergeTrustStores(await loadTrustStore(kv, userId), store);
    await saveTrustStore(kv, userId, merged);
    return merged;
  };
  const locks = typeof navigator !== "undefined" ? navigator.locks : undefined;
  return locks ? locks.request(`fm-e2e-trust-${userId}`, run) : run();
}

/** "Forget this device": removes keys and trust store for that user. */
export async function forgetDevice(kv: KeyValueStore, userId: string): Promise<void> {
  await kv.delete(`ak:${userId}`);
  await kv.delete(`trust:${userId}`);
  await webSealer(kv).forget(userId);
  const n = native();
  if (n) await n.forget(userId).catch(() => undefined);
}

// ---------------------------------------------------------------------------
// Implementations
// ---------------------------------------------------------------------------

export function memoryStore(): KeyValueStore & { dump(): Map<string, unknown> } {
  const m = new Map<string, unknown>();
  return {
    async get<T>(k: string) {
      return m.get(k) as T | undefined;
    },
    async set(k, v) {
      m.set(k, v);
    },
    async delete(k) {
      m.delete(k);
    },
    dump: () => m,
  };
}

const DB_NAME = "fm-e2e";
const STORE = "kv";

/**
 * Browser storage. Also asks for persistent storage so the browser does not
 * evict the device key under pressure (Safari's 7-day rule for non-installed
 * sites still applies — design §14; the passkey is the way back).
 */
export function indexedDbStore(): KeyValueStore {
  let dbp: Promise<IDBDatabase> | null = null;
  const open = () =>
    (dbp ??= new Promise<IDBDatabase>((resolve, reject) => {
      void navigator.storage?.persist?.().catch(() => undefined);
      const req = indexedDB.open(DB_NAME, 1);
      req.onupgradeneeded = () => req.result.createObjectStore(STORE);
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    }));

  async function tx<T>(mode: IDBTransactionMode, run: (s: IDBObjectStore) => IDBRequest<T>): Promise<T> {
    const db = await open();
    return new Promise<T>((resolve, reject) => {
      const t = db.transaction(STORE, mode);
      const req = run(t.objectStore(STORE));
      t.oncomplete = () => resolve(req.result);
      t.onerror = () => reject(t.error);
      t.onabort = () => reject(t.error);
    });
  }

  return {
    get: <T>(k: string) => tx<T | undefined>("readonly", (s) => s.get(k) as IDBRequest<T | undefined>),
    set: async (k, v) => {
      await tx("readwrite", (s) => s.put(v, k));
    },
    delete: async (k) => {
      await tx("readwrite", (s) => s.delete(k));
    },
  };
}
