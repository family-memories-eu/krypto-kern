import { describe, expect, it } from "vitest";

import { E2eError, toB64url } from "./bytes";
import { afterEach } from "vitest";

import type { NativeDeviceKey } from "@/lib/native/deviceKey";

import { aesOpen, aesSeal } from "./bytes";
import {
  deviceKeyBinding,
  forgetDevice,
  loadAccountKey,
  loadTrustStore,
  memoryStore,
  overrideNativeDeviceKeyForTests,
  saveAccountKey,
  saveTrustStore,
} from "./deviceStore";
import { fingerprint, generateAccountKey, publicPart, selfSign, type AccountKey } from "./identity";
import {
  acceptChange,
  emptyTrustStore,
  markVerified,
  observe,
  pendingChanges,
  trustedKey,
  type ObservedKey,
} from "./trustStore";

// =============================================================================
// Device storage + trust store (docs/e2e-design.md §5.4). The trust store is
// where a malicious server would try to swap a key, so the cases centre on:
// a changed key is never adopted silently and never used to verify anything.
// =============================================================================

const OMA = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const ENKEL = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";

function observed(userId: string, ak: AccountKey, identityId = "id-1"): ObservedKey {
  return { userId, identityId, pub: publicPart(ak), selfSig: selfSign(ak, userId) };
}

describe("trust store", () => {
  it("trusts on first use, then recognises the same key", async () => {
    const ak = generateAccountKey();
    const a = await observe(emptyTrustStore(), observed(OMA, ak));
    expect(a.status).toBe("new");
    const b = await observe(a.store, observed(OMA, ak));
    expect(b.status).toBe("known");
    expect(toB64url(trustedKey(b.store, OMA)!.edPk)).toBe(toB64url(ak.edPk));
  });

  it("rejects a key whose self-signature does not match the person", async () => {
    const ak = generateAccountKey();
    const forged = { ...observed(OMA, ak), selfSig: selfSign(ak, ENKEL) };
    const r = await observe(emptyTrustStore(), forged);
    expect(r.status).toBe("invalid");
    expect(trustedKey(r.store, OMA)).toBeNull();
  });

  it("A3: a different key for a known person is parked, never used", async () => {
    const real = generateAccountKey();
    const swapped = generateAccountKey();
    const { store } = await observe(emptyTrustStore(), observed(OMA, real));
    const r = await observe(store, observed(OMA, swapped, "id-2"));
    expect(r.status).toBe("changed");
    // Verification keeps using the key we already trusted.
    expect(toB64url(trustedKey(r.store, OMA)!.edPk)).toBe(toB64url(real.edPk));
    expect(pendingChanges(r.store)).toEqual([OMA]);
    // Seeing it again does not make it more trusted.
    expect((await observe(r.store, observed(OMA, swapped, "id-2"))).status).toBe("changed");
  });

  it("adopts a changed key only when a human confirms exactly that key", async () => {
    const real = generateAccountKey();
    const rescue = generateAccountKey();
    let { store } = await observe(emptyTrustStore(), observed(OMA, real));
    store = markVerified(store, OMA, await fingerprint(publicPart(real)));
    store = (await observe(store, observed(OMA, rescue, "id-2"))).store;

    expect(() => acceptChange(store, OMA, "wrong-fingerprint")).toThrow();
    const accepted = acceptChange(store, OMA, await fingerprint(publicPart(rescue)));
    const e = accepted.entries[OMA];
    expect(toB64url(trustedKey(accepted, OMA)!.edPk)).toBe(toB64url(rescue.edPk));
    expect(e.identityId).toBe("id-2");
    expect(e.verified).toBe(false); // a new key starts unverified
    expect(e.previous).toEqual([await fingerprint(publicPart(real))]);
    expect(pendingChanges(accepted)).toEqual([]);
  });

  it("drops a pending change when the server goes back to the trusted key", async () => {
    const real = generateAccountKey();
    let { store } = await observe(emptyTrustStore(), observed(OMA, real));
    store = (await observe(store, observed(OMA, generateAccountKey(), "id-2"))).store;
    const back = await observe(store, observed(OMA, real));
    expect(back.status).toBe("known");
    expect(pendingChanges(back.store)).toEqual([]);
  });

  it("marking verified requires the fingerprint on screen to match", async () => {
    const ak = generateAccountKey();
    const { store } = await observe(emptyTrustStore(), observed(OMA, ak));
    expect(() => markVerified(store, OMA, "not-it")).toThrow();
    expect(markVerified(store, OMA, await fingerprint(publicPart(ak))).entries[OMA].verified).toBe(true);
  });
});

describe("device store", () => {
  it("keeps the account key wrapped under a non-extractable device key", async () => {
    const kv = memoryStore();
    const ak = generateAccountKey();
    await saveAccountKey(kv, OMA, ak, "id-1");
    const back = await loadAccountKey(kv, OMA);
    expect(back?.identityId).toBe("id-1");
    expect(await fingerprint(publicPart(back!.ak))).toBe(await fingerprint(publicPart(ak)));

    const dsk = kv.dump().get(`dsk:${OMA}`) as CryptoKey;
    expect(dsk.extractable).toBe(false);
    await expect(globalThis.crypto.subtle.exportKey("raw", dsk)).rejects.toThrow();
    // Nothing in storage is the raw key material.
    const stored = kv.dump().get(`ak:${OMA}`) as { blob: Uint8Array };
    expect(toB64url(stored.blob)).not.toContain(toB64url(ak.edSk).slice(0, 16));
  });

  it("returns null on a device without a key, and after forgetting", async () => {
    const kv = memoryStore();
    expect(await loadAccountKey(kv, OMA)).toBeNull();
    await saveAccountKey(kv, OMA, generateAccountKey(), "id-1");
    await forgetDevice(kv, OMA);
    expect(await loadAccountKey(kv, OMA)).toBeNull();
    expect(kv.dump().size).toBe(0);
  });

  it("separates users on the same device", async () => {
    const kv = memoryStore();
    await saveAccountKey(kv, OMA, generateAccountKey(), "id-1");
    expect(await loadAccountKey(kv, ENKEL)).toBeNull();
    // Oma's blob under Enkel's name does not open.
    await saveAccountKey(kv, ENKEL, generateAccountKey(), "id-2");
    kv.dump().set(`ak:${ENKEL}`, kv.dump().get(`ak:${OMA}`));
    await expect(loadAccountKey(kv, ENKEL)).rejects.toBeInstanceOf(E2eError);
  });

  it("persists the trust store encrypted and detects tampering", async () => {
    const kv = memoryStore();
    const { store } = await observe(emptyTrustStore(), observed(ENKEL, generateAccountKey()));
    await saveTrustStore(kv, OMA, store);
    expect(await loadTrustStore(kv, OMA)).toEqual(store);
    const { blob, by } = kv.dump().get(`trust:${OMA}`) as { blob: Uint8Array; by: string };
    expect(by).toBe("web");
    expect(new TextDecoder().decode(blob)).not.toContain(ENKEL);
    blob[blob.length - 1] ^= 1;
    await expect(loadTrustStore(kv, OMA)).rejects.toBeInstanceOf(E2eError);
  });

  it("an empty device starts with an empty trust store", async () => {
    expect(await loadTrustStore(memoryStore(), OMA)).toEqual(emptyTrustStore());
  });
});

// A stand-in for the Android Keystore: non-extractable keys per user and
// generation that live OUTSIDE the key-value store (as on a phone, outside
// IndexedDB). `seal` uses generation 3 like the plugin — bound ("3"), or the
// fallback ("3u") while `binding` is false; `sealGen` lets a test plant a
// record from an older app (1: up to 1.0.8, 2: up to 1.0.16).
function fakeKeystore(opts: { brokenOpen?: boolean; binding?: boolean } = {}): NativeDeviceKey & {
  keys: Map<string, CryptoKey>;
  forgotten: string[];
  binding: boolean;
  sealGen(gen: 1 | 2, u: string, d: Uint8Array, a: Uint8Array): Promise<Uint8Array<ArrayBuffer>>;
} {
  const keys = new Map<string, CryptoKey>();
  const forgotten: string[] = [];
  const key = async (id: string) => {
    if (!keys.has(id)) {
      keys.set(id, await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]));
    }
    return keys.get(id)!;
  };
  const ks = {
    keys,
    forgotten,
    binding: opts.binding ?? true,
    async seal(u: string, d: Uint8Array, a: Uint8Array) {
      // Like sealingKey(): an existing bound key wins; otherwise bind if the phone can.
      const bound = keys.has(`3:${u}`) || ks.binding;
      return { blob: await aesSeal(await key(bound ? `3:${u}` : `3u:${u}`), d, a), bound };
    },
    sealGen: async (gen: 1 | 2, u: string, d: Uint8Array, a: Uint8Array) => aesSeal(await key(`${gen}:${u}`), d, a),
    async open(u: string, b: Uint8Array, a: Uint8Array, gen: 1 | 2 | 3, bound = true) {
      if (opts.brokenOpen && gen === 3) throw new Error("open-failed");
      const k = keys.get(gen === 3 && !bound ? `3u:${u}` : `${gen}:${u}`);
      if (!k) throw new Error("no-key");
      return aesOpen(k, b, a);
    },
    async forget(u: string) {
      for (const g of ["1", "2", "3", "3u"]) keys.delete(`${g}:${u}`);
      forgotten.push(u);
    },
    async forgetLegacy(u: string, unboundToo: boolean) {
      keys.delete(`1:${u}`);
      keys.delete(`2:${u}`);
      if (unboundToo) keys.delete(`3u:${u}`);
      forgotten.push(`legacy:${u}${unboundToo ? "+3u" : ""}`);
    },
  };
  return ks;
}

const byOf = (kv: ReturnType<typeof memoryStore>, k: string) => (kv.dump().get(k) as { by: string }).by;

describe("device store inside the Android app (Keystore)", () => {
  afterEach(() => overrideNativeDeviceKeyForTests(undefined));

  it("seals with the Keystore (generation 3, bound) and keeps no device key in the web store", async () => {
    const ks = fakeKeystore();
    overrideNativeDeviceKeyForTests(ks);
    const kv = memoryStore();
    const ak = generateAccountKey();
    await saveAccountKey(kv, OMA, ak, "id-1");
    expect(byOf(kv, `ak:${OMA}`)).toBe("native3");
    expect(kv.dump().has(`dsk:${OMA}`)).toBe(false);
    expect(await fingerprint(publicPart((await loadAccountKey(kv, OMA))!.ak))).toBe(await fingerprint(publicPart(ak)));
  });

  it("a copy of the app's storage is useless without the phone's Keystore", async () => {
    const kv = memoryStore();
    overrideNativeDeviceKeyForTests(fakeKeystore());
    await saveAccountKey(kv, OMA, generateAccountKey(), "id-1");
    overrideNativeDeviceKeyForTests(fakeKeystore()); // another phone, same files
    await expect(loadAccountKey(kv, OMA)).rejects.toBeInstanceOf(E2eError);
    overrideNativeDeviceKeyForTests(null); // or a browser
    await expect(loadAccountKey(kv, OMA)).rejects.toBeInstanceOf(E2eError);
  });

  it("moves browser-sealed records into the Keystore and then deletes the browser key", async () => {
    const kv = memoryStore();
    overrideNativeDeviceKeyForTests(null);
    const ak = generateAccountKey();
    await saveAccountKey(kv, OMA, ak, "id-1");
    const { store } = await observe(emptyTrustStore(), observed(ENKEL, generateAccountKey()));
    await saveTrustStore(kv, OMA, store);

    overrideNativeDeviceKeyForTests(fakeKeystore());
    expect(await fingerprint(publicPart((await loadAccountKey(kv, OMA))!.ak))).toBe(await fingerprint(publicPart(ak)));
    expect(byOf(kv, `ak:${OMA}`)).toBe("native3");
    // The trust store is still sealed by the browser key: it stays until that moved too.
    expect(kv.dump().has(`dsk:${OMA}`)).toBe(true);
    expect(await loadTrustStore(kv, OMA)).toEqual(store);
    expect(byOf(kv, `trust:${OMA}`)).toBe("native3");
    expect(kv.dump().has(`dsk:${OMA}`)).toBe(false);
    // Everything still opens afterwards.
    expect(await loadTrustStore(kv, OMA)).toEqual(store);
    expect(await fingerprint(publicPart((await loadAccountKey(kv, OMA))!.ak))).toBe(await fingerprint(publicPart(ak)));
  });

  it("moves generation-1 Keystore records to generation 3 and forgets the old key", async () => {
    const ks = fakeKeystore();
    overrideNativeDeviceKeyForTests(ks);
    const kv = memoryStore();
    const ak = generateAccountKey();
    const { store } = await observe(emptyTrustStore(), observed(ENKEL, generateAccountKey()));
    // What an app up to 1.0.8 left behind.
    const { serializeAccountKey } = await import("./identity");
    const { akWrapAad } = await import("./akWrap");
    const { encodeFields, utf8 } = await import("./bytes");
    await kv.set(`ak:${OMA}`, { identityId: "id-1", by: "native", blob: await ks.sealGen(1, OMA, serializeAccountKey(ak), akWrapAad("device", OMA, "id-1")) });
    await kv.set(`trust:${OMA}`, { by: "native", blob: await ks.sealGen(1, OMA, utf8(JSON.stringify(store)), encodeFields("fm/trust/v1", OMA)) });

    expect(await fingerprint(publicPart((await loadAccountKey(kv, OMA))!.ak))).toBe(await fingerprint(publicPart(ak)));
    expect(ks.keys.has(`1:${OMA}`)).toBe(true); // the trust store still needs it
    expect(await loadTrustStore(kv, OMA)).toEqual(store);
    expect(byOf(kv, `ak:${OMA}`)).toBe("native3");
    expect(byOf(kv, `trust:${OMA}`)).toBe("native3");
    expect(ks.keys.has(`1:${OMA}`)).toBe(false);
    expect(ks.forgotten).toContain(`legacy:${OMA}+3u`);
    expect(await fingerprint(publicPart((await loadAccountKey(kv, OMA))!.ak))).toBe(await fingerprint(publicPart(ak)));
  });

  // A-01: a generation-2 key may be unbound without anyone knowing — so its
  // records move to generation 3, where the binding is certain.
  it("moves generation-2 records to the bound key of generation 3 and forgets generation 2", async () => {
    const ks = fakeKeystore();
    overrideNativeDeviceKeyForTests(ks);
    const kv = memoryStore();
    const ak = generateAccountKey();
    const { serializeAccountKey } = await import("./identity");
    const { akWrapAad } = await import("./akWrap");
    await kv.set(`ak:${OMA}`, { identityId: "id-1", by: "native2", blob: await ks.sealGen(2, OMA, serializeAccountKey(ak), akWrapAad("device", OMA, "id-1")) });

    expect(await fingerprint(publicPart((await loadAccountKey(kv, OMA))!.ak))).toBe(await fingerprint(publicPart(ak)));
    expect(byOf(kv, `ak:${OMA}`)).toBe("native3");
    expect(ks.keys.has(`2:${OMA}`)).toBe(false);
    expect(await deviceKeyBinding(kv, OMA)).toBe("bound");
  });

  it("a phone without the binding seals with the fallback, says so, and keeps that record as it is", async () => {
    const ks = fakeKeystore({ binding: false });
    overrideNativeDeviceKeyForTests(ks);
    const kv = memoryStore();
    const ak = generateAccountKey();
    await saveAccountKey(kv, OMA, ak, "id-1");
    expect(byOf(kv, `ak:${OMA}`)).toBe("native3u");
    expect(await deviceKeyBinding(kv, OMA)).toBe("unbound");
    const before = kv.dump().get(`ak:${OMA}`);
    // Still no binding: loading changes nothing (no rewrite on every start).
    expect(await fingerprint(publicPart((await loadAccountKey(kv, OMA))!.ak))).toBe(await fingerprint(publicPart(ak)));
    expect(kv.dump().get(`ak:${OMA}`)).toBe(before);
    expect(ks.keys.has(`3u:${OMA}`)).toBe(true);
  });

  it("a fallback record moves to the bound key once the phone gives it, and the fallback key goes", async () => {
    const ks = fakeKeystore({ binding: false });
    overrideNativeDeviceKeyForTests(ks);
    const kv = memoryStore();
    const ak = generateAccountKey();
    await saveAccountKey(kv, OMA, ak, "id-1");
    const { store } = await observe(emptyTrustStore(), observed(ENKEL, generateAccountKey()));
    await saveTrustStore(kv, OMA, store);

    ks.binding = true; // e.g. the Keystore error was passing
    await loadAccountKey(kv, OMA);
    expect(byOf(kv, `ak:${OMA}`)).toBe("native3");
    expect(ks.keys.has(`3u:${OMA}`)).toBe(true); // the trust store still needs it
    expect(await loadTrustStore(kv, OMA)).toEqual(store);
    expect(byOf(kv, `trust:${OMA}`)).toBe("native3");
    expect(ks.keys.has(`3u:${OMA}`)).toBe(false);
    expect(await fingerprint(publicPart((await loadAccountKey(kv, OMA))!.ak))).toBe(await fingerprint(publicPart(ak)));
  });

  it("a Keystore that seals but will not open keeps the old record (no lock-out)", async () => {
    const kv = memoryStore();
    overrideNativeDeviceKeyForTests(null);
    const ak = generateAccountKey();
    await saveAccountKey(kv, OMA, ak, "id-1");
    const before = kv.dump().get(`ak:${OMA}`);

    overrideNativeDeviceKeyForTests(fakeKeystore({ brokenOpen: true }));
    // The key still opens (from the old record); the move simply did not happen.
    expect(await fingerprint(publicPart((await loadAccountKey(kv, OMA))!.ak))).toBe(await fingerprint(publicPart(ak)));
    expect(kv.dump().get(`ak:${OMA}`)).toBe(before);
    expect(kv.dump().has(`dsk:${OMA}`)).toBe(true);
    overrideNativeDeviceKeyForTests(null); // the browser key still opens it
    expect(await fingerprint(publicPart((await loadAccountKey(kv, OMA))!.ak))).toBe(await fingerprint(publicPart(ak)));
  });

  it("forgetting the device also deletes the Keystore keys", async () => {
    const ks = fakeKeystore();
    overrideNativeDeviceKeyForTests(ks);
    const kv = memoryStore();
    await saveAccountKey(kv, OMA, generateAccountKey(), "id-1");
    await forgetDevice(kv, OMA);
    expect(ks.forgotten).toEqual([OMA]);
    expect(ks.keys.size).toBe(0);
    expect(await loadAccountKey(kv, OMA)).toBeNull();
  });
});
