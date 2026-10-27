// =============================================================================
// Bridge to the native DeviceKey plugin (android/…/DeviceKeyPlugin.java): the
// E2E device storage key inside the Android Keystore. Like capacitor.ts, no
// npm package — in a browser `window.Capacitor` is absent and this returns null.
//
// Generations of Keystore key: 1 (apps up to 1.0.8, no unlock binding) and 2
// (AP-Android, 14.10.2026, bound — or silently not, A-01) are only opened, to
// move their records over, and then forgotten. `seal` uses generation 3 (P6):
// bound to the unlocked phone (setUnlockedDeviceRequired), and when the phone
// cannot give that, a fallback under its own alias — `bound` says which.
// =============================================================================

export type KeystoreGen = 1 | 2 | 3;

export type NativeDeviceKey = {
  seal(userId: string, data: Uint8Array, aad: Uint8Array): Promise<{ blob: Uint8Array<ArrayBuffer>; bound: boolean }>;
  /** `bound` only matters for generation 3 (which of its two keys). */
  open(userId: string, blob: Uint8Array, aad: Uint8Array, gen: KeystoreGen, bound?: boolean): Promise<Uint8Array<ArrayBuffer>>;
  /** Every generation. */
  forget(userId: string): Promise<void>;
  /** Generations 1 and 2 — and the unbound key of 3 with `unboundToo` — once nothing is sealed with them. */
  forgetLegacy(userId: string, unboundToo: boolean): Promise<void>;
};

type Plugin = {
  seal(o: { userId: string; data: string; aad: string }): Promise<{ blob: string; bound?: boolean }>;
  open(o: { userId: string; blob: string; aad: string; gen: KeystoreGen; bound: boolean }): Promise<{ data: string }>;
  forget(o: { userId: string; legacyOnly?: boolean; unboundToo?: boolean }): Promise<void>;
};

const toB64 = (b: Uint8Array) => {
  let s = "";
  for (let i = 0; i < b.byteLength; i++) s += String.fromCharCode(b[i]);
  return btoa(s);
};
const fromB64 = (s: string) => {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
};

export function nativeDeviceKey(): NativeDeviceKey | null {
  if (typeof window === "undefined") return null;
  const cap = (window as unknown as {
    Capacitor?: { isNativePlatform?: () => boolean; Plugins?: { DeviceKey?: Plugin } };
  }).Capacitor;
  const p = cap?.isNativePlatform?.() ? cap.Plugins?.DeviceKey : undefined;
  if (!p) return null;
  return {
    async seal(userId, data, aad) {
      const r = await p.seal({ userId, data: toB64(data), aad: toB64(aad) });
      return { blob: fromB64(r.blob), bound: r.bound === true };
    },
    async open(userId, blob, aad, gen, bound = true) {
      return fromB64((await p.open({ userId, blob: toB64(blob), aad: toB64(aad), gen, bound })).data);
    },
    async forget(userId) {
      await p.forget({ userId });
    },
    async forgetLegacy(userId, unboundToo) {
      await p.forget({ userId, legacyOnly: true, unboundToo });
    },
  };
}
