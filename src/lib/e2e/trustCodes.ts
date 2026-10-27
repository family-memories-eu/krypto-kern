// =============================================================================
// Human-comparable codes (docs/e2e-design.md §5.2, §5.5).
//
// Safety code: like Signal, each person has a 30-digit half derived from their
// own identity; the pair's code is both halves sorted and concatenated. A
// person's half therefore stays the same no matter whom they compare with, and
// it only changes when their account key changes.
//
// Pairing code: six digits both devices show during pairing, derived from the
// X25519 shared secret of the two ephemeral keys. If someone relays a
// different key, the two screens disagree.
//
// Commitment (12.10.2026, docs/e2e-pruefung.md AP-Kopplung): with the short
// code both keys travel only through the server. Six digits alone would let
// whoever controls the row try ~10^6 keys of their own until one matches the
// code the old device shows. So the new device first puts down only a HASH of
// its key and nonce, reveals the key after the old device has put down its
// own, and the old device checks the hash: each side is fixed before it sees
// the other, and an attacker gets one guess in a million.
// =============================================================================

import { x25519 } from "@noble/curves/ed25519.js";

import { encodeFields, hkdf, sha256, sha512 } from "./bytes";

/** The new device's commitment to its ephemeral key and nonce (32 bytes). */
export async function pairingCommitment(newDevicePub: Uint8Array, nonce: Uint8Array): Promise<Uint8Array> {
  return sha256(encodeFields("fm/pair-commit/v1", newDevicePub, nonce));
}

function digits5(b: Uint8Array, offset: number): string {
  // 5 bytes = 40 bits; mod 100000 has a negligible bias at this width.
  let n = 0;
  for (let i = 0; i < 5; i++) n = n * 256 + b[offset + i];
  return String(n % 100000).padStart(5, "0");
}

export async function safetyCodeHalf(userId: string, edPk: Uint8Array): Promise<string> {
  const h = await sha512(encodeFields("fm/safety/v1", userId, edPk));
  let s = "";
  for (let i = 0; i < 6; i++) s += digits5(h, i * 5);
  return s;
}

/**
 * A short code for a waiting account key (S-08, „Neu anfangen“): the mail, the
 * waiting device and my other devices all show it, so a second request from
 * someone else does not pass for mine. Ten digits of the key's safety half.
 */
export async function requestCode(userId: string, edPk: Uint8Array): Promise<string> {
  const half = await safetyCodeHalf(userId, edPk);
  return `${half.slice(0, 5)} ${half.slice(5, 10)}`;
}

/** 60 digits, in groups of five for display. */
export async function safetyCode(
  a: { userId: string; edPk: Uint8Array },
  b: { userId: string; edPk: Uint8Array },
): Promise<string[]> {
  const halves = [await safetyCodeHalf(a.userId, a.edPk), await safetyCodeHalf(b.userId, b.edPk)].sort();
  return (halves[0] + halves[1]).match(/.{5}/g)!;
}

export function newEphemeralKeyPair(): { priv: Uint8Array; pub: Uint8Array } {
  const priv = x25519.utils.randomSecretKey();
  return { priv, pub: x25519.getPublicKey(priv) };
}

export async function pairingCode(
  myPriv: Uint8Array,
  theirPub: Uint8Array,
  newDevicePub: Uint8Array,
  oldDevicePub: Uint8Array,
  nonce: Uint8Array,
): Promise<string> {
  const shared = x25519.getSharedSecret(myPriv, theirPub);
  const out = await hkdf(shared, nonce, encodeFields("fm/pair-code/v1", newDevicePub, oldDevicePub), 4);
  const n = new DataView(out.buffer).getUint32(0) % 1_000_000;
  return String(n).padStart(6, "0");
}
