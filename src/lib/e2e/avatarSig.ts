// =============================================================================
// Signed profile pictures (interne Prüfung K-03, P1 Teil C · Entscheidung Alex
// 18.10.2026: eigene Signatur). A picture has no signed row: the path sits in
// `profiles.avatar_url`, the server's to change, and everyone who holds the
// person's avatar key (a former family member, say) could seal another picture
// that opens. So the person signs the stored object itself:
//
//   "FMAV" ‖ u8 1 ‖ identity id (36 ASCII) ‖ u64 signedAt (ms) ‖ Ed25519 sig (64) ‖ sealed picture
//
//   sig = Sign(AK_ed, "fm/avatar/v1" ‖ user ‖ identity ‖ path ‖ signedAt ‖ SHA-256(sealed))
//
// The signature lives in the object, not in a column: no schema change, and
// every screen that already reads avatar_url keeps reading it. Readers check
// it against the key their trust store holds for that person (rowVerify's
// signer book), refuse an older signedAt than one they have shown (no rolling
// back to an earlier picture the server kept), and — once they have shown a
// signed picture of someone — refuse that person's unsigned ones.
// =============================================================================

import { concat, fromUtf8, sha256, utf8 } from "./bytes";
import { sign, verify } from "./identity";

const MAGIC = [0x46, 0x4d, 0x41, 0x56]; // "FMAV"
const VERSION = 1;
const ID_LEN = 36;
const SIG_LEN = 64;
const HEAD_LEN = 4 + 1 + ID_LEN + 8 + SIG_LEN;
export const CTX_AVATAR = "fm/avatar/v1";

export type SignedAvatar = { identityId: string; signedAt: number; sig: Uint8Array; sealed: Uint8Array };

/** signedAt as signed: 8 bytes big-endian (encodeFields numbers are only u32). */
function at64(ms: number): Uint8Array {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, BigInt(ms), false);
  return b;
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/** Wrap a sealed picture with the owner's signature over user, identity, path and time. */
export async function signAvatar(
  sealed: Uint8Array,
  a: { userId: string; identityId: string; path: string; signedAt: number; edSk: Uint8Array },
): Promise<Uint8Array<ArrayBuffer>> {
  if (!UUID.test(a.identityId) || !Number.isSafeInteger(a.signedAt) || a.signedAt < 0) throw new Error("avatar-sig");
  const sig = sign(a.edSk, CTX_AVATAR, a.userId, a.identityId, a.path, at64(a.signedAt), await sha256(sealed));
  const head = new Uint8Array(HEAD_LEN - SIG_LEN);
  head.set(MAGIC, 0);
  head[4] = VERSION;
  head.set(utf8(a.identityId), 5);
  head.set(at64(a.signedAt), 5 + ID_LEN);
  return concat(head, sig, sealed);
}

/**
 * The parts of a signed picture; null for an unsigned (older) one; "bad" for
 * an object that claims to be signed but is malformed.
 */
export function parseSignedAvatar(bytes: Uint8Array): SignedAvatar | null | "bad" {
  if (bytes.length < 4 || MAGIC.some((b, i) => bytes[i] !== b)) return null;
  if (bytes.length <= HEAD_LEN || bytes[4] !== VERSION) return "bad";
  const identityId = fromUtf8(bytes.subarray(5, 5 + ID_LEN));
  if (!UUID.test(identityId)) return "bad";
  const at = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getBigUint64(5 + ID_LEN, false);
  if (at > BigInt(Number.MAX_SAFE_INTEGER)) return "bad";
  return {
    identityId,
    signedAt: Number(at),
    sig: bytes.slice(HEAD_LEN - SIG_LEN, HEAD_LEN),
    sealed: bytes.slice(HEAD_LEN),
  };
}

/** Does `s` carry `userId`'s signature (key `edPk`) for the picture at `path`? */
export async function verifyAvatar(edPk: Uint8Array, s: SignedAvatar, userId: string, path: string): Promise<boolean> {
  return verify(edPk, s.sig, CTX_AVATAR, userId, s.identityId, path, at64(s.signedAt), await sha256(s.sealed));
}

/**
 * The reader's rule, pure: the sealed picture to open, or null when refused.
 *   unsigned            → only while this device has never shown a signed picture of `ownerId` (lastSeen absent);
 *   signed              → by `ownerId` as the signer book knows them, over this path, not older than lastSeen.
 * `signedAt` is what the caller remembers as shown.
 */
export async function checkAvatar(a: {
  bytes: Uint8Array;
  ownerId: string;
  path: string;
  lastSeen: number | undefined;
  signer: (identityId: string) => Promise<{ userId: string; edPk: Uint8Array } | null>;
}): Promise<{ sealed: Uint8Array; signedAt?: number } | null> {
  const s = parseSignedAvatar(a.bytes);
  if (s === "bad") return null;
  if (s === null) return a.lastSeen === undefined ? { sealed: a.bytes } : null;
  const who = await a.signer(s.identityId).catch(() => null);
  if (!who || who.userId !== a.ownerId) return null;
  if (!(await verifyAvatar(who.edPk, s, a.ownerId, a.path))) return null;
  if (a.lastSeen !== undefined && s.signedAt < a.lastSeen) return null;
  return { sealed: s.sealed, signedAt: s.signedAt };
}
