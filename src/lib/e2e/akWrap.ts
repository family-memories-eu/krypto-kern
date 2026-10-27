// =============================================================================
// Wrapping the account key at rest (docs/e2e-design.md §3, §6). The same
// function serves all three places a private AK is ever stored:
//   * "device"   — IndexedDB, wrap key = non-extractable device storage key
//   * "passkey"  — server `ak_backups`, wrap key = HKDF(WebAuthn PRF output)
//   * "recovery" — server `ak_backups`, wrap key = Argon2id(recovery code)
// The kind and user id are AAD, so a blob wrapped for one purpose or person
// cannot be swapped in for another.
// =============================================================================

import { aesOpen, aesSeal, encodeFields, hkdf, importAesKey, utf8, type Bytes } from "./bytes";
import { deserializeAccountKey, serializeAccountKey, type AccountKey } from "./identity";

export type AkWrapKind = "device" | "passkey" | "recovery";

/** Also used by deviceStore, so web- and Keystore-sealed blobs bind identically. */
export function akWrapAad(kind: AkWrapKind, userId: string, credentialId = ""): Bytes {
  return encodeFields("fm/ak-wrap/v1", kind, userId, credentialId);
}

export async function wrapAccountKey(
  wrapKey: CryptoKey,
  ak: AccountKey,
  kind: AkWrapKind,
  userId: string,
  credentialId = "",
): Promise<Bytes> {
  return aesSeal(wrapKey, serializeAccountKey(ak), akWrapAad(kind, userId, credentialId));
}

export async function unwrapAccountKey(
  wrapKey: CryptoKey,
  blob: Uint8Array,
  kind: AkWrapKind,
  userId: string,
  credentialId = "",
): Promise<AccountKey> {
  return deserializeAccountKey(await aesOpen(wrapKey, blob, akWrapAad(kind, userId, credentialId)));
}

/**
 * Passkey path (design §6.4): the 32-byte WebAuthn PRF output never becomes a
 * key directly; it is stretched with HKDF and bound to the credential id.
 */
export async function passkeyWrapKey(prfOutput: Uint8Array, credentialId: string): Promise<CryptoKey> {
  return importAesKey(
    await hkdf(prfOutput, new Uint8Array(0), encodeFields("fm/passkey/v1", utf8(credentialId))),
  );
}

/** The device storage key: generated once per device, never extractable. */
export async function generateDeviceStorageKey(): Promise<CryptoKey> {
  return globalThis.crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, [
    "encrypt",
    "decrypt",
  ]);
}
