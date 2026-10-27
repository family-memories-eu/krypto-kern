// =============================================================================
// Small images sealed end to end (E2E Etappe 3 · E3.6): a family's cover image
// and logo under the family key, a profile picture under the person's avatar
// key. Whole-blob AES-GCM with an AAD that binds the ciphertext to its scope,
// its storage path and the key version — a file copied to another family,
// another person or another name does not open.
//
// The version is part of the path (`….e2e.v<N>.enc`), so a reader knows which
// key to use without another column, and replacing an image under a new key
// version is a new object rather than an overwrite.
//
// Only `bytes` is imported: this sits on the family page's read path.
// =============================================================================

import { aesOpen, aesSeal, encodeFields, hkdf, importAesKey } from "@/lib/e2e/bytes";

export type MediaScope = "family" | "avatar";

function aad(scope: MediaScope, scopeId: string, path: string, version: number): Uint8Array {
  return encodeFields("fm/media/v1", scope, scopeId, path, version);
}

/** The key version an E2E image path carries, or null for any other path. */
export function e2eMediaVersion(path: string | null | undefined): number | null {
  const m = /\.e2e\.v(\d{1,9})\.enc$/.exec(path ?? "");
  return m ? Number(m[1]) : null;
}

/** `<prefix>/<name>.e2e.v<N>.enc` */
export function e2eMediaPath(prefix: string, name: string, version: number): string {
  return `${prefix}/${name}.e2e.v${version}.enc`;
}

export function sealMedia(
  key: CryptoKey,
  scope: MediaScope,
  scopeId: string,
  path: string,
  version: number,
  plain: Uint8Array,
): Promise<Uint8Array> {
  return aesSeal(key, plain, aad(scope, scopeId, path, version));
}

/** Throws when the key, the scope or the path do not match. */
export function openMedia(
  key: CryptoKey,
  scope: MediaScope,
  scopeId: string,
  path: string,
  version: number,
  blob: Uint8Array,
): Promise<Uint8Array> {
  return aesOpen(key, blob, aad(scope, scopeId, path, version));
}

// ---------------------------------------------------------------------------
// Format v2 (AP-Zeilen v2, key separation): sealed with HKDF(FMK_v / PAK_v,
// "fm/media-seal/v2") instead of the raw scope key, AAD "fm/media/v2". The
// file name carries ".s2" before ".e2e.v<N>.enc", so every check for "is this
// an E2E path, which version" (e2eMediaVersion) stays as it is, and a reader
// picks the key from the path it loads.
// ---------------------------------------------------------------------------

/** True for a path sealed in format v2 (`….s2.e2e.v<N>.enc`). */
export function isMediaSealV2(path: string | null | undefined): boolean {
  return /\.s2\.e2e\.v\d{1,9}\.enc$/.test(path ?? "");
}

/** `<prefix>/<name>.s2.e2e.v<N>.enc` */
export function e2eMediaPathV2(prefix: string, name: string, version: number): string {
  return `${prefix}/${name}.s2.e2e.v${version}.enc`;
}

/** The v2 media-seal key of one scope version. Derived while the raw key is at hand. */
export async function mediaSealKeyV2(rawScopeKey: Uint8Array): Promise<CryptoKey> {
  return importAesKey(await hkdf(rawScopeKey, new Uint8Array(0), encodeFields("fm/media-seal/v2")));
}

function aadV2(scope: MediaScope, scopeId: string, path: string, version: number): Uint8Array {
  return encodeFields("fm/media/v2", scope, scopeId, path, version);
}

export function sealMediaV2(
  key: CryptoKey,
  scope: MediaScope,
  scopeId: string,
  path: string,
  version: number,
  plain: Uint8Array,
): Promise<Uint8Array> {
  if (!isMediaSealV2(path)) throw new Error("sealMediaV2: path must carry .s2");
  return aesSeal(key, plain, aadV2(scope, scopeId, path, version));
}

/** Throws when the key, the scope or the path do not match. */
export function openMediaV2(
  key: CryptoKey,
  scope: MediaScope,
  scopeId: string,
  path: string,
  version: number,
  blob: Uint8Array,
): Promise<Uint8Array> {
  return aesOpen(key, blob, aadV2(scope, scopeId, path, version));
}

/**
 * Seal an image for upload under a fresh path: format v2 (`.s2`, the
 * media-seal key) when `keys.v2` is given — the writer is on v2 — else v1
 * with the raw scope key.
 */
export async function sealImage(
  keys: { v1: CryptoKey; v2?: CryptoKey | null },
  scope: MediaScope,
  scopeId: string,
  prefix: string,
  name: string,
  version: number,
  plain: Uint8Array,
): Promise<{ path: string; sealed: Uint8Array }> {
  if (keys.v2) {
    const path = e2eMediaPathV2(prefix, name, version);
    return { path, sealed: await sealMediaV2(keys.v2, scope, scopeId, path, version, plain) };
  }
  const path = e2eMediaPath(prefix, name, version);
  return { path, sealed: await sealMedia(keys.v1, scope, scopeId, path, version, plain) };
}
