import { describe, expect, it } from "vitest";

import { decryptBlob, encryptBlob } from "@/lib/crypto";
import { decryptVideoChunked, encryptVideoChunked } from "@/lib/videoCrypto";

import { generateContentKey } from "./envelope";
import { mediaBaseKey, objectKey, type ObjectRef } from "./objectKey";

// =============================================================================
// E5.1: one key per media object, derived from the family/story key version,
// its path and its row. The point is the binding — an object moved to another
// path, row, family, version or scope does not open — while the containers
// (whole blob, FMV2 video) stay exactly as they are.
// =============================================================================

const F = "11111111-1111-4111-8111-111111111111";
const PHOTO = "22222222-2222-4222-8222-222222222222";
const REF: ObjectRef = { scope: "family", scopeId: F, path: `${F}/abc_full.e2e.v3.enc`, version: 3, rowId: PHOTO };
const JPEG = new Blob([new Uint8Array([0xff, 0xd8, 0xff, 1, 2, 3])], { type: "image/jpeg" });

async function sealed(ref = REF) {
  const base = await mediaBaseKey(generateContentKey());
  const cipher = await encryptBlob(await objectKey(base, ref), JPEG);
  return { base, cipher };
}

const opens = async (base: CryptoKey, ref: ObjectRef, cipher: Blob) =>
  decryptBlob(await objectKey(base, ref), cipher, "image/jpeg").then(
    () => true,
    () => false,
  );

describe("objectKey", () => {
  it("the same object opens again — the whole-blob format is unchanged", async () => {
    const { base, cipher } = await sealed();
    const clear = await decryptBlob(await objectKey(base, REF), cipher, "image/jpeg");
    expect(new Uint8Array(await clear.arrayBuffer())).toEqual(new Uint8Array(await JPEG.arrayBuffer()));
  });

  it("does not open under another path, row, version, family or scope", async () => {
    const { base, cipher } = await sealed();
    expect(await opens(base, { ...REF, path: `${F}/other_full.e2e.v3.enc` }, cipher)).toBe(false);
    expect(await opens(base, { ...REF, rowId: "33333333-3333-4333-8333-333333333333" }, cipher)).toBe(false);
    expect(await opens(base, { ...REF, version: 4 }, cipher)).toBe(false);
    expect(await opens(base, { ...REF, scopeId: "44444444-4444-4444-8444-444444444444" }, cipher)).toBe(false);
    expect(await opens(base, { ...REF, scope: "story" }, cipher)).toBe(false);
  });

  it("does not open under another family key", async () => {
    const { cipher } = await sealed();
    const other = await mediaBaseKey(generateContentKey());
    expect(await opens(other, REF, cipher)).toBe(false);
  });

  it("FMV2 video chunks work unchanged with an object key", async () => {
    const base = await mediaBaseKey(generateContentKey());
    const ref = { ...REF, path: `${F}/abc_video.e2e.v3.enc` };
    const video = new Blob([new Uint8Array(3000).fill(7)], { type: "video/mp4" });
    const cipher = await encryptVideoChunked(await objectKey(base, ref), video);
    const clear = await decryptVideoChunked(await objectKey(base, ref), cipher);
    expect(clear.size).toBe(3000);
    await expect(decryptVideoChunked(await objectKey(base, { ...ref, rowId: "x" }), cipher)).rejects.toThrow();
  });

  it("neither the base key nor an object key can be read back", async () => {
    const base = await mediaBaseKey(generateContentKey());
    expect(base.extractable).toBe(false);
    expect(base.usages).toEqual(["deriveKey"]);
    const k = await objectKey(base, REF);
    expect(k.extractable).toBe(false);
    await expect(globalThis.crypto.subtle.exportKey("raw", k)).rejects.toThrow();
  });
});
