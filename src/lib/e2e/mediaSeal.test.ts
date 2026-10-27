import { describe, expect, it } from "vitest";

import { importAesKey, randomBytes } from "@/lib/e2e/bytes";
import {
  e2eMediaPath,
  e2eMediaPathV2,
  e2eMediaVersion,
  isMediaSealV2,
  mediaSealKeyV2,
  openMedia,
  openMediaV2,
  sealImage,
  sealMedia,
  sealMediaV2,
} from "@/lib/e2e/mediaSeal";

// E3.6: a sealed image opens only as what it was sealed as — the same scope,
// the same owner, the same path, the same key version.

const FAM = "a0000000-0000-4000-8000-000000000001";

describe("mediaSeal", () => {
  it("round trip, and every binding refuses to open elsewhere", async () => {
    const key = await importAesKey(randomBytes(32));
    const path = e2eMediaPath(`${FAM}/branding`, "cover.ab12cd34", 3);
    expect(path).toBe(`${FAM}/branding/cover.ab12cd34.e2e.v3.enc`);
    expect(e2eMediaVersion(path)).toBe(3);

    const plain = randomBytes(500);
    const sealed = await sealMedia(key, "family", FAM, path, 3, plain);
    expect(await openMedia(key, "family", FAM, path, 3, sealed)).toEqual(plain);

    await expect(openMedia(key, "avatar", FAM, path, 3, sealed)).rejects.toThrow();
    await expect(openMedia(key, "family", "other-family", path, 3, sealed)).rejects.toThrow();
    await expect(openMedia(key, "family", FAM, path.replace("cover", "logo"), 3, sealed)).rejects.toThrow();
    await expect(openMedia(key, "family", FAM, path, 4, sealed)).rejects.toThrow();
    await expect(openMedia(await importAesKey(randomBytes(32)), "family", FAM, path, 3, sealed)).rejects.toThrow();
  });

  it("reads the version only from an E2E path", () => {
    expect(e2eMediaVersion("x/branding/cover.jpg")).toBeNull();
    expect(e2eMediaVersion("u/avatar.enc")).toBeNull();
    expect(e2eMediaVersion(null)).toBeNull();
    expect(e2eMediaVersion("u/avatar.e2e.v12.enc")).toBe(12);
  });
});

// AP-Zeilen v2 (1g): cover, logo and avatar in format v2 are sealed with
// HKDF(scope key, "fm/media-seal/v2") — never with the raw key — and the
// path says which format a reader has to open.
describe("mediaSeal v2", () => {
  it("round trip with the derived key, and every binding refuses to open elsewhere", async () => {
    const raw = randomBytes(32);
    const key = await mediaSealKeyV2(raw);
    const path = e2eMediaPathV2(`${FAM}/branding`, "cover.ab12cd34", 3);
    expect(path).toBe(`${FAM}/branding/cover.ab12cd34.s2.e2e.v3.enc`);
    expect(e2eMediaVersion(path)).toBe(3);

    const plain = randomBytes(500);
    const sealed = await sealMediaV2(key, "family", FAM, path, 3, plain);
    expect(await openMediaV2(key, "family", FAM, path, 3, sealed)).toEqual(plain);
    // The same raw bytes derive the same key (a second device opens it).
    expect(await openMediaV2(await mediaSealKeyV2(raw), "family", FAM, path, 3, sealed)).toEqual(plain);

    await expect(openMediaV2(key, "avatar", FAM, path, 3, sealed)).rejects.toThrow();
    await expect(openMediaV2(key, "family", "other-family", path, 3, sealed)).rejects.toThrow();
    await expect(openMediaV2(key, "family", FAM, path.replace("cover", "logo"), 3, sealed)).rejects.toThrow();
    await expect(openMediaV2(key, "family", FAM, path, 4, sealed)).rejects.toThrow();
    await expect(openMediaV2(await mediaSealKeyV2(randomBytes(32)), "family", FAM, path, 3, sealed)).rejects.toThrow();
  });

  it("key separation: the raw key does not open v2, the seal key does not open v1", async () => {
    const raw = randomBytes(32);
    const v1Key = await importAesKey(raw);
    const v2Key = await mediaSealKeyV2(raw);
    const path2 = e2eMediaPathV2(`${FAM}/branding`, "logo.ab12cd34", 1);
    const path1 = e2eMediaPath(`${FAM}/branding`, "logo.ab12cd34", 1);
    const plain = randomBytes(64);

    const sealed2 = await sealMediaV2(v2Key, "family", FAM, path2, 1, plain);
    await expect(openMediaV2(v1Key, "family", FAM, path2, 1, sealed2)).rejects.toThrow();
    // Not even the v1 opener with the v2 key: the AAD label differs too.
    await expect(openMedia(v2Key, "family", FAM, path2, 1, sealed2)).rejects.toThrow();

    const sealed1 = await sealMedia(v1Key, "family", FAM, path1, 1, plain);
    await expect(openMediaV2(v2Key, "family", FAM, path1, 1, sealed1)).rejects.toThrow();
  });

  it("seals v2 only under a .s2 path, and tells the formats apart by the path", async () => {
    const key = await mediaSealKeyV2(randomBytes(32));
    expect(() =>
      sealMediaV2(key, "family", FAM, e2eMediaPath(`${FAM}/branding`, "cover.x", 1), 1, randomBytes(8)),
    ).toThrow(/\.s2/);

    expect(isMediaSealV2(`${FAM}/branding/cover.ab12cd34.s2.e2e.v3.enc`)).toBe(true);
    expect(isMediaSealV2("u/avatar.ab12cd34.s2.e2e.v12.enc")).toBe(true);
    expect(isMediaSealV2(`${FAM}/branding/cover.ab12cd34.e2e.v3.enc`)).toBe(false);
    expect(isMediaSealV2("u/avatar.s2.enc")).toBe(false);
    expect(isMediaSealV2("x/cover.s2.jpg")).toBe(false);
    expect(isMediaSealV2(null)).toBe(false);
    expect(isMediaSealV2(undefined)).toBe(false);
  });
});

describe("sealImage (the writers' choice of format)", () => {
  it("with a media-seal key: a .s2 path, opened only with that key; without: v1 as before", async () => {
    const raw = randomBytes(32);
    const v1 = await importAesKey(raw);
    const v2 = await mediaSealKeyV2(raw);
    const plain = randomBytes(40);

    const a = await sealImage({ v1, v2 }, "family", FAM, `${FAM}/branding`, "logo.ab12cd34", 2, plain);
    expect(a.path).toBe(`${FAM}/branding/logo.ab12cd34.s2.e2e.v2.enc`);
    expect(await openMediaV2(v2, "family", FAM, a.path, 2, a.sealed)).toEqual(plain);
    await expect(openMedia(v1, "family", FAM, a.path, 2, a.sealed)).rejects.toThrow();

    const b = await sealImage({ v1, v2: null }, "family", FAM, `${FAM}/branding`, "logo.ab12cd34", 2, plain);
    expect(b.path).toBe(`${FAM}/branding/logo.ab12cd34.e2e.v2.enc`);
    expect(await openMedia(v1, "family", FAM, b.path, 2, b.sealed)).toEqual(plain);
  });
});
