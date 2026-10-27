import { beforeEach, describe, expect, it } from "vitest";

import { decryptBlob, encryptBlob } from "@/lib/crypto";
import { decryptChunk, encryptVideoChunked, parseVideoHeader, cipherChunkLen, cipherChunkStart } from "@/lib/videoCrypto";
import {
  bindKeyToRow,
  blobHash,
  cipherHash,
  noteBlockList,
  noteRowObjects,
  noteScopeMediaBound,
  objField,
  resetObjBindingForTests,
} from "./objBinding";

// K-03 (interne Prüfung, P1 Teil C): an object key opens only what the signed row binds.

async function aesKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}

const blob = (s: string) => new Blob([new TextEncoder().encode(s)]);
const text = async (b: Blob) => new TextDecoder().decode(await b.arrayBuffer());

beforeEach(() => resetObjBindingForTests());

describe("objField", () => {
  it("keeps only known roles with well-formed hashes", async () => {
    const h = await cipherHash(new Uint8Array([1]));
    expect(objField({ full: h, thumb: "kurz", evil: h })).toEqual({ full: h });
    expect(objField(null)).toBeNull();
    expect(objField([h])).toBeNull();
    expect(objField({ thumb: 5 })).toBeNull();
  });
});

describe("decryptBlob with a key tied to a row", () => {
  it("opens the object the row binds", async () => {
    const key = await aesKey();
    const enc = await encryptBlob(key, blob("original"));
    bindKeyToRow(key, "row-1", "fam-1");
    noteRowObjects("row-1", { full: await blobHash(enc) });
    expect(await text(await decryptBlob(key, enc, "text/plain"))).toBe("original");
  });

  it("refuses another object made with the same key (the attack: an old scope key + the server)", async () => {
    const key = await aesKey();
    const enc = await encryptBlob(key, blob("original"));
    const forged = await encryptBlob(key, blob("gefälscht"));
    bindKeyToRow(key, "row-1", "fam-1");
    noteRowObjects("row-1", { full: await blobHash(enc), thumb: await blobHash(await encryptBlob(key, blob("t"))) });
    await expect(decryptBlob(key, forged, "text/plain")).rejects.toMatchObject({ code: "errorDecrypt" });
  });

  it("refuses the objects of a row that did not open", async () => {
    const key = await aesKey();
    const enc = await encryptBlob(key, blob("original"));
    bindKeyToRow(key, "row-1", "fam-1");
    noteRowObjects("row-1", "refused");
    await expect(decryptBlob(key, enc, "text/plain")).rejects.toMatchObject({ code: "errorDecrypt" });
  });

  it("opens an unbound object (no obj yet) only until the scope is bound", async () => {
    const key = await aesKey();
    const enc = await encryptBlob(key, blob("alt"));
    bindKeyToRow(key, "row-1", "fam-1");
    noteRowObjects("row-1", null);
    expect(await text(await decryptBlob(key, enc, "text/plain"))).toBe("alt");
    noteScopeMediaBound("fam-1");
    await expect(decryptBlob(key, enc, "text/plain")).rejects.toMatchObject({ code: "errorDecrypt" });
  });

  it("refuses an object of a row never opened here once the scope is bound", async () => {
    const key = await aesKey();
    const enc = await encryptBlob(key, blob("x"));
    bindKeyToRow(key, "row-unknown", "fam-1");
    noteScopeMediaBound("fam-1");
    await expect(decryptBlob(key, enc, "text/plain")).rejects.toMatchObject({ code: "errorDecrypt" });
  });

  it("does not check a key that is not tied to a row (links, writing)", async () => {
    const key = await aesKey();
    noteScopeMediaBound("fam-1");
    const enc = await encryptBlob(key, blob("link"));
    expect(await text(await decryptBlob(key, enc, "text/plain"))).toBe("link");
  });
});

describe("FMV2 chunks of a bound video", () => {
  async function video(key: CryptoKey) {
    const plain = new Uint8Array((1 << 20) + 10).map((_, i) => i % 251);
    const enc = new Uint8Array(await (await encryptVideoChunked(key, new Blob([plain], { type: "video/mp4" }))).arrayBuffer());
    const h = parseVideoHeader(enc.subarray(0, 1024));
    const chunk = (i: number) => enc.slice(cipherChunkStart(h, i), cipherChunkStart(h, i) + cipherChunkLen(h, i));
    return { h, chunk };
  }

  it("needs the checked block list, and only its chunks open", async () => {
    const key = await aesKey();
    const { h, chunk } = await video(key);
    bindKeyToRow(key, "vid-1", "fam-1");
    noteRowObjects("vid-1", { blocks: await cipherHash(new Uint8Array([9])) });
    // No list checked yet → nothing opens.
    await expect(decryptChunk(key, h, 0, chunk(0))).rejects.toMatchObject({ code: "errorDecrypt" });
    noteBlockList("vid-1", { header: await cipherHash(h.headerBytes), chunks: [await cipherHash(chunk(0)), await cipherHash(chunk(1))] });
    expect((await decryptChunk(key, h, 0, chunk(0))).length).toBe(1 << 20);
    // Chunk 1 handed in as chunk 0 (same key, other bytes) → refused.
    await expect(decryptChunk(key, h, 0, chunk(1))).rejects.toMatchObject({ code: "errorDecrypt" });
  });

  it("refuses a chunk whose list names another header", async () => {
    const key = await aesKey();
    const { h, chunk } = await video(key);
    bindKeyToRow(key, "vid-1", "fam-1");
    noteRowObjects("vid-1", { blocks: await cipherHash(new Uint8Array([9])) });
    noteBlockList("vid-1", { header: await cipherHash(new Uint8Array([1])), chunks: [await cipherHash(chunk(0))] });
    await expect(decryptChunk(key, h, 0, chunk(0))).rejects.toMatchObject({ code: "errorDecrypt" });
  });
});
