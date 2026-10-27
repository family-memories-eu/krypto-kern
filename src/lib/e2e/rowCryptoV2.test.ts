import { describe, expect, it } from "vitest";

import { E2eError, importAesKey, randomBytes } from "./bytes";
import { generateAccountKey } from "./identity";
import { encryptRow } from "./rowCrypto";
import {
  bytesUuid,
  decryptRowV2,
  encryptRowV2,
  openRowV2Unchecked,
  rowFormat,
  rowKeyV2,
  uuidBytes,
  type RowBindingV2,
  type SignerLookup,
} from "./rowCryptoV2";

// =============================================================================
// Row format v2 (AP-Zeilen v2). Each case is an ATTACK the format must stop:
// the server moving a row or changing its references, author or revision, a
// member writing in someone else's name, and the plain v1 key opening v2.
// =============================================================================

const ALICE = "11111111-1111-4111-8111-111111111111";
const ALICE_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const MALLORY = "22222222-2222-4222-8222-222222222222";
const MALLORY_ID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";

const alice = generateAccountKey();
const mallory = generateAccountKey();
const lookup: SignerLookup = async (id) =>
  id === ALICE_ID ? { userId: ALICE, edPk: alice.edPk } : id === MALLORY_ID ? { userId: MALLORY, edPk: mallory.edPk } : null;

const binding: RowBindingV2 & { author: string } = {
  table: "comments",
  rowId: "33333333-3333-4333-8333-333333333333",
  scopeId: "44444444-4444-4444-8444-444444444444",
  keyVersion: 3,
  refs: ["44444444-4444-4444-8444-444444444444", "photo", "55555555-5555-4555-8555-555555555555", ""],
  author: ALICE,
};
const asAlice = { userId: ALICE, identityId: ALICE_ID, edSk: alice.edSk };

async function code(p: Promise<unknown>): Promise<string> {
  try {
    await p;
    return "opened";
  } catch (e) {
    return e instanceof E2eError ? e.code : String(e);
  }
}

describe("row format v2", () => {
  it("round trip: fields, signer, revision, legacy flag", async () => {
    const key = await rowKeyV2(randomBytes(32));
    const blob = await encryptRowV2(key, binding, { body: "Hallo" }, asAlice, 7);
    expect(rowFormat(blob)).toBe(2);
    const out = await decryptRowV2(key, binding, blob, lookup);
    expect(out).toEqual({
      fields: { body: "Hallo" },
      author: ALICE,
      signer: { userId: ALICE, identityId: ALICE_ID },
      rev: 7,
      legacy: false,
    });
    const legacy = await encryptRowV2(key, binding, { body: "alt" }, asAlice, 1, { legacy: true });
    expect((await decryptRowV2(key, binding, legacy, lookup)).legacy).toBe(true);
  });

  it("uuid bytes round trip", () => {
    expect(bytesUuid(uuidBytes(ALICE_ID))).toBe(ALICE_ID);
    expect(() => uuidBytes("nope")).toThrow();
  });

  it("server moves the comment to another photo, row, scope or version → does not open", async () => {
    const key = await rowKeyV2(randomBytes(32));
    const blob = await encryptRowV2(key, binding, { body: "x" }, asAlice, 1);
    const moved: RowBindingV2[] = [
      { ...binding, refs: [binding.refs[0], "photo", "66666666-6666-4666-8666-666666666666", ""] },
      { ...binding, refs: [binding.refs[0], "album", binding.refs[2], ""] },
      { ...binding, rowId: "77777777-7777-4777-8777-777777777777" },
      { ...binding, scopeId: "88888888-8888-4888-8888-888888888888" },
      { ...binding, keyVersion: 4 },
      { ...binding, table: "stories" },
    ];
    for (const b of moved) expect(await code(decryptRowV2(key, b, blob, lookup))).toBe("signature");
  });

  it("the author is sealed inside: a changed author column still yields the real author (the reader compares)", async () => {
    const key = await rowKeyV2(randomBytes(32));
    const blob = await encryptRowV2(key, binding, { body: "x" }, asAlice, 1);
    const out = await decryptRowV2(key, { ...binding, author: MALLORY } as RowBindingV2, blob, lookup);
    expect(out.author).toBe(ALICE);
  });

  it("the signer's user is in the signature: the same key under another user id does not verify", async () => {
    const key = await rowKeyV2(randomBytes(32));
    const blob = await encryptRowV2(key, binding, { body: "x" }, asAlice, 1);
    const otherUser: SignerLookup = async (id) => (id === ALICE_ID ? { userId: MALLORY, edPk: alice.edPk } : null);
    expect(await code(decryptRowV2(key, binding, blob, otherUser))).toBe("signature");
  });

  it("unchecked opening (resealing only): works without knowing the signer, never with a wrong key or binding", async () => {
    const key = await rowKeyV2(randomBytes(32));
    const blob = await encryptRowV2(key, binding, { body: "Bestand" }, asAlice, 4, { legacy: false });
    // The author's account and identity are gone (0026): no lookup needed.
    expect(await openRowV2Unchecked(key, binding, blob)).toEqual({
      fields: { body: "Bestand" },
      author: ALICE,
      signerIdentity: ALICE_ID,
      rev: 4,
      legacy: false,
    });
    expect(await code(openRowV2Unchecked(await rowKeyV2(randomBytes(32)), binding, blob))).toBe("decrypt");
    expect(await code(openRowV2Unchecked(key, { ...binding, rowId: "77777777-7777-4777-8777-777777777777" }, blob))).toBe("decrypt");
  });

  it("revision or legacy flag flipped in the header → rejected", async () => {
    const key = await rowKeyV2(randomBytes(32));
    const blob = await encryptRowV2(key, binding, { body: "x" }, asAlice, 5);
    const older = blob.slice();
    new DataView(older.buffer).setUint32(17, 4);
    expect(await code(decryptRowV2(key, binding, older, lookup))).toBe("signature");
    const legacy = blob.slice();
    legacy[21] = 1;
    expect(await code(decryptRowV2(key, binding, legacy, lookup))).toBe("signature");
    const unknownFlag = blob.slice();
    unknownFlag[21] = 2;
    expect(await code(decryptRowV2(key, binding, unknownFlag, lookup))).toBe("format");
  });

  it("a member re-signs Alice's text with their own key: signer becomes Mallory, never Alice", async () => {
    const key = await rowKeyV2(randomBytes(32));
    // Mallory holds the family key and seals a text claiming author = Alice.
    const forged = await encryptRowV2(key, binding, { body: "gefälscht" }, { userId: MALLORY, identityId: MALLORY_ID, edSk: mallory.edSk }, 9);
    const out = await decryptRowV2(key, binding, forged, lookup);
    // It opens — but the signer is Mallory; the author-or-owner rule rejects it (rowVerify).
    expect(out.signer.userId).toBe(MALLORY);
    // Swapping in Alice's identity in the header breaks the signature.
    const swapped = forged.slice();
    swapped.set(uuidBytes(ALICE_ID), 1);
    expect(await code(decryptRowV2(key, binding, swapped, lookup))).toBe("signature");
  });

  it("unknown signer → untrustedSender; flipped ciphertext → signature", async () => {
    const key = await rowKeyV2(randomBytes(32));
    const blob = await encryptRowV2(key, binding, { body: "x" }, asAlice, 1);
    expect(await code(decryptRowV2(key, binding, blob, async () => null))).toBe("untrustedSender");
    const flipped = blob.slice();
    flipped[30] ^= 1;
    expect(await code(decryptRowV2(key, binding, flipped, lookup))).toBe("signature");
  });

  it("key separation: the raw scope key (v1 row key) does not open v2, and v1 blobs are not v2", async () => {
    const raw = randomBytes(32);
    const v2 = await rowKeyV2(raw);
    const blob = await encryptRowV2(v2, binding, { body: "x" }, asAlice, 1);
    expect(await code(decryptRowV2(await importAesKey(raw), binding, blob, lookup))).toBe("decrypt");
    const v1 = await encryptRow(await importAesKey(raw), { table: "comments", rowId: binding.rowId, scopeId: binding.scopeId, keyVersion: 3 }, { body: "x" });
    expect(rowFormat(v1)).toBe(1);
    expect(await code(decryptRowV2(v2, binding, v1, lookup))).toBe("format");
  });

  it("rev must be a positive u32", async () => {
    const key = await rowKeyV2(randomBytes(32));
    await expect(encryptRowV2(key, binding, {}, asAlice, 0)).rejects.toThrow(RangeError);
  });
});
