import { describe, expect, it } from "vitest";

import { toPgBytea } from "./bytes";
import { memoryStore } from "./deviceStore";
import { fingerprint, generateAccountKey, publicPart, selfSign, type AccountKey } from "./identity";
import { makeSignerBook, RowRevisions, signerAllowed, type IdentityRow, type SignerContext } from "./rowVerify";
import { emptyTrustStore, type TrustStore } from "./trustStore";

// The checks around a v2 signature (AP-Zeilen v2): whose key, may they sign,
// and is it older than what this device already showed.

const ME = "00000000-0000-4000-8000-000000000000";
const ME_ID = "00000000-0000-4000-8000-0000000000aa";
const A = "11111111-1111-4111-8111-111111111111";
const B = "22222222-2222-4222-8222-222222222222";
const OWNER = "33333333-3333-4333-8333-333333333333";

function idRow(id: string, userId: string, ak: AccountKey, signFor = userId): IdentityRow {
  return {
    id,
    user_id: userId,
    x25519_pub: toPgBytea(ak.x25519Pub),
    ed25519_pub: toPgBytea(ak.edPk),
    self_sig: toPgBytea(selfSign(ak, signFor)),
  };
}

async function storeWith(userId: string, current: AccountKey, previous: AccountKey[] = [], pending?: AccountKey): Promise<TrustStore> {
  const fp = await fingerprint(publicPart(current));
  const s = emptyTrustStore();
  s.entries[userId] = {
    identityId: "x",
    x25519Pub: "",
    edPk: "",
    fingerprint: fp,
    firstSeen: new Date().toISOString(),
    verified: false,
    previous: await Promise.all(previous.map((k) => fingerprint(publicPart(k)))),
    ...(pending ? { pendingChange: { identityId: "p", x25519Pub: "", edPk: "", fingerprint: await fingerprint(publicPart(pending)), seen: "" } } : {}),
  };
  return s;
}

describe("signer book", () => {
  it("K-08: a person met first as a signer is pinned — a second, other key of theirs counts for nothing", async () => {
    const real = generateAccountKey();
    const forged = generateAccountKey();
    const rows = new Map([
      ["id-real", idRow("id-real", A, real)],
      ["id-forged", idRow("id-forged", A, forged)],
    ]);
    const kept: TrustStore[] = [];
    const book = makeSignerBook(
      async (id) => rows.get(id) ?? null,
      emptyTrustStore(),
      { userId: ME, identityId: ME_ID },
      async (s) => void kept.push(s),
    );
    expect(await book("id-real")).toMatchObject({ userId: A, status: "current" });
    expect(await book("id-forged")).toBeNull();
    // Kept for the next time — as a first use, which never earns a release.
    expect(kept.at(-1)?.entries[A]).toMatchObject({ fingerprint: await fingerprint(publicPart(real)), origin: "tofu" });
  });

  it("accepted key → current; earlier key → previous; pending or unknown other key → null", async () => {
    const now = generateAccountKey();
    const old = generateAccountKey();
    const pending = generateAccountKey();
    const stranger = generateAccountKey();
    const rows: Record<string, IdentityRow> = {
      i1: idRow("i1", A, now),
      i2: idRow("i2", A, old),
      i3: idRow("i3", A, pending),
      i4: idRow("i4", A, stranger),
    };
    const book = makeSignerBook(async (id) => rows[id] ?? null, await storeWith(A, now, [old], pending), { userId: ME, identityId: ME_ID });
    expect((await book("i1"))?.status).toBe("current");
    expect((await book("i2"))?.status).toBe("previous");
    expect(await book("i3")).toBeNull();
    expect(await book("i4")).toBeNull();
    expect(await book("missing")).toBeNull();
  });

  it("the server reassigning a key to another person fails the self-signature", async () => {
    const k = generateAccountKey();
    const book = makeSignerBook(async () => ({ ...idRow("i1", A, k), user_id: B }), emptyTrustStore(), { userId: ME, identityId: ME_ID });
    expect(await book("i1")).toBeNull();
  });

  it("a person never seen is taken on first use; my own keys by identity", async () => {
    const k = generateAccountKey();
    const mine = generateAccountKey();
    const rows: Record<string, IdentityRow> = { i1: idRow("i1", B, k), [ME_ID]: idRow(ME_ID, ME, mine), old: idRow("old", ME, generateAccountKey()) };
    const book = makeSignerBook(async (id) => rows[id] ?? null, emptyTrustStore(), { userId: ME, identityId: ME_ID });
    expect((await book("i1"))?.userId).toBe(B);
    expect((await book(ME_ID))?.status).toBe("current");
    expect((await book("old"))?.status).toBe("previous");
  });
});

describe("who may sign", () => {
  const ctx: SignerContext = { owners: new Set([OWNER]), members: new Set([A, B, OWNER]), currentVersion: 3 };
  const cur = (userId: string) => ({ userId, status: "current" as const });
  const row = { author: A, keyVersion: 3, legacy: false };

  it("authorOrOwner: the author and the owner, nobody else (Z1)", () => {
    expect(signerAllowed("authorOrOwner", cur(A), row, ctx)).toBe(true);
    expect(signerAllowed("authorOrOwner", cur(OWNER), row, ctx)).toBe(true);
    expect(signerAllowed("authorOrOwner", cur(B), row, ctx)).toBe(false);
    // No author (account gone): only the owner.
    expect(signerAllowed("authorOrOwner", cur(""), { ...row, author: "" }, ctx)).toBe(false);
  });

  it("member rule: anyone in the family; owner rule: only the owner", () => {
    expect(signerAllowed("member", cur(B), row, ctx)).toBe(true);
    expect(signerAllowed("member", cur("44444444-4444-4444-8444-444444444444"), row, ctx)).toBe(false);
    expect(signerAllowed("owner", cur(A), row, ctx)).toBe(false);
    expect(signerAllowed("owner", cur(OWNER), row, ctx)).toBe(true);
  });

  it("Bestand only from an owner — not even from the author", () => {
    expect(signerAllowed("authorOrOwner", cur(A), { ...row, legacy: true }, ctx)).toBe(false);
    expect(signerAllowed("authorOrOwner", cur(OWNER), { ...row, legacy: true }, ctx)).toBe(true);
  });

  it("an earlier key signs only rows of an older key version", () => {
    const prev = { userId: A, status: "previous" as const };
    expect(signerAllowed("authorOrOwner", prev, { ...row, keyVersion: 2 }, ctx)).toBe(true);
    expect(signerAllowed("authorOrOwner", prev, row, ctx)).toBe(false);
    expect(signerAllowed("authorOrOwner", prev, { ...row, keyVersion: 2 }, { ...ctx, currentVersion: null })).toBe(false);
  });
});

describe("revisions on this device", () => {
  it("a lower revision, or v1 after v2, is a rollback; v2-only is sticky across loads", async () => {
    const kv = memoryStore();
    const r = new RowRevisions(kv, ME, 0);
    await r.load();
    expect(r.seeV1("comments", "c1")).toBe("ok");
    expect(r.seeV2("comments", "c1", 3)).toBe("ok");
    expect(r.seeV2("comments", "c1", 3)).toBe("ok");
    expect(r.seeV2("comments", "c1", 2)).toBe("rollback");
    expect(r.seeV1("comments", "c1")).toBe("rollback");
    r.markV2Only("fam");
    await r.flush();

    const again = new RowRevisions(kv, ME, 0);
    await again.load();
    expect(again.seeV2("comments", "c1", 2)).toBe("rollback");
    expect(again.isV2Only("fam")).toBe(true);
    expect(again.isV2Only("other")).toBe(false);
  });
});
