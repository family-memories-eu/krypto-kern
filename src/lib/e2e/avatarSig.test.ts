import { describe, expect, it } from "vitest";

import { checkAvatar, parseSignedAvatar, signAvatar, verifyAvatar } from "./avatarSig";
import { generateAccountKey } from "./identity";

// K-03 (interne Prüfung, P1 Teil C · Entscheidung Alex 18.10.2026): the owner
// signs the stored picture; readers open only what the owner signed.

const OWNER = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const OTHER = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const OWNER_ID = "11111111-1111-4111-8111-111111111111";
const OTHER_ID = "22222222-2222-4222-8222-222222222222";
const PATH = `${OWNER}/avatar.ab12cd34.s2.e2e.v1.enc`;

const owner = generateAccountKey();
const other = generateAccountKey();
const signer = async (identityId: string) =>
  identityId === OWNER_ID ? { userId: OWNER, edPk: owner.edPk } : identityId === OTHER_ID ? { userId: OTHER, edPk: other.edPk } : null;

const sealed = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
const signed = (o: Partial<{ path: string; signedAt: number; edSk: Uint8Array; identityId: string; userId: string; sealed: Uint8Array }> = {}) =>
  signAvatar(o.sealed ?? sealed, {
    userId: o.userId ?? OWNER,
    identityId: o.identityId ?? OWNER_ID,
    path: o.path ?? PATH,
    signedAt: o.signedAt ?? 1_760_000_000_000,
    edSk: o.edSk ?? owner.edSk,
  });
const check = (bytes: Uint8Array, lastSeen?: number) => checkAvatar({ bytes, ownerId: OWNER, path: PATH, lastSeen, signer });

describe("signed profile pictures", () => {
  it("round-trips: the parts come back and the signature holds", async () => {
    const p = parseSignedAvatar(await signed());
    expect(p).toMatchObject({ identityId: OWNER_ID, signedAt: 1_760_000_000_000, sealed });
    expect(await verifyAvatar(owner.edPk, p as Exclude<typeof p, null | "bad">, OWNER, PATH)).toBe(true);
  });

  it("opens the owner's signed picture and reports when it was signed", async () => {
    expect(await check(await signed())).toEqual({ sealed, signedAt: 1_760_000_000_000 });
  });

  it("refuses another picture sealed with the avatar key — unsigned, once a signed one was shown", async () => {
    expect(await check(new Uint8Array([9, 9, 9]))).toEqual({ sealed: new Uint8Array([9, 9, 9]) }); // never seen signed: as before
    expect(await check(new Uint8Array([9, 9, 9]), 1)).toBeNull();
  });

  it("refuses a picture signed by someone else — even for their own identity", async () => {
    expect(await check(await signed({ identityId: OTHER_ID, edSk: other.edSk }))).toBeNull();
    expect(await check(await signed({ edSk: other.edSk }))).toBeNull();
  });

  it("refuses the owner's signature moved to another path, user or picture", async () => {
    expect(await check(await signed({ path: `${OWNER}/avatar.other000.s2.e2e.v1.enc` }))).toBeNull();
    expect(await check(await signed({ userId: OTHER }))).toBeNull();
    const bytes = await signed();
    bytes[bytes.length - 1] ^= 1;
    expect(await check(bytes)).toBeNull();
  });

  it("refuses an older picture than one already shown (no rolling back)", async () => {
    expect(await check(await signed({ signedAt: 100 }), 200)).toBeNull();
    expect(await check(await signed({ signedAt: 200 }), 200)).not.toBeNull();
  });

  it("an unknown signer, or a malformed head, is refused", async () => {
    expect(await check(await signed({ identityId: "33333333-3333-4333-8333-333333333333" }))).toBeNull();
    const bytes = await signed();
    expect(parseSignedAvatar(bytes.slice(0, 50))).toBe("bad");
    bytes[4] = 9;
    expect(await check(bytes)).toBeNull();
  });
});
