import { describe, expect, it } from "vitest";

import { generateAccountKey } from "./identity";
import { linkSignerAllowed, signLink, verifyLink } from "./linkSig";

// Signed links (AP-Zeilen v2): the server must not be able to pair a tag with
// another photo, or put a link in someone else's name.

const A = "11111111-1111-4111-8111-111111111111";
const A_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const B = "22222222-2222-4222-8222-222222222222";
const ak = generateAccountKey();
const signer = { userId: A, identityId: A_ID, edSk: ak.edSk };
const pub = { userId: A, identityId: A_ID, edPk: ak.edPk };

const photo = "33333333-3333-4333-8333-333333333333";
const tag = "44444444-4444-4444-8444-444444444444";

describe("signed links", () => {
  it("a tag link verifies; moved to another photo or tag it does not", () => {
    const sig = signLink("photo_tags", { photo_id: photo, tag_id: tag }, signer);
    expect(verifyLink("photo_tags", { photo_id: photo, tag_id: tag }, pub, sig)).toBe(true);
    expect(verifyLink("photo_tags", { photo_id: tag, tag_id: photo }, pub, sig)).toBe(false);
    expect(verifyLink("photo_tags", { photo_id: "55555555-5555-4555-8555-555555555555", tag_id: tag }, pub, sig)).toBe(false);
    // Same ids under another link table (story instead of photo) → no.
    expect(verifyLink("story_tags", { story_id: photo, tag_id: tag }, pub, sig)).toBe(false);
  });

  it("the signature names its signer: claiming another person fails", () => {
    const sig = signLink("album_tags", { album_id: photo, tag_id: tag }, signer);
    expect(verifyLink("album_tags", { album_id: photo, tag_id: tag }, { ...pub, userId: B }, sig)).toBe(false);
  });

  it("a timeline link counts only when signed by its creator, and binds both ends", () => {
    const row = {
      id: "66666666-6666-4666-8666-666666666666",
      family_id: "77777777-7777-4777-8777-777777777777",
      created_by: A,
      source_photo_id: photo,
      target_story_id: tag,
    };
    const sig = signLink("timeline_links", row, signer);
    expect(verifyLink("timeline_links", row, pub, sig)).toBe(true);
    expect(verifyLink("timeline_links", { ...row, target_story_id: null, target_album_id: tag }, pub, sig)).toBe(false);
    expect(verifyLink("timeline_links", { ...row, created_by: B }, pub, sig)).toBe(false);
    const ctx = { owners: new Set([B]), members: new Set([A, B]) };
    expect(linkSignerAllowed("timeline_links", row, { userId: A, status: "current" }, ctx)).toBe(true);
    // A member other than the creator may not sign it; the owner only once the creator is gone.
    expect(linkSignerAllowed("timeline_links", row, { userId: B, status: "current" }, ctx)).toBe(false);
    expect(linkSignerAllowed("timeline_links", { ...row, created_by: null }, { userId: B, status: "current" }, ctx)).toBe(true);
    expect(linkSignerAllowed("timeline_links", { ...row, created_by: null }, { userId: A, status: "current" }, ctx)).toBe(false);
  });

  it("tag links: anyone in the family with a current key", () => {
    const ctx = { owners: new Set<string>(), members: new Set([A]) };
    expect(linkSignerAllowed("photo_tags", {}, { userId: A, status: "current" }, ctx)).toBe(true);
    expect(linkSignerAllowed("photo_tags", {}, { userId: A, status: "previous" }, ctx)).toBe(false);
    expect(linkSignerAllowed("photo_tags", {}, { userId: B, status: "current" }, ctx)).toBe(false);
  });
});
