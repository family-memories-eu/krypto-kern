// =============================================================================
// Signed links (AP-Zeilen v2, design §4.3): tags on photos, stories and albums
// and timeline links carry no content, only "A belongs with B". The server
// could still invent such a pairing — so whoever adds one signs it with the
// Ed25519 half of their account key, and readers drop links whose signature
// does not hold or whose signer may not write in that family.
//
// sig = Ed25519(signer, enc("fm/link/v2", table, fields…, signer user, signer identity))
//
// What a signature cannot stop: the server DELETING a link, or putting back one
// that was removed (it keeps a valid signature). Both are named in design §10.
// =============================================================================

import { encodeFields, type Bytes } from "./bytes";
import { sign, verify } from "./identity";
import { refValue } from "./rowFields";

const CTX = "fm/link/v2";

/** The columns of each link table that the signature covers, in order. */
export const LINK_FIELDS = {
  photo_tags: ["photo_id", "tag_id"],
  story_tags: ["story_id", "tag_id"],
  album_tags: ["album_id", "tag_id"],
  timeline_links: [
    "id",
    "family_id",
    "created_by",
    "source_photo_id",
    "source_album_id",
    "source_story_id",
    "target_photo_id",
    "target_album_id",
    "target_story_id",
  ],
} as const;

export type LinkTable = keyof typeof LINK_FIELDS;

function message(table: LinkTable, row: Record<string, unknown>, signerUser: string, signerIdentity: string): Bytes {
  return encodeFields(table, encodeFields(...LINK_FIELDS[table].map((c) => refValue(row[c]))), signerUser, signerIdentity);
}

export function signLink(
  table: LinkTable,
  row: Record<string, unknown>,
  signer: { userId: string; identityId: string; edSk: Uint8Array },
): Bytes {
  return sign(signer.edSk, CTX, message(table, row, signer.userId, signer.identityId));
}

export function verifyLink(
  table: LinkTable,
  row: Record<string, unknown>,
  signer: { userId: string; identityId: string; edPk: Uint8Array },
  sig: Uint8Array,
): boolean {
  return verify(signer.edPk, sig, CTX, message(table, row, signer.userId, signer.identityId));
}

/**
 * May this person sign this link? Tags on photos, stories and albums: anyone in
 * the family. A timeline link: its creator — or, once the creator's account is
 * gone (created_by NULL), the owner re-signing it as Bestand. Only a CURRENT
 * key: a link has no key version that could mark an earlier key's work as old;
 * after a rescue the links are signed anew (Teil 2).
 */
export function linkSignerAllowed(
  table: LinkTable,
  row: Record<string, unknown>,
  signer: { userId: string; status: "current" | "previous" },
  ctx: { owners: ReadonlySet<string>; members: ReadonlySet<string> },
): boolean {
  if (signer.status !== "current") return false;
  if (table === "timeline_links") {
    const creator = refValue(row.created_by);
    return creator !== "" ? creator === signer.userId : ctx.owners.has(signer.userId);
  }
  return ctx.members.has(signer.userId) || ctx.owners.has(signer.userId);
}
