// =============================================================================
// Which content fields an encrypted row carries, and which plaintext column
// each one replaces (E2E Etappe 2, design §4.3, migration 0134). The ONE place
// this mapping lives: the writers seal these fields and null these columns
// (lib/data/mutations/sealedRows.ts), the export opens them back into the
// columns (lib/data/openRows.ts openRawRows), and the readers use the same
// field names.
// =============================================================================

export const ROW_COLUMNS = {
  stories: { title: "title", content: "content", transcript: "transcript", storyDate: "story_date" },
  story_chapters: { title: "title", content: "content", transcript: "transcript", chapterDate: "chapter_date" },
  photos: { caption: "caption", dateTaken: "date_taken", durationSeconds: "duration_seconds" },
  albums: { title: "title", albumDate: "album_date" },
  comments: { body: "body" },
  tags: { name: "name" },
  families: { name: "name", tagline: "tagline", accent: "accent" },
  // Posters (0207): the whole draft is one sealed field `doc`; the table has no
  // plaintext column it would replace.
  poster_designs: {},
  // Book drafts (0208, Buch-Editor): the head and each page are one sealed field
  // each (`head`, `page`); no plaintext column to replace.
  book_drafts: {},
  book_draft_pages: {},
} as const;

export type SealedTable = keyof typeof ROW_COLUMNS;

// =============================================================================
// Format v2 (AP-Zeilen v2): which plaintext columns of a row are bound into
// the AAD (in this order), which column names the author, and who may sign.
//   authorOrOwner — the author, or the family owner (Z1; in a collaborative
//                   story also the story's author, who seals its Bestand);
//   member        — anyone in the family (tags, translations: no author);
//   owner         — the family owner only (the family row).
// family_id is not listed: the AAD binds the scope (the family, or the
// collaborative story, whose family_id the database keeps fixed).
// Not bound: albums.cover_photo_id (`on delete set null` would lock the album
// when its cover is deleted) — the server could show another family photo as
// cover; named as a limit in design §10.
// =============================================================================

export type SignerRule = "authorOrOwner" | "member" | "owner";

export const ROW_V2 = {
  stories: { refs: ["is_collaborative"], author: "author_id", signers: "authorOrOwner" },
  story_chapters: { refs: ["story_id", "position"], author: "author_id", signers: "authorOrOwner" },
  photos: { refs: ["album_id", "story_id", "chapter_id"], author: "uploaded_by", signers: "authorOrOwner" },
  albums: { refs: [], author: "created_by", signers: "authorOrOwner" },
  comments: {
    refs: ["story_id", "chapter_id", "photo_id", "album_id", "parent_id"],
    author: "author_id",
    signers: "authorOrOwner",
  },
  tags: { refs: ["name_idx"], author: null, signers: "member" },
  // No author bound: owner_id changes with a transfer of ownership, and the
  // signer rule already asks for the CURRENT owner — the new owner's device
  // then seals the head anew (resealV2.ts).
  families: { refs: [], author: null, signers: "owner" },
  // Private drafts (Q8): only the creator reads and writes them (RLS 0207), so
  // only the creator signs. NOT in the reseal of resealV2.ts — the owner's
  // device that reseals after a rotation cannot even see these rows; older key
  // versions stay readable (Schlüsselrotation), so a draft is never lost.
  poster_designs: { refs: [], author: "created_by", signers: "authorOrOwner" },
  // Book drafts (0208): private to their creator like poster drafts. A page is
  // bound to its draft, so a server cannot move it into another draft unnoticed
  // (the database's composite key holds family and author as well).
  book_drafts: { refs: [], author: "created_by", signers: "authorOrOwner" },
  book_draft_pages: { refs: ["draft_id"], author: "created_by", signers: "authorOrOwner" },
  content_translations: {
    refs: ["source_table", "source_id", "source_column", "target_locale"],
    author: null,
    signers: "member",
  },
} as const satisfies Record<string, { refs: readonly string[]; author: string | null; signers: SignerRule }>;

export type V2Table = keyof typeof ROW_V2;

/** A column value as bound: absent → "", booleans "1"/"0", the rest as text. */
export function refValue(v: unknown): string {
  if (v === null || v === undefined) return "";
  if (typeof v === "boolean") return v ? "1" : "0";
  return String(v);
}

/** The bound references and author of a RAW row (snake_case columns). */
export function v2BindingOf(table: V2Table, row: Record<string, unknown>): { refs: string[]; author: string } {
  const spec = ROW_V2[table];
  return {
    refs: spec.refs.map((c) => refValue(row[c])),
    author: spec.author ? refValue(row[spec.author]) : "",
  };
}
