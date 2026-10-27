// =============================================================================
// The global switch "write rows in format v2" (AP-Zeilen v2 Teil 2, Z5; 0154).
//
// The database holds `rows_v2_since` (null = off). This device remembers the
// earliest time it has seen there and from then on stays on — the service
// cannot turn a device back to v1 by clearing the row, and cannot push the
// date later to delay the owner's takeover after 14 days (Z6).
//
// A failed load is not "off": a device that has seen the switch stays on; one
// that never has keeps writing v1, which every reader still opens (until the
// scope is "v2 only" — the writers check that themselves, rowsV2 never lowers it).
// =============================================================================

import type { KeyValueStore } from "./deviceStore";

export type RowsV2State = { on: boolean; since: string | null };

const KEY = "rowsv2:since";

/** Days after the switch until the owner takes over the rest as "Bestand" (Z6). */
export const BESTAND_AFTER_DAYS = 14;

function valid(s: unknown): s is string {
  return typeof s === "string" && !Number.isNaN(Date.parse(s));
}

/**
 * `load` returns the database value: a timestamp, null (off) — or throws when
 * it could not be read.
 */
export async function readRowsV2(kv: KeyValueStore, load: () => Promise<string | null>): Promise<RowsV2State> {
  const stored = await kv.get<string>(KEY).catch(() => undefined);
  const seen = valid(stored) ? stored : null;
  let server: string | null = null;
  try {
    const v = await load();
    server = valid(v) ? v : null;
  } catch {
    server = null;
  }
  const since = [seen, server].filter((x): x is string => x !== null).sort((a, b) => Date.parse(a) - Date.parse(b))[0] ?? null;
  if (since !== null && since !== seen) await kv.set(KEY, since).catch(() => undefined);
  return { on: since !== null, since };
}

/** Is the owner's takeover of others' old rows due (Z6)? */
export function bestandDue(state: RowsV2State, now: number = Date.now()): boolean {
  return state.since !== null && now - Date.parse(state.since) >= BESTAND_AFTER_DAYS * 24 * 60 * 60 * 1000;
}
