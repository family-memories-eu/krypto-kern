// =============================================================================
// Recovery code (docs/e2e-design.md §6.3). Printed on paper, typed by people who
// may not type often — so the format is forgiving and has a check character:
//
//   24 Crockford-Base32 symbols, shown as 6 groups of 4:  K7QM-2F9X-…-T4W1
//   = 23 random symbols (115 bits) + 1 check symbol.
//
// Input tolerates lower case, spaces, dashes, and the classic confusions
// O→0, I/L→1. A typo is reported as a typo (check symbol mismatch) before any
// expensive Argon2id run, instead of as "wrong code".
//
// The wrap key is Argon2id(canonical code, salt). 115 random bits are far
// beyond guessing on their own; Argon2id is cheap insurance on top.
// =============================================================================

import { argon2id } from "hash-wasm";

import { E2eError, importAesKey, randomBytes, type Bytes } from "./bytes";

const ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const DATA_SYMBOLS = 23;
const GROUP = 4;

export type Argon2Params = { memoryKiB: number; iterations: number; parallelism: number };

/** Design §4.1. Tests pass smaller values; production must not. */
export const RECOVERY_ARGON2: Argon2Params = { memoryKiB: 64 * 1024, iterations: 3, parallelism: 1 };

function checkSymbol(values: number[]): number {
  // Odd weights (2i+1) are units mod 32, so every single-symbol error changes
  // the checksum.
  let sum = 0;
  for (let i = 0; i < values.length; i++) sum = (sum + values[i] * (2 * i + 1)) % 32;
  return sum;
}

export function generateRecoveryCode(): string {
  const r = randomBytes(DATA_SYMBOLS);
  const values = Array.from(r, (b) => b & 31); // 256 is a multiple of 32: no bias
  values.push(checkSymbol(values));
  const s = values.map((v) => ALPHABET[v]).join("");
  return s.match(new RegExp(`.{1,${GROUP}}`, "g"))!.join("-");
}

export type ParsedCode = { ok: true; canonical: string } | { ok: false; reason: "length" | "symbol" | "typo" };

export function parseRecoveryCode(input: string): ParsedCode {
  const s = input
    .toUpperCase()
    .replace(/[\s-]/g, "")
    .replace(/O/g, "0")
    .replace(/[IL]/g, "1");
  if (s.length !== DATA_SYMBOLS + 1) return { ok: false, reason: "length" };
  const values: number[] = [];
  for (const ch of s) {
    const v = ALPHABET.indexOf(ch);
    if (v < 0) return { ok: false, reason: "symbol" };
    values.push(v);
  }
  const check = values.pop()!;
  if (checkSymbol(values) !== check) return { ok: false, reason: "typo" };
  return { ok: true, canonical: s };
}

export async function recoveryWrapKey(
  code: string,
  salt: Uint8Array,
  params: Argon2Params = RECOVERY_ARGON2,
): Promise<CryptoKey> {
  const parsed = parseRecoveryCode(code);
  if (!parsed.ok) throw new E2eError("recoveryCode");
  const raw = await argon2id({
    password: parsed.canonical,
    salt,
    memorySize: params.memoryKiB,
    iterations: params.iterations,
    parallelism: params.parallelism,
    hashLength: 32,
    outputType: "binary",
  });
  return importAesKey(raw);
}

export function newRecoverySalt(): Bytes {
  return randomBytes(16);
}
