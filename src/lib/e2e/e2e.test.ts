import { describe, expect, it } from "vitest";

import { generateDeviceStorageKey, passkeyWrapKey, unwrapAccountKey, wrapAccountKey } from "./akWrap";
import { E2eError, encodeFields, importAesKey, randomBytes, toB64url } from "./bytes";
import { generateContentKey, openEnvelope, sealEnvelope, type Envelope } from "./envelope";
import {
  deserializeAccountKey,
  fingerprint,
  generateAccountKey,
  publicPart,
  selfSign,
  serializeAccountKey,
  sign,
  verify,
  verifySelf,
} from "./identity";
import { generateRecoveryCode, newRecoverySalt, parseRecoveryCode, recoveryWrapKey } from "./recoveryCode";
import { decryptRow, encryptRow, paddedLength } from "./rowCrypto";
import {
  openPairingTransfer,
  sealPairingTransfer,
  signInvitation,
  tagIndex,
  tagIndexKey,
  verifyInvitation,
} from "./statements";
import { newEphemeralKeyPair, pairingCode, safetyCode, safetyCodeHalf } from "./trustCodes";

// =============================================================================
// The end-to-end core (docs/e2e-design.md). Beyond round trips, each block
// asserts the ATTACK it exists to stop — a crypto layer whose failure cases are
// untested fails silently in exactly the way that matters.
// =============================================================================

const FAMILY = "11111111-1111-4111-8111-111111111111";
const OMA = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const ENKEL = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const SERVER = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";

// Fast Argon2id for tests only; production uses RECOVERY_ARGON2 (64 MiB).
const FAST = { memoryKiB: 256, iterations: 1, parallelism: 1 };

async function rejects(p: Promise<unknown>, code: E2eError["code"]) {
  await expect(p).rejects.toMatchObject({ name: "E2eError", code });
}

describe("encodeFields", () => {
  it("cannot be made ambiguous by moving bytes between fields", () => {
    expect(toB64url(encodeFields("ab", "c"))).not.toBe(toB64url(encodeFields("a", "bc")));
    expect(toB64url(encodeFields("1", 2))).not.toBe(toB64url(encodeFields(1, "2")));
  });
  it("rejects non-u32 numbers", () => {
    expect(() => encodeFields(-1)).toThrow(RangeError);
    expect(() => encodeFields(1.5)).toThrow(RangeError);
  });
});

describe("account key", () => {
  it("round-trips and keeps a stable fingerprint", async () => {
    const ak = generateAccountKey();
    const back = deserializeAccountKey(serializeAccountKey(ak));
    expect(await fingerprint(publicPart(back))).toBe(await fingerprint(publicPart(ak)));
  });

  it("rejects a blob whose halves do not belong together", () => {
    const a = serializeAccountKey(generateAccountKey());
    const b = serializeAccountKey(generateAccountKey());
    a.set(b.subarray(33, 65), 33); // foreign X25519 public half
    expect(() => deserializeAccountKey(a)).toThrow(E2eError);
  });

  it("self-signature is bound to the user id", () => {
    const ak = generateAccountKey();
    const sig = selfSign(ak, OMA);
    expect(verifySelf(publicPart(ak), OMA, sig)).toBe(true);
    expect(verifySelf(publicPart(ak), ENKEL, sig)).toBe(false);
  });

  // ⛔ K-07: strenge Prüfung nach RFC 8032 statt ZIP-215.
  it("accepts our own signatures under strict verification", () => {
    const ak = generateAccountKey();
    expect(verify(ak.edPk, sign(ak.edSk, "fm/test/v1", "x"), "fm/test/v1", "x")).toBe(true);
  });

  it("rejects a small-order public key that would verify anything", () => {
    // Das Einselement (y = 1) als Schlüssel und R = Einselement, S = 0: unter
    // ZIP-215 „gültig“ für JEDE Nachricht.
    const identity = new Uint8Array(32);
    identity[0] = 1;
    const sig = new Uint8Array(64);
    sig.set(identity, 0);
    expect(verify(identity, sig, "fm/test/v1", "beliebig")).toBe(false);
    expect(verify(identity, sig, "fm/test/v1", "etwas anderes")).toBe(false);
  });
});

describe("key envelopes", () => {
  const oma = generateAccountKey();
  const enkel = generateAccountKey();
  const server = generateAccountKey();
  const fmk = generateContentKey();

  const seal = (over: Partial<Parameters<typeof sealEnvelope>[0]> = {}) =>
    sealEnvelope({
      scope: "family",
      scopeId: FAMILY,
      version: 1,
      contentKey: fmk,
      recipient: ENKEL,
      recipientPub: publicPart(enkel),
      sender: OMA,
      senderAk: oma,
      ...over,
    });

  it("delivers the content key to the recipient", async () => {
    const env = await seal();
    const key = await openEnvelope({ envelope: env, me: ENKEL, myAk: enkel, senderPub: publicPart(oma) });
    expect(toB64url(key)).toBe(toB64url(fmk));
  });

  it("A3: a key minted by the server is refused, even though it sealed it correctly to us", async () => {
    // The server knows our public key and can produce a valid HPKE ciphertext.
    // It claims Oma as sender, but cannot sign as Oma.
    const forged = await seal({ contentKey: generateContentKey(), senderAk: server, sender: OMA });
    await rejects(openEnvelope({ envelope: forged, me: ENKEL, myAk: enkel, senderPub: publicPart(oma) }), "signature");
  });

  it("an envelope moved to another version or family is refused", async () => {
    const env = await seal();
    const moved: Envelope = { ...env, version: 2 };
    await rejects(openEnvelope({ envelope: moved, me: ENKEL, myAk: enkel, senderPub: publicPart(oma) }), "signature");
    const other: Envelope = { ...env, scopeId: "22222222-2222-4222-8222-222222222222" };
    await rejects(openEnvelope({ envelope: other, me: ENKEL, myAk: enkel, senderPub: publicPart(oma) }), "signature");
  });

  it("someone else's envelope is refused before any decryption", async () => {
    const env = await seal();
    await rejects(openEnvelope({ envelope: env, me: SERVER, myAk: server, senderPub: publicPart(oma) }), "binding");
    // Re-addressed to the server's user id: the signature covers the recipient.
    const readdressed: Envelope = { ...env, recipient: SERVER };
    await rejects(
      openEnvelope({ envelope: readdressed, me: SERVER, myAk: server, senderPub: publicPart(oma) }),
      "signature",
    );
  });

  it("a flipped ciphertext bit is refused", async () => {
    const env = await seal();
    const ct = new Uint8Array(env.ct);
    ct[0] ^= 1;
    await rejects(
      openEnvelope({ envelope: { ...env, ct }, me: ENKEL, myAk: enkel, senderPub: publicPart(oma) }),
      "signature",
    );
  });
});

describe("encrypted rows", () => {
  const binding = { table: "photos", rowId: "p1", scopeId: FAMILY, keyVersion: 1 };

  it("round-trips content fields", async () => {
    const key = await importAesKey(generateContentKey());
    const blob = await encryptRow(key, binding, { caption: "Oma im Garten", takenAt: "1987-06-01" });
    expect(await decryptRow(key, binding, blob)).toEqual({ caption: "Oma im Garten", takenAt: "1987-06-01" });
  });

  it("a caption pasted onto another row, family or version is refused", async () => {
    const key = await importAesKey(generateContentKey());
    const blob = await encryptRow(key, binding, { caption: "x" });
    await rejects(decryptRow(key, { ...binding, rowId: "p2" }, blob), "decrypt");
    await rejects(decryptRow(key, { ...binding, scopeId: "other" }, blob), "decrypt");
    await rejects(decryptRow(key, { ...binding, keyVersion: 2 }, blob), "decrypt");
    await rejects(decryptRow(key, { ...binding, table: "stories" }, blob), "decrypt");
  });

  it("padding hides short length differences", async () => {
    const key = await importAesKey(generateContentKey());
    const a = await encryptRow(key, binding, { t: "Ja" });
    const b = await encryptRow(key, binding, { t: "Hochzeit von Inge und Karl" });
    expect(a.byteLength).toBe(b.byteLength);
    expect(paddedLength(1)).toBe(64);
    expect(paddedLength(257)).toBe(512);
    expect(paddedLength(5000)).toBe(8192);
  });
});

describe("account key wrapping", () => {
  it("device, passkey and recovery wraps are not interchangeable", async () => {
    const ak = generateAccountKey();
    const dsk = await generateDeviceStorageKey();
    const blob = await wrapAccountKey(dsk, ak, "device", OMA);
    expect(await fingerprint(publicPart(await unwrapAccountKey(dsk, blob, "device", OMA)))).toBe(
      await fingerprint(publicPart(ak)),
    );
    await rejects(unwrapAccountKey(dsk, blob, "recovery", OMA), "decrypt");
    await rejects(unwrapAccountKey(dsk, blob, "device", ENKEL), "decrypt");
  });

  it("passkey wrap key depends on PRF output and credential", async () => {
    const ak = generateAccountKey();
    const prf = randomBytes(32);
    const blob = await wrapAccountKey(await passkeyWrapKey(prf, "cred-1"), ak, "passkey", OMA, "cred-1");
    await unwrapAccountKey(await passkeyWrapKey(prf, "cred-1"), blob, "passkey", OMA, "cred-1");
    await rejects(
      unwrapAccountKey(await passkeyWrapKey(prf, "cred-2"), blob, "passkey", OMA, "cred-1"),
      "decrypt",
    );
    await rejects(
      unwrapAccountKey(await passkeyWrapKey(randomBytes(32), "cred-1"), blob, "passkey", OMA, "cred-1"),
      "decrypt",
    );
  });
});

describe("recovery code", () => {
  it("has the printed shape and parses back", () => {
    const code = generateRecoveryCode();
    expect(code).toMatch(/^([0-9A-HJKMNP-TV-Z]{4}-){5}[0-9A-HJKMNP-TV-Z]{4}$/);
    expect(parseRecoveryCode(code).ok).toBe(true);
  });

  it("forgives case, spaces and O/I/L confusion", () => {
    const code = generateRecoveryCode();
    const sloppy = code.toLowerCase().replace(/-/g, "  ").replace(/0/g, "o").replace(/1/g, "l");
    const parsed = parseRecoveryCode(sloppy);
    expect(parsed).toEqual({ ok: true, canonical: code.replace(/-/g, "") });
  });

  it("reports every single-symbol typo as a typo", () => {
    const canonical = generateRecoveryCode().replace(/-/g, "");
    const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    for (let pos = 0; pos < canonical.length; pos++) {
      for (const ch of alphabet) {
        if (ch === canonical[pos]) continue;
        const typo = canonical.slice(0, pos) + ch + canonical.slice(pos + 1);
        expect(parseRecoveryCode(typo)).toEqual({ ok: false, reason: "typo" });
      }
    }
  });

  it("rejects wrong length and foreign symbols", () => {
    expect(parseRecoveryCode("ABCD")).toEqual({ ok: false, reason: "length" });
    expect(parseRecoveryCode("U".repeat(24))).toEqual({ ok: false, reason: "symbol" });
  });

  it("unwraps the account key only with the right code", async () => {
    const ak = generateAccountKey();
    const code = generateRecoveryCode();
    const salt = newRecoverySalt();
    const blob = await wrapAccountKey(await recoveryWrapKey(code, salt, FAST), ak, "recovery", OMA);
    const back = await unwrapAccountKey(
      await recoveryWrapKey(code.toLowerCase(), salt, FAST),
      blob,
      "recovery",
      OMA,
    );
    expect(await fingerprint(publicPart(back))).toBe(await fingerprint(publicPart(ak)));
    await rejects(
      unwrapAccountKey(await recoveryWrapKey(generateRecoveryCode(), salt, FAST), blob, "recovery", OMA),
      "decrypt",
    );
    await rejects(recoveryWrapKey("nonsense", salt, FAST), "recoveryCode");
  });
});

describe("safety and pairing codes", () => {
  it("safety code is symmetric, 12×5 digits, and changes with the key", async () => {
    const a = { userId: OMA, edPk: generateAccountKey().edPk };
    const b = { userId: ENKEL, edPk: generateAccountKey().edPk };
    const ab = await safetyCode(a, b);
    expect(ab).toEqual(await safetyCode(b, a));
    expect(ab).toHaveLength(12);
    ab.forEach((g) => expect(g).toMatch(/^\d{5}$/));
    expect(ab.join("")).toContain(await safetyCodeHalf(OMA, a.edPk));
    const a2 = { userId: OMA, edPk: generateAccountKey().edPk };
    expect(await safetyCode(a2, b)).not.toEqual(ab);
  });

  it("both devices show the same pairing code; a relay in the middle breaks it", async () => {
    const neu = newEphemeralKeyPair();
    const alt = newEphemeralKeyPair();
    const mitm = newEphemeralKeyPair();
    const nonce = randomBytes(16);
    const onNew = await pairingCode(neu.priv, alt.pub, neu.pub, alt.pub, nonce);
    const onOld = await pairingCode(alt.priv, neu.pub, neu.pub, alt.pub, nonce);
    expect(onNew).toMatch(/^\d{6}$/);
    expect(onNew).toBe(onOld);
    // The old device was shown the attacker's key instead of the new device's.
    const fooled = await pairingCode(alt.priv, mitm.pub, mitm.pub, alt.pub, nonce);
    expect(fooled).not.toBe(onNew);
  });

  it("pairing transfer delivers the account key and trust store, bound to user and nonce", async () => {
    const ak = generateAccountKey();
    const neu = newEphemeralKeyPair();
    const alt = newEphemeralKeyPair();
    const nonce = randomBytes(16);
    const sealed = await sealPairingTransfer({
      ak,
      trust: '{"version":1,"entries":{}}',
      userId: OMA,
      nonce,
      oldDevicePriv: alt.priv,
      newDevicePub: neu.pub,
      oldDevicePub: alt.pub,
    });
    const base = { newDevicePriv: neu.priv, newDevicePub: neu.pub, oldDevicePub: alt.pub, ...sealed };
    const back = await openPairingTransfer({ ...base, userId: OMA, nonce });
    expect(await fingerprint(publicPart(back.ak))).toBe(await fingerprint(publicPart(ak)));
    expect(back.trust).toBe('{"version":1,"entries":{}}');
    await rejects(openPairingTransfer({ ...base, userId: ENKEL, nonce }), "decrypt");
    await rejects(openPairingTransfer({ ...base, userId: OMA, nonce: randomBytes(16) }), "decrypt");
  });

  // K-02 (security review 17.10.2026): the service knows both PUBLIC keys of the
  // pairing row. A transfer it builds without the old device's private key —
  // the one behind the code a human compared — must not open.
  it("K-02: a transfer built only from the public keys in the row is refused", async () => {
    const neu = newEphemeralKeyPair();
    const alt = newEphemeralKeyPair();
    const nonce = randomBytes(16);
    const service = newEphemeralKeyPair(); // whatever the service holds instead of alt.priv
    const forged = await sealPairingTransfer({
      ak: generateAccountKey(),
      trust: null,
      userId: OMA,
      nonce,
      oldDevicePriv: service.priv,
      newDevicePub: neu.pub,
      oldDevicePub: alt.pub,
    });
    await rejects(
      openPairingTransfer({ newDevicePriv: neu.priv, newDevicePub: neu.pub, oldDevicePub: alt.pub, userId: OMA, nonce, ...forged }),
      "decrypt",
    );
  });
});

describe("invitations", () => {
  const inviter = generateAccountKey();
  const inv = {
    scope: "family" as const,
    scopeId: FAMILY,
    invitationId: "inv-1",
    email: "Enkel@Example.org ",
    role: "member",
    expiresAt: "2026-10-18T00:00:00.000Z",
  };

  it("verifies against the inviter, case-insensitively on the email", () => {
    const sig = signInvitation(inviter, inv);
    expect(verifyInvitation(publicPart(inviter), { ...inv, email: "enkel@example.org" }, sig)).toBe(true);
  });

  it("a changed role, family or inviter does not verify", () => {
    const sig = signInvitation(inviter, inv);
    expect(verifyInvitation(publicPart(inviter), { ...inv, role: "owner" }, sig)).toBe(false);
    expect(verifyInvitation(publicPart(inviter), { ...inv, scopeId: "other" }, sig)).toBe(false);
    expect(verifyInvitation(publicPart(generateAccountKey()), inv, sig)).toBe(false);
  });
});

describe("tag blind index", () => {
  it("is stable under normalisation and differs between families", async () => {
    const k1 = await tagIndexKey(generateContentKey());
    const k2 = await tagIndexKey(generateContentKey());
    expect(await tagIndex(k1, "  Urlaub   2019 ")).toBe(await tagIndex(k1, "urlaub 2019"));
    expect(await tagIndex(k1, "Urlaub")).not.toBe(await tagIndex(k2, "Urlaub"));
    expect(await tagIndex(k1, "Urlaub")).toHaveLength(22);
  });
});
