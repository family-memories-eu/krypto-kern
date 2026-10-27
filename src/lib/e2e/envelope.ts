// =============================================================================
// Key envelopes (docs/e2e-design.md §4.2). A content key (family / story /
// avatar, 32 bytes) sealed to ONE person's account key with HPKE and signed by
// the sender's Ed25519 key.
//
// Two separate bindings, both necessary:
//   * HPKE `info` binds the ciphertext to scope / id / version / recipient, so
//     the server cannot move an envelope to another family or version.
//   * The signature binds it to a SENDER the recipient already trusts, so the
//     server cannot mint its own family key and seal it to us (design A3) — it
//     knows our public key, so HPKE alone would not stop that.
// =============================================================================

import { E2eError, encodeFields, type Bytes } from "./bytes";
import { hpkeOpen, hpkeSeal } from "./hpke";
import { sign, verify, type AccountKey, type PublicAccountKey } from "./identity";

export type KeyScope = "family" | "story" | "avatar";

export type Envelope = {
  scope: KeyScope;
  scopeId: string;
  version: number;
  recipient: string;
  enc: Bytes;
  ct: Bytes;
  sender: string;
  sig: Bytes;
};

type EnvelopeMeta = Pick<Envelope, "scope" | "scopeId" | "version" | "recipient">;

const CTX_INFO = "fm/env/v1";
const CTX_SIG = "fm/env-sig/v1";
const CONTENT_KEY_BYTES = 32;

function info(e: EnvelopeMeta, recipientPub: Uint8Array): Bytes {
  return encodeFields(CTX_INFO, e.scope, e.scopeId, e.version, e.recipient, recipientPub);
}

function signedFields(e: Omit<Envelope, "sig">, recipientPub: Uint8Array) {
  return [e.scope, e.scopeId, e.version, e.recipient, recipientPub, e.sender, e.enc, e.ct] as const;
}

export async function sealEnvelope(args: {
  scope: KeyScope;
  scopeId: string;
  version: number;
  contentKey: Uint8Array;
  recipient: string;
  recipientPub: PublicAccountKey;
  sender: string;
  senderAk: AccountKey;
}): Promise<Envelope> {
  if (args.contentKey.byteLength !== CONTENT_KEY_BYTES) throw new E2eError("format");
  const meta: EnvelopeMeta = {
    scope: args.scope,
    scopeId: args.scopeId,
    version: args.version,
    recipient: args.recipient,
  };
  const { enc, ct } = await hpkeSeal(
    args.recipientPub.x25519Pub,
    info(meta, args.recipientPub.x25519Pub),
    args.contentKey,
  );
  const unsigned = { ...meta, enc, ct, sender: args.sender };
  const sig = sign(args.senderAk.edSk, CTX_SIG, ...signedFields(unsigned, args.recipientPub.x25519Pub));
  return { ...unsigned, sig };
}

/**
 * Open an envelope addressed to us. `senderPub` MUST come from the local trust
 * store (design §5.4), never from the server row next to the envelope.
 */
export async function openEnvelope(args: {
  envelope: Envelope;
  me: string;
  myAk: AccountKey;
  senderPub: PublicAccountKey;
}): Promise<Bytes> {
  const e = args.envelope;
  if (e.recipient !== args.me) throw new E2eError("binding");
  if (!verify(args.senderPub.edPk, e.sig, CTX_SIG, ...signedFields(e, args.myAk.x25519Pub))) {
    throw new E2eError("signature");
  }
  const pt = await hpkeOpen(args.myAk.x25519Priv, e.enc, info(e, args.myAk.x25519Pub), e.ct);
  if (pt.byteLength !== CONTENT_KEY_BYTES) throw new E2eError("format");
  return pt;
}

/**
 * Whether `senderPub` sealed this envelope for exactly this recipient key —
 * without opening it (P1-2: proof that someone held a version). The signature
 * covers scope, version, recipient, the recipient's key, sender and ciphertext,
 * so a server can leave such a proof out but neither forge nor relabel it.
 */
export function envelopeSignedBy(e: Envelope, recipientX25519Pub: Uint8Array, senderPub: PublicAccountKey): boolean {
  return verify(senderPub.edPk, e.sig, CTX_SIG, ...signedFields(e, recipientX25519Pub));
}

/** A fresh 32-byte content key (family / story / avatar / link). */
export function generateContentKey(): Bytes {
  return globalThis.crypto.getRandomValues(new Uint8Array(CONTENT_KEY_BYTES));
}
