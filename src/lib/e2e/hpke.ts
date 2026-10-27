// =============================================================================
// The single HPKE suite of the end-to-end layer (docs/e2e-design.md §4.1):
// RFC 9180 base mode, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM.
// The X25519 KEM is the pure-JS one from @hpke/dhkem-x25519, so it works on
// browsers without X25519 in WebCrypto (older iPads).
// =============================================================================

import { Aes256Gcm, CipherSuite } from "@hpke/core";
import { DhkemX25519HkdfSha256, HkdfSha256 } from "@hpke/dhkem-x25519";

import { E2eError, own, type Bytes } from "./bytes";

let suite: CipherSuite | null = null;
function hpke(): CipherSuite {
  suite ??= new CipherSuite({
    kem: new DhkemX25519HkdfSha256(),
    kdf: new HkdfSha256(),
    aead: new Aes256Gcm(),
  });
  return suite;
}

export async function hpkeSeal(
  recipientX25519Pub: Uint8Array,
  info: Uint8Array,
  pt: Uint8Array,
): Promise<{ enc: Bytes; ct: Bytes }> {
  const s = hpke();
  const { enc, ct } = await s.seal(
    { recipientPublicKey: await s.kem.deserializePublicKey(own(recipientX25519Pub)), info: own(info) },
    own(pt),
  );
  return { enc: own(enc), ct: own(ct) };
}

export async function hpkeOpen(
  recipientX25519Priv: Uint8Array,
  enc: Uint8Array,
  info: Uint8Array,
  ct: Uint8Array,
): Promise<Bytes> {
  const s = hpke();
  try {
    const pt = await s.open(
      {
        recipientKey: await s.kem.deserializePrivateKey(own(recipientX25519Priv)),
        enc: own(enc),
        info: own(info),
      },
      own(ct),
    );
    return own(pt);
  } catch {
    throw new E2eError("decrypt");
  }
}
