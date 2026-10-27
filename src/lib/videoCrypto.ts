// =============================================================================
// Chunked, authenticated video encryption (browser + Node-testable).
//
// WHY A SECOND FORMAT: photos/audio go through lib/crypto's whole-file
// `encryptBlob` — fine for small blobs. Videos are large: reading the whole file
// into memory to encrypt (and again to decrypt for playback) spikes the tab's
// working set (a ~150 MB clip → ~450 MB peak, OOM risk on phones). This module
// encrypts a video in FIXED-SIZE chunks so the peak heap is ~one chunk, and — the
// point of the fixed size — the ciphertext is RANDOM-ACCESS: any plaintext byte
// range maps to a computable ciphertext byte range, which lets the service worker
// serve HTTP Range requests (seek/stream) without downloading the whole file.
//
// CONTAINER FORMAT "FMV2" (all integers big-endian):
//
//   Header (cleartext):
//     magic[4] = 'F','M','V','2'
//     version  u8
//     streamId 16B   (random per object — defeats cross-file chunk splicing)
//     chunkPlainSize u32   (FIXED across all but the last chunk)
//     totalChunks    u32
//     plainTotalBytes u64  (the real video length → Content-Length for playback)
//     mimeLen  u16
//     mime     UTF-8[mimeLen]   (container type, e.g. "video/mp4")
//   Then, for chunk i in [0, totalChunks):
//     iv  12B                 (fresh random 96-bit GCM nonce, never reused)
//     ct  (plainLen_i + 16)B  (AES-256-GCM ciphertext WITH its 128-bit tag)
//   plainLen_i = min(chunkPlainSize, plainTotalBytes - i*chunkPlainSize), so every
//   chunk's byte length is DERIVABLE from the header — no per-chunk length prefix,
//   hence O(1) seek to any chunk.
//
// SECURITY (AEAD per chunk, AES-256-GCM):
//   * additionalData (AAD) = <entire header bytes> || u32(chunkIndex). Binding the
//     whole header authenticates every header field (mime, sizes, counts, streamId):
//     flip any header byte and every chunk's tag fails. Binding the index defeats
//     REORDERING; the random streamId (inside the header) defeats SPLICING chunks
//     from a different object; and decrypting exactly `totalChunks` chunks defeats
//     TRUNCATION (a dropped tail leaves fewer chunks than the header promises).
//   * A fresh 96-bit random IV per chunk — never reused under the family media key.
//   * MIME lives in the header (not prepended to the plaintext) so plaintext byte i
//     == real video byte i: the service worker can hand raw container bytes to the
//     <video> element for any range with no offset gymnastics.
//
// WebCrypto (SubtleCrypto) only — no third-party crypto lib, same stance as
// lib/crypto.ts. Pure w.r.t. the DOM (uses only crypto/TextEncoder/DataView/Blob),
// so the format logic is unit-testable headless under Node's WebCrypto.
//
// NOTE: src/sw/sw.js reimplements the Range decrypt in plain JS (it can't import
// this TS module). Keep the FMV2 layout + AAD rule below in sync with that copy.
// =============================================================================

import { CryptoError } from "@/lib/crypto";
import { chunkAllowed } from "@/lib/e2e/objBinding";
import { safeFmvMime } from "@/lib/mediaMime";

const MAGIC = new Uint8Array([0x46, 0x4d, 0x56, 0x32]); // 'F','M','V','2'
const VERSION = 1;
const IV_BYTES = 12; // 96-bit GCM nonce (the size AES-GCM is defined for)
const TAG_BYTES = 16; // 128-bit GCM auth tag (appended to ciphertext by WebCrypto)
const STREAM_ID_BYTES = 16;
const ALGO = "AES-GCM";

// Fixed plaintext chunk size. FIXED is load-bearing: it makes cipher offsets a
// closed-form function of the chunk index (see cipherChunkStart), which is what
// enables Range/seek playback. 1 MiB balances seek granularity vs. per-chunk
// overhead (28 B/chunk → ~4 KB over a 150 MB clip).
export const VIDEO_CHUNK_PLAIN_SIZE = 1 << 20; // 1 MiB

// The fixed part of the header (everything before the variable-length mime).
const HEADER_FIXED_LEN = 4 + 1 + STREAM_ID_BYTES + 4 + 4 + 8 + 2; // = 39
// Upper bound we probe when reading a header off the front of an object. Real
// container MIME strings are well under this; guarded in parseVideoHeader.
export const VIDEO_HEADER_PROBE_BYTES = 1024;

export type VideoHeader = {
  version: number;
  streamId: Uint8Array;
  chunkPlainSize: number;
  totalChunks: number;
  plainTotalBytes: number;
  mime: string;
  // Byte length of the header itself (offset of the first chunk).
  headerLen: number;
  // Exact header bytes — reused verbatim as the AAD base so encrypt/decrypt agree.
  headerBytes: Uint8Array;
};

function subtle(): SubtleCrypto {
  const s = globalThis.crypto?.subtle;
  if (!s) throw new CryptoError("errorCryptoUnavailable");
  return s;
}

// AAD for chunk i = header bytes || u32(i). See the security note above.
function aadFor(headerBytes: Uint8Array, index: number): Uint8Array<ArrayBuffer> {
  const aad = new Uint8Array(headerBytes.length + 4);
  aad.set(headerBytes, 0);
  new DataView(aad.buffer).setUint32(headerBytes.length, index, false);
  return aad;
}

// -----------------------------------------------------------------------------
// Cipher-offset math (pure) — the closed form that fixed chunks buy us. Used by
// the whole-file decrypt below and by the service-worker Range handler.
// -----------------------------------------------------------------------------

// Plaintext length of chunk i (the last chunk is short).
export function plainChunkLen(h: VideoHeader, i: number): number {
  const start = i * h.chunkPlainSize;
  return Math.max(0, Math.min(h.chunkPlainSize, h.plainTotalBytes - start));
}

// Ciphertext byte length of chunk i = iv + (plain + tag).
export function cipherChunkLen(h: VideoHeader, i: number): number {
  return IV_BYTES + plainChunkLen(h, i) + TAG_BYTES;
}

// Byte offset of chunk i within the object. Because every earlier chunk has a
// derivable length, this is closed-form (all full chunks except a possible last).
export function cipherChunkStart(h: VideoHeader, i: number): number {
  return h.headerLen + i * (IV_BYTES + h.chunkPlainSize + TAG_BYTES);
}

// -----------------------------------------------------------------------------
// Encrypt.
// -----------------------------------------------------------------------------

// Shared plan for encrypting a source of `plainTotalBytes` with container `mime`:
// the cleartext header (which doubles as the AAD base) plus the derived counts.
// Both the whole-Blob encryptor and the streaming encryptor build from this, so
// the on-wire FMV2 layout is defined in exactly one place.
type EncryptPlan = {
  header: Uint8Array<ArrayBuffer>;
  totalChunks: number;
  chunkPlainSize: number;
  plainTotalBytes: number;
};

function buildEncryptPlan(mime: string, plainTotalBytes: number): EncryptPlan {
  const mimeBytes = new TextEncoder().encode(mime);
  const chunkPlainSize = VIDEO_CHUNK_PLAIN_SIZE;
  const totalChunks = Math.max(1, Math.ceil(plainTotalBytes / chunkPlainSize));
  const streamId = globalThis.crypto.getRandomValues(new Uint8Array(STREAM_ID_BYTES));

  const headerLen = HEADER_FIXED_LEN + mimeBytes.length;
  const header = new Uint8Array(headerLen);
  const dv = new DataView(header.buffer);
  let o = 0;
  header.set(MAGIC, o); o += 4;
  dv.setUint8(o, VERSION); o += 1;
  header.set(streamId, o); o += STREAM_ID_BYTES;
  dv.setUint32(o, chunkPlainSize, false); o += 4;
  dv.setUint32(o, totalChunks, false); o += 4;
  dv.setBigUint64(o, BigInt(plainTotalBytes), false); o += 8;
  dv.setUint16(o, mimeBytes.length, false); o += 2;
  header.set(mimeBytes, o); o += mimeBytes.length;

  return { header, totalChunks, chunkPlainSize, plainTotalBytes };
}

// Encrypt + append one FMV2 chunk. Returns `iv || ciphertext+tag` for chunk `i`.
async function encryptOneChunk(
  key: CryptoKey,
  plan: EncryptPlan,
  file: Blob,
  i: number,
): Promise<Uint8Array<ArrayBuffer>> {
  const start = i * plan.chunkPlainSize;
  const end = Math.min(start + plan.chunkPlainSize, plan.plainTotalBytes);
  return sealChunk(key, plan, new Uint8Array(await file.slice(start, end).arrayBuffer()), i);
}

// Seal chunk `i` from its plaintext bytes: `iv || ciphertext+tag`.
async function sealChunk(
  key: CryptoKey,
  plan: EncryptPlan,
  plain: Uint8Array<ArrayBuffer>,
  i: number,
): Promise<Uint8Array<ArrayBuffer>> {
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const ct = new Uint8Array(
    await subtle().encrypt({ name: ALGO, iv, additionalData: aadFor(plan.header, i) }, key, plain),
  );
  const out = new Uint8Array(iv.length + ct.length);
  out.set(iv, 0);
  out.set(ct, iv.length);
  return out;
}

// Exact byte length an FMV2 object will have for `plainTotalBytes` + `mime`.
// Deterministic (fixed IV+tag per chunk, fixed chunk size), so a STREAMING upload
// can declare its total size up front without materialising the ciphertext. Must
// stay in lock-step with the layout in buildEncryptPlan / encryptOneChunk.
export function computeCipherSize(plainTotalBytes: number, mime: string): number {
  const mimeBytes = new TextEncoder().encode(mime || "video/mp4");
  const headerLen = HEADER_FIXED_LEN + mimeBytes.length;
  const totalChunks = Math.max(1, Math.ceil(plainTotalBytes / VIDEO_CHUNK_PLAIN_SIZE));
  return headerLen + totalChunks * (IV_BYTES + TAG_BYTES) + plainTotalBytes;
}

// Encrypt a video Blob/File into an FMV2 ciphertext Blob. Reads the source one
// chunk at a time (file.slice) and accumulates ENCRYPTED chunks as Blob parts, so
// the browser can spill them to its (disk-backed) blob store instead of the JS
// heap: peak heap ≈ one plaintext chunk + one ciphertext chunk. `onProgress`
// receives 0..1 as chunks complete.
export async function encryptVideoChunked(
  key: CryptoKey,
  file: Blob,
  onProgress?: (fraction: number) => void,
  // Aborts the encrypt loop between chunks (wasted work ≤ one chunk). Used when
  // the user applies a trim mid-upload and we replace the clip.
  signal?: AbortSignal,
): Promise<Blob> {
  const plan = buildEncryptPlan(safeFmvMime(file.type, "video/mp4"), file.size);
  const parts: BlobPart[] = [plan.header];
  for (let i = 0; i < plan.totalChunks; i++) {
    // Cheap per-chunk abort checkpoint (throws AbortError).
    signal?.throwIfAborted();
    parts.push(await encryptOneChunk(key, plan, file, i));
    onProgress?.((i + 1) / plan.totalChunks);
  }
  return new Blob(parts, { type: "application/octet-stream" });
}

// Streaming FMV2 encryptor: instead of materialising the whole ciphertext Blob
// up front (the old serial "encrypt everything, THEN upload" pass), it hands back
// a ReadableStream that encrypts ONE chunk per pull. Fed to the resumable upload
// (lib/tusUpload) this lets encryption and network transfer OVERLAP — the upload's
// read cadence drives encryption, backpressure keeps peak heap ≈ one chunk, and
// (crucially) the byte count is known in advance via computeCipherSize so tus can
// declare `uploadSize` even though the source is a stream. The stream can be
// produced on the main thread OR inside a worker and transferred (see
// lib/media/videoEncryptSource) — the format is identical either way.
export function encryptVideoChunkedStream(
  key: CryptoKey,
  file: Blob,
): { stream: ReadableStream<Uint8Array>; uploadSize: number; mime: string } {
  // X-03: what goes into the header is already a media type (or, for shared
  // photos, a raster image — safeFmvMime).
  const mime = safeFmvMime(file.type, "video/mp4");
  const plan = buildEncryptPlan(mime, file.size);
  let i = 0;
  let headerSent = false;

  const stream = new ReadableStream<Uint8Array>({
    // Default (count-based) queuing strategy → highWaterMark 1: at most one chunk
    // is encrypted ahead of what the consumer has taken. That IS the backpressure.
    async pull(controller) {
      if (!headerSent) {
        controller.enqueue(plan.header);
        headerSent = true;
        return;
      }
      if (i >= plan.totalChunks) {
        controller.close();
        return;
      }
      controller.enqueue(await encryptOneChunk(key, plan, file, i));
      i += 1;
    },
  });

  return { stream, uploadSize: computeCipherSize(file.size, mime), mime };
}

// Re-key an FMV2 object WITHOUT ever holding it (E2E Etappe 3 · E3.4, shared
// download links): chunk i is fetched as a byte range of the source, opened
// with the source key and sealed again under `dstKey` into a fresh FMV2 object
// with the same MIME and length (new streamId, new IVs). Like
// encryptVideoChunkedStream the result is a pull stream with a size known up
// front, ready for the resumable upload. `chunksPerFetch` source chunks are
// fetched per request, so a 500 MB clip is not 500 round trips.
export function reencryptVideoChunkedStream(
  srcKey: CryptoKey,
  src: VideoHeader,
  fetchCipher: (start: number, endExclusive: number) => Promise<Uint8Array<ArrayBuffer>>,
  dstKey: CryptoKey,
  chunksPerFetch = 8,
): { stream: ReadableStream<Uint8Array>; uploadSize: number; mime: string } {
  // The plaintext must split into the same chunks on both sides; every object
  // this app ever wrote uses the one fixed size.
  if (src.chunkPlainSize !== VIDEO_CHUNK_PLAIN_SIZE) throw new CryptoError("errorDecrypt");
  const plan = buildEncryptPlan(src.mime, src.plainTotalBytes);
  let i = 0;
  let headerSent = false;
  let buffered: { first: number; chunks: Uint8Array<ArrayBuffer>[] } = { first: 0, chunks: [] };

  async function cipherChunk(index: number): Promise<Uint8Array<ArrayBuffer>> {
    const at = index - buffered.first;
    if (at >= 0 && at < buffered.chunks.length) return buffered.chunks[at];
    const last = Math.min(index + chunksPerFetch, src.totalChunks) - 1;
    const start = cipherChunkStart(src, index);
    const bytes = await fetchCipher(start, cipherChunkStart(src, last) + cipherChunkLen(src, last));
    const chunks: Uint8Array<ArrayBuffer>[] = [];
    for (let c = index; c <= last; c++) {
      const from = cipherChunkStart(src, c) - start;
      const piece = bytes.slice(from, from + cipherChunkLen(src, c));
      if (piece.length !== cipherChunkLen(src, c)) throw new CryptoError("errorDecrypt");
      chunks.push(piece);
    }
    buffered = { first: index, chunks };
    return chunks[0];
  }

  const stream = new ReadableStream<Uint8Array>({
    async pull(controller) {
      if (!headerSent) {
        controller.enqueue(plan.header);
        headerSent = true;
        return;
      }
      if (i >= src.totalChunks) {
        controller.close();
        return;
      }
      const plain = await decryptChunk(srcKey, src, i, await cipherChunk(i));
      controller.enqueue(await sealChunk(dstKey, plan, plain, i));
      i += 1;
    },
  });

  return { stream, uploadSize: computeCipherSize(src.plainTotalBytes, src.mime), mime: src.mime };
}

// -----------------------------------------------------------------------------
// Parse / detect.
// -----------------------------------------------------------------------------

// True if `bytes` (the front of an object) starts with the FMV2 magic. Lets the
// read path distinguish a chunked object from a legacy whole-file `.enc`.
export function isChunkedVideo(bytes: Uint8Array): boolean {
  if (bytes.length < MAGIC.length) return false;
  for (let i = 0; i < MAGIC.length; i++) if (bytes[i] !== MAGIC[i]) return false;
  return true;
}

// Parse an FMV2 header from the front bytes of an object. `bytes` must contain at
// least the full header (probe VIDEO_HEADER_PROBE_BYTES). Throws errorDecrypt on
// a bad magic / unknown version / short buffer.
export function parseVideoHeader(bytes: Uint8Array): VideoHeader {
  if (bytes.length < HEADER_FIXED_LEN || !isChunkedVideo(bytes)) {
    throw new CryptoError("errorDecrypt");
  }
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let o = 4;
  const version = dv.getUint8(o); o += 1;
  // A version this reader does not know is refused, never read as v1
  // (AP-Zeilen v2, finding 8): the layout below is only defined for VERSION.
  if (version !== VERSION) throw new CryptoError("errorDecrypt");
  const streamId = bytes.slice(o, o + STREAM_ID_BYTES); o += STREAM_ID_BYTES;
  const chunkPlainSize = dv.getUint32(o, false); o += 4;
  const totalChunks = dv.getUint32(o, false); o += 4;
  const plainTotalBytes = Number(dv.getBigUint64(o, false)); o += 8;
  const mimeLen = dv.getUint16(o, false); o += 2;
  if (bytes.length < o + mimeLen || chunkPlainSize <= 0) {
    throw new CryptoError("errorDecrypt");
  }
  // The header is authenticated only through the chunks' AAD — a header that
  // claims zero chunks would never be checked and open as an empty file (K-04,
  // security review 17.10.2026). Every writer makes max(1, ⌈total / size⌉).
  if (
    !Number.isSafeInteger(plainTotalBytes) ||
    totalChunks !== Math.max(1, Math.ceil(plainTotalBytes / chunkPlainSize))
  ) {
    throw new CryptoError("errorDecrypt");
  }
  const mime = new TextDecoder().decode(bytes.subarray(o, o + mimeLen)); o += mimeLen;
  const headerLen = o;
  return {
    version,
    streamId,
    chunkPlainSize,
    totalChunks,
    plainTotalBytes,
    mime,
    headerLen,
    headerBytes: bytes.slice(0, headerLen),
  };
}

// -----------------------------------------------------------------------------
// Decrypt one chunk (shared by whole-file + range paths).
// -----------------------------------------------------------------------------

// Decrypt chunk i given its raw bytes (iv || ciphertext+tag). Throws errorDecrypt
// if the GCM tag fails (wrong key, tampered bytes, or a reordered/spliced chunk,
// since the index + streamId are bound into the AAD).
export async function decryptChunk(
  key: CryptoKey,
  h: VideoHeader,
  index: number,
  cipherChunk: Uint8Array<ArrayBuffer>,
): Promise<Uint8Array<ArrayBuffer>> {
  // K-03: a chunk of a bound video must be the one its checked block list names.
  if (!(await chunkAllowed(key, h.headerBytes, index, cipherChunk))) throw new CryptoError("errorDecrypt");
  const iv = cipherChunk.subarray(0, IV_BYTES);
  const ct = cipherChunk.subarray(IV_BYTES);
  try {
    return new Uint8Array(
      await subtle().decrypt({ name: ALGO, iv, additionalData: aadFor(h.headerBytes, index) }, key, ct),
    );
  } catch {
    throw new CryptoError("errorDecrypt");
  }
}

// -----------------------------------------------------------------------------
// Whole-file decrypt (download + playback fallback).
// -----------------------------------------------------------------------------

// Decrypt an entire FMV2 object back to a playable Blob tagged with its real MIME.
// Slices the source Blob chunk-by-chunk (peak heap ≈ one chunk) and collects the
// decrypted plaintext as Blob parts (disk-spillable), so even the fallback path
// is far lighter than the old whole-file decrypt.
export async function decryptVideoChunked(key: CryptoKey, cipher: Blob): Promise<Blob> {
  const probeLen = Math.min(VIDEO_HEADER_PROBE_BYTES, cipher.size);
  const h = parseVideoHeader(new Uint8Array(await cipher.slice(0, probeLen).arrayBuffer()));
  const parts: BlobPart[] = [];
  let off = h.headerLen;
  for (let i = 0; i < h.totalChunks; i++) {
    const len = cipherChunkLen(h, i);
    const cc = new Uint8Array(await cipher.slice(off, off + len).arrayBuffer());
    off += len;
    parts.push(await decryptChunk(key, h, i, cc));
  }
  return new Blob(parts, { type: safeFmvMime(h.mime, "video/mp4") });
}

// -----------------------------------------------------------------------------
// Range decrypt (service-worker seek/stream). Pure over a byte-range fetcher so
// it's unit-testable headless and mirrors the plain-JS copy in src/sw/sw.js.
// -----------------------------------------------------------------------------

// Return decrypted plaintext (real video bytes) for [plainStart, plainEnd). Only
// the chunks covering that range are fetched + decrypted, so a mid-clip seek
// touches ~one chunk, never the whole file. `fetchCipher(start, endExclusive)`
// returns the object's ciphertext bytes for a half-open byte range.
export async function decryptPlainRange(
  key: CryptoKey,
  h: VideoHeader,
  fetchCipher: (start: number, endExclusive: number) => Promise<Uint8Array<ArrayBuffer>>,
  plainStart: number,
  plainEnd: number,
): Promise<Uint8Array<ArrayBuffer>> {
  const clampedEnd = Math.min(plainEnd, h.plainTotalBytes);
  if (clampedEnd <= plainStart) return new Uint8Array(0);

  const firstChunk = Math.floor(plainStart / h.chunkPlainSize);
  const lastChunk = Math.floor((clampedEnd - 1) / h.chunkPlainSize);

  const decrypted: Uint8Array[] = [];
  let joinedLen = 0;
  for (let i = firstChunk; i <= lastChunk; i++) {
    const cs = cipherChunkStart(h, i);
    const cc = await fetchCipher(cs, cs + cipherChunkLen(h, i));
    const plain = await decryptChunk(key, h, i, cc);
    decrypted.push(plain);
    joinedLen += plain.length;
  }

  const joined = new Uint8Array(joinedLen);
  let p = 0;
  for (const part of decrypted) { joined.set(part, p); p += part.length; }

  const sliceStart = plainStart - firstChunk * h.chunkPlainSize;
  return joined.subarray(sliceStart, sliceStart + (clampedEnd - plainStart));
}
