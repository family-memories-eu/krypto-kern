// X-03 (interne Prüfung, P5): The MIME of an encrypted video or recording is
// written into its header by whoever UPLOADED it. Turned into a Blob or a
// response as-is, "text/html" with a script inside would open as a same-origin
// page. So a decrypted medium only ever gets a video/audio type — anything else
// becomes application/octet-stream, which no browser renders. The service
// worker (src/sw/sw.js, plain JS) carries the same rule.
const MEDIA_MIME = /^(video|audio)\/[a-z0-9.+-]+$/i;

/** `mime` if it is a plain video/audio type, `fallback` if empty, else application/octet-stream. */
export function safeMediaMime(mime: string | null | undefined, fallback: string): string {
  if (!mime) return fallback;
  return MEDIA_MIME.test(mime) ? mime.toLowerCase() : "application/octet-stream";
}

// FMV2 objects (lib/videoCrypto.ts) carry videos AND — in shared downloads
// (lib/download/shareCrypto.ts) — photos. So their header may also name a
// raster image type. Never SVG: an SVG is a document that can hold script.
const FMV_MIME = /^(?:(?:video|audio)\/[a-z0-9.+-]+|image\/(?:jpeg|png|webp|gif|heic|heif|avif))$/i;

/** Like safeMediaMime, for FMV2 objects: video/audio or a raster image. */
export function safeFmvMime(mime: string | null | undefined, fallback: string): string {
  if (!mime) return fallback;
  return FMV_MIME.test(mime) ? mime.toLowerCase() : "application/octet-stream";
}
