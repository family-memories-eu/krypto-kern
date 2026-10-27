// =============================================================================
// Which shell is this bundle? (Client-App K0, docs/client-app-plan.md)
//
//   web  — the Next deployment: public pages with SSR, the private area as
//          client code, API routes on the same origin, session in cookies.
//   app  — the static export bundled into the Android APK (Capacitor serves it
//          from https://localhost): no server of its own, API routes and links
//          go to the web origin, session in local storage, bearer tokens.
//
// Baked in at build time (NEXT_PUBLIC_*), so dead branches drop out.
// =============================================================================

export const IS_APP_BUILD = process.env.NEXT_PUBLIC_APP_BUILD === "1";

/** Origin of the web deployment — where API routes and shareable links live. */
export function webOrigin(): string {
  const env = process.env.NEXT_PUBLIC_SITE_URL?.replace(/\/+$/, "");
  if (IS_APP_BUILD) return env || "https://family-memories.eu";
  if (typeof window !== "undefined") return window.location.origin;
  return env || "https://family-memories.eu";
}
