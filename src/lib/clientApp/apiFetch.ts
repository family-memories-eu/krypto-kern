// =============================================================================
// Calling our own API routes from client code, in both shells (Client-App K0):
//   web — same origin, relative URL, the session cookie goes along.
//   app — absolute URL to the web origin, `Authorization: Bearer <access token>`
//         (the routes accept that only from the app origin, see
//         src/lib/api/requestAuth.ts), never cookies.
// =============================================================================

import type { SupabaseClient } from "@supabase/supabase-js";

import { MAINTENANCE_EVENT } from "./maintenanceSignal";
import { IS_APP_BUILD, webOrigin } from "./buildTarget";

export function apiUrl(path: string, app = IS_APP_BUILD): string {
  if (!path.startsWith("/api/")) throw new Error(`apiUrl: not an API path: ${path}`);
  return app ? `${webOrigin()}${path}` : path;
}

export async function apiFetch(
  supabase: SupabaseClient,
  path: string,
  init: RequestInit = {},
  app = IS_APP_BUILD,
): Promise<Response> {
  const headers = new Headers(init.headers);
  if (app) {
    const { data } = await supabase.auth.getSession();
    const token = data.session?.access_token;
    if (token) headers.set("authorization", `Bearer ${token}`);
  }
  const res = await fetch(apiUrl(path, app), {
    ...init,
    headers,
    credentials: app ? "omit" : "same-origin",
  });
  // The middleware closes /api/* with 503 during maintenance. Tell the app
  // shell at once instead of waiting for its next look (appStatus.ts).
  if (res.status === 503 && typeof window !== "undefined") {
    window.dispatchEvent(new Event(MAINTENANCE_EVENT));
  }
  return res;
}
