import { afterEach, describe, expect, it, vi } from "vitest";

// AP-Android (A2): the app offers no passkeys — its WebView origin is
// https://localhost, so a passkey would be bound to "localhost". The same
// browser environment says yes on the web build and no in the app build.

async function supportedWith(appBuild: string | undefined): Promise<boolean> {
  vi.resetModules();
  vi.stubEnv("NEXT_PUBLIC_APP_BUILD", appBuild ?? "");
  vi.stubGlobal("window", { PublicKeyCredential: function PublicKeyCredential() {} });
  vi.stubGlobal("PublicKeyCredential", function PublicKeyCredential() {});
  vi.stubGlobal("navigator", { credentials: {} });
  const { passkeySupported } = await import("./vault");
  return passkeySupported();
}

describe("passkeys in the Android app", () => {
  afterEach(() => {
    vi.unstubAllEnvs();
    vi.unstubAllGlobals();
  });

  it("are offered on the web, never in the app", async () => {
    expect(await supportedWith(undefined)).toBe(true);
    expect(await supportedWith("1")).toBe(false);
  });
});
