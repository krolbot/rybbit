import { describe, expect, it } from "vitest";
import { getOIDCProvider } from "./oidc.js";

const completeEnv = {
  OIDC_CLIENT_ID: "rybbit",
  OIDC_CLIENT_SECRET: "secret",
  OIDC_DISCOVERY_URL: "https://auth.example.com/.well-known/openid-configuration",
  OIDC_PROVIDER_NAME: "Example SSO",
};

describe("getOIDCProvider", () => {
  it("returns null when OIDC is not configured", () => {
    expect(getOIDCProvider({})).toBeNull();
    expect(
      getOIDCProvider({
        OIDC_PROVIDER_NAME: "OpenID Connect",
        OIDC_PKCE: "true",
        OIDC_DISABLE_SIGNUP: "true",
      })
    ).toBeNull();
  });

  it("builds a verified OIDC provider with secure defaults", () => {
    expect(getOIDCProvider(completeEnv)).toMatchObject({
      providerId: "oidc",
      name: "Example SSO",
      clientId: "rybbit",
      clientSecret: "secret",
      discoveryUrl: completeEnv.OIDC_DISCOVERY_URL,
      scopes: ["openid", "profile", "email"],
      requireIdTokenVerification: true,
      tokenEndpointAuth: { method: "client_secret_basic" },
      pkce: true,
      disableSignUp: true,
    });
  });

  it("allows an explicit provider compatibility override", () => {
    expect(
      getOIDCProvider({
        ...completeEnv,
        OIDC_PKCE: "false",
        OIDC_DISABLE_SIGNUP: "false",
      })
    ).toMatchObject({ pkce: false, disableSignUp: false });
  });

  it("rejects partial, insecure, and malformed configuration", () => {
    expect(() => getOIDCProvider({ OIDC_CLIENT_ID: "rybbit" })).toThrow(/is required/);
    expect(() =>
      getOIDCProvider({
        ...completeEnv,
        OIDC_DISCOVERY_URL: "http://auth.example.com/.well-known/openid-configuration",
      })
    ).toThrow(/HTTPS/);
    expect(() => getOIDCProvider({ ...completeEnv, OIDC_DISCOVERY_URL: "not a URL" })).toThrow(/valid absolute URL/);
    expect(() => getOIDCProvider({ ...completeEnv, OIDC_PKCE: "sometimes" })).toThrow(/OIDC_PKCE/);
  });
});
