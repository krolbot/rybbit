import type { GenericOAuthConfig } from "better-auth/plugins/generic-oauth";

const OIDC_REQUIRED_KEYS = ["OIDC_CLIENT_ID", "OIDC_CLIENT_SECRET", "OIDC_DISCOVERY_URL"] as const;

const OIDC_KEYS = [
  "OIDC_CLIENT_ID",
  "OIDC_CLIENT_SECRET",
  "OIDC_DISCOVERY_URL",
  "OIDC_PROVIDER_NAME",
  "OIDC_PKCE",
  "OIDC_DISABLE_SIGNUP",
] as const;

type Env = Record<string, string | undefined>;

function required(env: Env, key: (typeof OIDC_KEYS)[number]): string {
  const value = env[key];
  if (!value?.trim()) throw new Error(`${key} is required when OIDC is configured`);
  return value;
}

function boolean(env: Env, key: "OIDC_PKCE" | "OIDC_DISABLE_SIGNUP", defaultValue: boolean): boolean {
  const value = env[key]?.trim().toLowerCase();
  if (!value) return defaultValue;
  if (value === "true") return true;
  if (value === "false") return false;
  throw new Error(`${key} must be true or false`);
}

export function getOIDCProvider(env: Env = process.env): GenericOAuthConfig<"oidc"> | null {
  if (!OIDC_REQUIRED_KEYS.some(key => env[key]?.trim())) return null;

  const discoveryUrl = required(env, "OIDC_DISCOVERY_URL");
  let discovery: URL;
  try {
    discovery = new URL(discoveryUrl);
  } catch {
    throw new Error("OIDC_DISCOVERY_URL must be a valid absolute URL");
  }
  if (discovery.protocol !== "https:") throw new Error("OIDC_DISCOVERY_URL must use HTTPS");
  if (discovery.username || discovery.password) throw new Error("OIDC_DISCOVERY_URL must not contain credentials");

  return {
    providerId: "oidc",
    name: env.OIDC_PROVIDER_NAME?.trim() || "OpenID Connect",
    clientId: required(env, "OIDC_CLIENT_ID"),
    clientSecret: required(env, "OIDC_CLIENT_SECRET"),
    discoveryUrl: discovery.toString(),
    scopes: ["openid", "profile", "email"],
    requireIdTokenVerification: true,
    tokenEndpointAuth: { method: "client_secret_basic" },
    pkce: boolean(env, "OIDC_PKCE", true),
    disableSignUp: boolean(env, "OIDC_DISABLE_SIGNUP", true),
  };
}

export function getOIDCProviderSummary(env: Env = process.env) {
  const provider = getOIDCProvider(env);
  return provider ? { providerId: provider.providerId, name: provider.name ?? provider.providerId } : null;
}
