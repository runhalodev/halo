/**
 * Known inference provider presets. "Custom" lets operators point at any
 * OpenAI-compatible endpoint that isn't in the list.
 *
 * Wire shape:
 *   "openai-compat" — POST {baseUrl}/chat/completions, Bearer auth (default)
 *   "anthropic"     — POST {baseUrl}/messages with x-api-key + anthropic-version;
 *                     translated to/from OpenAI chat-completions in serve.ts
 *
 * Agent runtimes (OpenClaw, Claude Code, Hermes) expose an upstream the
 * operator can point at without operating a model themselves. Self-hosted
 * options (Ollama, LM Studio) and OpenRouter let any operator serve without
 * an agent at all.
 */
export type ProviderWireFormat = "openai-compat" | "anthropic";

export interface ProviderPreset {
  slug: string;
  label: string;
  baseUrl: string;
  requiresApiKey: boolean;
  isPrivacy?: boolean;
  /** Provider runs inference inside a hardware TEE with per-response attestation
   *  (confidential mode). Models served by such a provider are advertised as
   *  TEE-capable so consumers can route confidentially to them. */
  isTee?: boolean;
  /** Wire format the operator's upstream speaks. Defaults to openai-compat. */
  wire?: ProviderWireFormat;
  /** Suggested margin % if pricing mode is "margin". */
  defaultMarginPercent: number;
}

export const PROVIDER_PRESETS: Record<string, ProviderPreset> = {
  openclaw: {
    slug: "openclaw",
    label: "OpenClaw gateway (auto-detect)",
    baseUrl: "http://127.0.0.1:18789/v1",
    requiresApiKey: false,
    defaultMarginPercent: 20,
  },
  ollama: {
    slug: "ollama",
    label: "Local Ollama (no upstream cost)",
    baseUrl: "http://127.0.0.1:11434/v1",
    requiresApiKey: false,
    isPrivacy: true,
    defaultMarginPercent: 0,
  },
  lmstudio: {
    slug: "lmstudio",
    label: "Local LM Studio (no upstream cost)",
    baseUrl: "http://127.0.0.1:1234/v1",
    requiresApiKey: false,
    isPrivacy: true,
    defaultMarginPercent: 0,
  },
  "claude-code": {
    slug: "claude-code",
    label: "Claude Code (Anthropic API)",
    baseUrl: "https://api.anthropic.com/v1",
    requiresApiKey: true,
    wire: "anthropic",
    defaultMarginPercent: 30,
  },
  hermes: {
    slug: "hermes",
    label: "Hermes (Nous Research)",
    baseUrl: "https://inference-api.nousresearch.com/v1",
    requiresApiKey: true,
    defaultMarginPercent: 25,
  },
  openai: {
    slug: "openai",
    label: "OpenAI",
    baseUrl: "https://api.openai.com/v1",
    requiresApiKey: true,
    defaultMarginPercent: 30,
  },
  anthropic: {
    slug: "anthropic",
    label: "Anthropic",
    baseUrl: "https://api.anthropic.com/v1",
    requiresApiKey: true,
    wire: "anthropic",
    defaultMarginPercent: 30,
  },
  openrouter: {
    slug: "openrouter",
    label: "OpenRouter (100+ models)",
    baseUrl: "https://openrouter.ai/api/v1",
    requiresApiKey: true,
    defaultMarginPercent: 30,
  },
  venice: {
    slug: "venice",
    label: "Venice.ai (privacy)",
    baseUrl: "https://api.venice.ai/api/v1",
    requiresApiKey: true,
    isPrivacy: true,
    defaultMarginPercent: 30,
  },
  near: {
    slug: "near",
    // NEAR AI Cloud: OpenAI-compatible inference inside Intel TDX + NVIDIA H200
    // TEEs, with per-response attestation. The gateway base serves every model
    // and `/v1/models`; the confidential (attested, E2EE) path uses each model's
    // direct-completions subdomain — see the attestation integration.
    label: "NEAR AI Cloud (confidential TEE)",
    baseUrl: "https://cloud-api.near.ai/v1",
    requiresApiKey: true,
    isPrivacy: true,
    isTee: true,
    defaultMarginPercent: 20,
  },
  together: {
    slug: "together",
    label: "Together.ai",
    baseUrl: "https://api.together.xyz/v1",
    requiresApiKey: true,
    defaultMarginPercent: 30,
  },
  fireworks: {
    slug: "fireworks",
    label: "Fireworks.ai",
    baseUrl: "https://api.fireworks.ai/inference/v1",
    requiresApiKey: true,
    defaultMarginPercent: 30,
  },
  groq: {
    slug: "groq",
    label: "Groq",
    baseUrl: "https://api.groq.com/openai/v1",
    requiresApiKey: true,
    defaultMarginPercent: 30,
  },
  custom: {
    slug: "custom",
    label: "Custom OpenAI-compatible endpoint",
    baseUrl: "",
    requiresApiKey: false,
    defaultMarginPercent: 30,
  },
};

export interface ProviderModelEntry {
  id: string;
  [k: string]: unknown;
}

export const ANTHROPIC_API_VERSION = "2023-06-01";

/** Returns the wire format for a known slug (defaults to openai-compat). */
export function wireFormatFor(slug: string): ProviderWireFormat {
  return PROVIDER_PRESETS[slug]?.wire ?? "openai-compat";
}

/** True when a provider slug serves inside a hardware TEE (confidential mode).
 *  Kept in sync with the relay's TEE_PROVIDERS set. */
export function isTeeProviderSlug(slug: string): boolean {
  return PROVIDER_PRESETS[slug]?.isTee === true;
}

/**
 * Fetch the provider's models list. Returns only the `id` fields.
 *
 * Three shapes:
 *   - Ollama:    GET {host}/api/tags → { models: [{ name }] }
 *   - Anthropic: GET {base}/models with x-api-key + anthropic-version → { data: [{ id }] }
 *   - Everything else (OpenAI-compatible): GET {base}/models with Bearer → { data: [{ id }] }
 */
export async function detectModels(
  baseUrl: string,
  apiKey: string | undefined,
  slug: string
): Promise<string[]> {
  if (slug === "ollama") {
    const url = baseUrl.replace(/\/v1\/?$/, "") + "/api/tags";
    const res = await fetch(url);
    if (!res.ok) throw new Error(`Ollama /api/tags returned ${res.status}`);
    const body = (await res.json()) as { models?: Array<{ name: string }> };
    return (body.models || []).map((m) => m.name);
  }

  const url = baseUrl.replace(/\/+$/, "") + "/models";
  const headers: Record<string, string> = { Accept: "application/json" };
  if (wireFormatFor(slug) === "anthropic") {
    if (apiKey) headers["x-api-key"] = apiKey;
    headers["anthropic-version"] = ANTHROPIC_API_VERSION;
  } else if (apiKey) {
    headers["Authorization"] = `Bearer ${apiKey}`;
  }
  const res = await fetch(url, { headers });
  if (!res.ok) throw new Error(`GET ${url} returned ${res.status}`);
  const body = (await res.json()) as { data?: ProviderModelEntry[] };
  const list = (body.data || []).map((m) => m.id);
  return list;
}
