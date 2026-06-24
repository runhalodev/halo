/**
 * Outbound request body sanitization.
 *
 * Goal: the operator must never forward consumer-identifying or tracking
 * metadata to the upstream inference provider. Two attack vectors this
 * defends against:
 *
 *   1. A consumer (or a compromised consumer SDK) accidentally tags itself
 *      across requests with OpenAI's `user` field, `metadata`, `store: true`,
 *      or a custom extension field. Even a privacy-aware operator would
 *      blindly pass these through, fingerprinting the user at OpenAI/etc.
 *
 *   2. A future schema extension on the operator side accidentally adds
 *      consumer-identifying data to the upstream call. The allowlist locks
 *      down the shape so any addition must go through a code review.
 *
 * Strategy: explicit allowlist of known-safe fields for OpenAI-compatible
 * chat-completions requests. Anything else is dropped silently. If a field
 * is genuinely useful and safe, add it here on purpose.
 */

const ALLOWED_FIELDS: ReadonlySet<string> = new Set([
  // Routing / required
  "model",
  "messages",
  // Generation controls (no consumer identity)
  "max_tokens",
  "max_completion_tokens",
  "temperature",
  "top_p",
  "top_k",
  "stop",
  "stop_sequences",
  "frequency_penalty",
  "presence_penalty",
  "n",
  "logit_bias",
  "logprobs",
  "top_logprobs",
  "response_format",
  "seed",
  "stream",
  "stream_options",
  // Tool/function calling — content, not identity
  "tools",
  "tool_choice",
  "parallel_tool_calls",
  "functions",
  "function_call",
]);

/**
 * Explicitly forbidden — fields known to carry user-identifying or
 * provider-side telemetry data. Listed for clarity; the allowlist would
 * already drop them, but enumerating them makes the threat model obvious.
 */
export const FORBIDDEN_FIELDS: ReadonlySet<string> = new Set([
  "user", // OpenAI's stable per-user identifier — never forward
  "metadata", // OpenAI Assistant API user metadata
  "store", // OpenAI's "save this conversation on their side" opt-in
  "x-source", // common debug/source tag from SDK wrappers
  "x-user-id",
  "x-session-id",
  "client_reference_id",
]);

export interface SanitizationReport {
  /** Fields that were dropped from the outbound body. */
  dropped: string[];
}

/**
 * Return a copy of `body` containing only allowlisted fields. Also report
 * what was dropped, so the operator can log the count (not the values) for
 * its own audit.
 *
 * Non-object input is returned unchanged on the assumption that an
 * upstream HTTP error will surface the malformed body — sanitization is
 * not the place to validate JSON shape.
 */
export function sanitizeChatRequest(
  body: unknown
): { sanitized: Record<string, unknown>; report: SanitizationReport } {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return { sanitized: {} as Record<string, unknown>, report: { dropped: [] } };
  }
  const dropped: string[] = [];
  const sanitized: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(body as Record<string, unknown>)) {
    if (ALLOWED_FIELDS.has(k)) {
      sanitized[k] = v;
    } else {
      dropped.push(k);
    }
  }
  return { sanitized, report: { dropped } };
}

/**
 * Sanitize each message: keep `role` and `content`, drop everything else
 * (notably `name`, which OpenAI exposes as a per-message user identifier).
 *
 * Tool-call messages are passed through with their `tool_calls` and
 * `tool_call_id` fields intact, since those are the actual content of a
 * tool-using conversation — they don't carry identity.
 */
export function sanitizeMessages(messages: unknown): unknown {
  if (!Array.isArray(messages)) return messages;
  return messages.map((m) => {
    if (!m || typeof m !== "object") return m;
    const src = m as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    if (typeof src.role === "string") out.role = src.role;
    if (src.content !== undefined) out.content = src.content;
    if (src.tool_calls !== undefined) out.tool_calls = src.tool_calls;
    if (typeof src.tool_call_id === "string") out.tool_call_id = src.tool_call_id;
    // Deliberately drop: name, function_call (legacy, replaced by tool_calls),
    // any custom keys.
    return out;
  });
}
