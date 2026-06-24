/**
 * Thin client for an x402 facilitator (CDP or any compatible service).
 *
 * Facilitator API:
 *   GET  {baseUrl}/supported → { address: string, schemes: string[] }
 *   POST {baseUrl}/verify    → { isValid: boolean, invalidReason?: string }
 *   POST {baseUrl}/settle    → { success: boolean, transaction?: string, network?: string, errorReason?: string }
 *
 * Body shape (verify / settle):
 *   { paymentPayload, paymentRequirements }
 *
 * For the `upto` scheme, settle additionally overrides paymentRequirements.maxAmountRequired
 * with the actual amount consumed (≤ the signed max), so the user is charged exactly what
 * was used rather than the full authorized ceiling.
 */

export interface PaymentPayload {
  signature: string;
  authType: string;
  // EIP-3009 payload — used with the `exact` scheme
  payload?: {
    from: string;
    to: string;
    value: string;
    validAfter: number;
    validBefore: number;
    nonce: string;
  };
  // Permit2 PermitWitnessTransferFrom payload — used with the `upto` scheme
  permit2Authorization?: {
    from: string;
    permitted: { token: string; amount: string };
    spender: string;
    nonce: string;
    deadline: string;
    witness: {
      to: string;
      facilitator: string;
      validAfter: string;
    };
  };
}

export interface PaymentRequirements {
  scheme: string;
  network: string;
  maxAmountRequired: string;
  resource?: string;
  payTo: string;
  maxTimeoutSeconds: number;
  asset: string;
  description?: string;
  mimeType?: string;
  extra?: Record<string, unknown>;
}

export interface VerifyResult {
  isValid: boolean;
  invalidReason?: string;
  payer?: string;
}

export interface SettleResult {
  success: boolean;
  transaction?: string;
  network?: string;
  errorReason?: string;
  amount?: string;
}

// Per-attempt timeout for a single facilitator URL. If it doesn't respond
// within this window, we abort and try the next URL in the failover list.
const FACILITATOR_TIMEOUT_MS = 30_000;
const SUPPORTED_FETCH_TIMEOUT_MS = 5_000;

export class Facilitator {
  private readonly urls: string[];
  // undefined = not yet fetched, null = fetched but not supported, string = address
  private cachedFacilitatorAddress: string | null | undefined = undefined;

  constructor(
    baseUrl: string,
    private readonly apiKey?: string,
    failoverUrls: string[] = []
  ) {
    this.urls = [baseUrl, ...failoverUrls]
      .map((u) => u.replace(/\/+$/, ""))
      .filter(Boolean);
  }

  private headers(): Record<string, string> {
    const h: Record<string, string> = { "Content-Type": "application/json" };
    if (this.apiKey) h["Authorization"] = `Bearer ${this.apiKey}`;
    return h;
  }

  /**
   * Fetch and cache the facilitator's own Ethereum address from GET /supported.
   * Returns null if the facilitator does not expose this endpoint (older versions),
   * which signals the operator to fall back to the `exact` scheme.
   */
  async getFacilitatorAddress(): Promise<string | null> {
    if (this.cachedFacilitatorAddress !== undefined) return this.cachedFacilitatorAddress;
    for (const url of this.urls) {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), SUPPORTED_FETCH_TIMEOUT_MS);
      try {
        const res = await fetch(`${url}/supported`, {
          headers: this.headers(),
          signal: controller.signal,
        });
        clearTimeout(timer);
        if (!res.ok) continue;
        const data = (await res.json()) as { address?: string };
        if (typeof data.address === "string" && /^0x[0-9a-fA-F]{40}$/i.test(data.address)) {
          this.cachedFacilitatorAddress = data.address.toLowerCase();
          return this.cachedFacilitatorAddress;
        }
      } catch {
        clearTimeout(timer);
      }
    }
    this.cachedFacilitatorAddress = null;
    return null;
  }

  /**
   * Try each facilitator URL in order. Returns the first successful response.
   * Only falls over on network errors, timeouts, or 5xx; 4xx is returned as-is
   * (it means the payload is invalid, not the facilitator).
   */
  private async tryAll<T>(path: string, body: unknown): Promise<T> {
    let lastErr: Error | null = null;
    for (let i = 0; i < this.urls.length; i++) {
      const url = `${this.urls[i]}${path}`;
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), FACILITATOR_TIMEOUT_MS);
      try {
        const res = await fetch(url, {
          method: "POST",
          headers: this.headers(),
          body: JSON.stringify(body),
          signal: controller.signal,
        });
        clearTimeout(timer);
        if (res.status >= 500) {
          lastErr = new Error(`${url} returned ${res.status}`);
          continue; // try next facilitator
        }
        if (!res.ok) {
          const text = await res.text();
          throw new Error(`facilitator ${path} ${res.status}: ${text}`);
        }
        return (await res.json()) as T;
      } catch (err) {
        clearTimeout(timer);
        lastErr = err instanceof Error ? err : new Error(String(err));
        // Network-level failure or timeout — try next.
      }
    }
    throw lastErr || new Error(`all facilitators failed for ${path}`);
  }

  async verify(
    paymentPayload: PaymentPayload,
    paymentRequirements: PaymentRequirements
  ): Promise<VerifyResult> {
    return this.tryAll<VerifyResult>("/verify", { paymentPayload, paymentRequirements });
  }

  /**
   * Settle a payment.
   *
   * For the `upto` scheme, pass `actualAmount` — the amount actually consumed
   * (≤ the signed max). The facilitator will charge only this amount on-chain.
   * For `exact`, omit `actualAmount` (the full signed value is charged).
   */
  async settle(
    paymentPayload: PaymentPayload,
    paymentRequirements: PaymentRequirements,
    actualAmount?: bigint
  ): Promise<SettleResult> {
    const requirements =
      actualAmount !== undefined
        ? { ...paymentRequirements, maxAmountRequired: actualAmount.toString() }
        : paymentRequirements;
    return this.tryAll<SettleResult>("/settle", { paymentPayload, paymentRequirements: requirements });
  }

  /**
   * Activate a budget by submitting the consumer's signed Permit2 permit
   * onchain. Idempotent — repeated calls for the same (consumer, nonce) just
   * return the existing budgetId without resubmitting. The protocol pays
   * gas. See docs/BUDGET_MODE.md for the full design.
   */
  async permitSubmit(payload: unknown): Promise<{
    submitted: boolean;
    alreadyActive?: boolean;
    budgetId: string;
    consumer?: string;
    transaction?: string;
    errorReason?: string;
  }> {
    return this.tryAll("/permit-submit", { payload });
  }

  /**
   * Draw down a single inference's worth of USDC from an active budget.
   * Validates per-tx cap, total budget remaining, and operator binding
   * facilitator-side; submits Permit2.transferFrom onchain.
   */
  async settleBudget(req: {
    budgetId: string;
    operator: string;
    amount: string;
    /** Consumer voucher (Phase 1), forwarded verbatim from the X-Halo-Voucher
     *  header so the facilitator can verify it against the budget sessionKey. */
    voucher?: {
      voucher: { budgetId: string; operator: string; cumulative: string; expiry: number };
      signature: string;
    };
    metadata?: { inferenceId?: string; model?: string; tokens?: number };
  }): Promise<{
    success: boolean;
    transaction?: string;
    spent?: string;
    remaining?: string;
    errorReason?: string;
  }> {
    return this.tryAll("/settle-budget", req);
  }
}
