/**
 * x402 wire-format types — match the standard exact-EVM scheme used by
 * Coinbase's CDP facilitator and any other compliant facilitator.
 */

export interface X402PaymentRequired {
  scheme: string;
  network: string;
  maxAmountRequired: string;
  resource?: string;
  payTo: string;
  maxTimeoutSeconds: number;
  asset: string;
  description?: string;
  mimeType?: string;
  extra?: {
    domainName?: string;
    domainVersion?: string;
    chainId?: number;
  };
}

export interface X402PaymentPayload {
  signature: string;
  authType: "TransferWithAuthorization";
  payload: {
    from: string;
    to: string;
    value: string;
    validAfter: number;
    validBefore: number;
    nonce: string;
  };
}

export interface ChatMessage {
  role: string;
  content: string;
}

export interface ChatCompletionUsage {
  prompt_tokens: number;
  completion_tokens: number;
  total_tokens: number;
}

export interface ChatCompletionChoice {
  index: number;
  message: ChatMessage;
  finish_reason: string;
}

export interface ChatCompletionResponse {
  id: string;
  object: string;
  created: number;
  model: string;
  choices: ChatCompletionChoice[];
  usage?: ChatCompletionUsage;
}
