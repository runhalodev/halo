/**
 * Operator-side end-to-end prompt encryption.
 *
 * Scheme: X25519 ECDH → HKDF-SHA256 → AES-256-GCM.
 *
 * Key lifecycle:
 *   - Operator generates a fresh X25519 keypair on every `halo serve`
 *     startup. The private key lives in process memory only — never persisted
 *     to disk. The public key rides in the WS `announce` payload.
 *   - When the operator process restarts, the key is gone forever. Ciphertext
 *     captured from past sessions becomes provably uncrackable, even by the
 *     operator themselves. That's the forward-secrecy property fresh-per-
 *     session buys us.
 *
 * Why X25519 instead of reusing the operator's secp256k1 wallet key:
 *   - Forward secrecy at the session boundary (above).
 *   - Separation of concerns: payment-signing and content-decryption never
 *     share a key, eliminating an entire class of confused-deputy bugs.
 *   - TEE-attestation forward compatibility: a future enclave generates its
 *     keypair at attestation time, which can't be done with the wallet key.
 *
 * Wire format (the JSON value of `_enc` in the request body or top-level
 * response body):
 *
 *   {
 *     v: 1,
 *     alg: "x25519-aes256gcm",
 *     epk:   "<32 byte hex>",   // consumer's ephemeral X25519 pubkey
 *     nonce: "<12 byte hex>",   // AES-GCM IV, fresh per direction
 *     ct:    "<hex>"            // ciphertext || 16-byte GCM auth tag
 *   }
 *
 * The plaintext under `ct` is JSON.stringify(body) of the request (sans
 * `model`, which the relay needs in cleartext for routing) or the response.
 */
import { createCipheriv, createDecipheriv, randomBytes } from "crypto";
import { x25519 } from "@noble/curves/ed25519";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";

export const ENCRYPTION_ALG = "x25519-aes256gcm";
export const ENCRYPTION_VERSION = 1;
const HKDF_INFO = new TextEncoder().encode("halo/v1/x25519-aes256gcm");

export interface OperatorKeyPair {
  /** 32-byte X25519 public key, hex-encoded (no 0x prefix). */
  publicKeyHex: string;
  /** 32-byte X25519 private key. Held only in process memory. */
  privateKey: Uint8Array;
}

export interface EncryptedEnvelope {
  v: 1;
  alg: typeof ENCRYPTION_ALG;
  epk: string;
  nonce: string;
  ct: string;
}

/** True if `value` looks like a v1 EncryptedEnvelope. */
export function isEncryptedEnvelope(value: unknown): value is EncryptedEnvelope {
  if (!value || typeof value !== "object") return false;
  const v = value as Record<string, unknown>;
  return (
    v.v === ENCRYPTION_VERSION &&
    v.alg === ENCRYPTION_ALG &&
    typeof v.epk === "string" &&
    typeof v.nonce === "string" &&
    typeof v.ct === "string"
  );
}

/** Generate a fresh X25519 keypair. Called once at operator startup. */
export function generateOperatorKeypair(): OperatorKeyPair {
  const privateKey = x25519.utils.randomPrivateKey();
  const publicKey = x25519.getPublicKey(privateKey);
  return {
    publicKeyHex: bufToHex(publicKey),
    privateKey,
  };
}

/**
 * Derive the AES-256-GCM session key from an X25519 ECDH between our private
 * key and the peer's public key. Same derivation on both ends produces the
 * same key; one direction encrypts with it, the other decrypts.
 *
 * The HKDF info string is fixed and versioned so a future scheme bump can
 * coexist without ambiguity.
 */
function deriveSessionKey(
  ourPrivateKey: Uint8Array,
  peerPublicKey: Uint8Array
): Uint8Array {
  const shared = x25519.getSharedSecret(ourPrivateKey, peerPublicKey);
  // HKDF with no salt (RFC 5869 says omit-salt is fine when input is uniform,
  // and an X25519 shared secret is). 32 bytes out = AES-256 key.
  return hkdf(sha256, shared, undefined, HKDF_INFO, 32);
}

/**
 * Decrypt an `_enc` envelope received from the consumer. Returns the parsed
 * JSON plaintext (typically the OpenAI-compat body sans `model`).
 *
 * Throws on:
 *   - Unsupported envelope version/alg
 *   - Malformed hex
 *   - AES-GCM auth tag mismatch (wrong key, tampered ciphertext, wrong peer pubkey)
 */
export function decryptRequest(
  envelope: EncryptedEnvelope,
  operatorPrivateKey: Uint8Array
): { plaintext: unknown; consumerPublicKey: Uint8Array } {
  if (envelope.v !== ENCRYPTION_VERSION || envelope.alg !== ENCRYPTION_ALG) {
    throw new Error(`unsupported envelope: v=${envelope.v} alg=${envelope.alg}`);
  }
  const consumerPublicKey = hexToBuf(envelope.epk);
  if (consumerPublicKey.length !== 32) {
    throw new Error(`epk must be 32 bytes, got ${consumerPublicKey.length}`);
  }
  const nonce = hexToBuf(envelope.nonce);
  if (nonce.length !== 12) {
    throw new Error(`nonce must be 12 bytes, got ${nonce.length}`);
  }
  const sealed = hexToBuf(envelope.ct);
  if (sealed.length < 16) {
    throw new Error(`ct too short to contain GCM tag`);
  }
  const sessionKey = deriveSessionKey(operatorPrivateKey, consumerPublicKey);

  // Node's createDecipheriv splits ciphertext from tag (last 16 bytes).
  const tag = sealed.subarray(sealed.length - 16);
  const ct = sealed.subarray(0, sealed.length - 16);

  const decipher = createDecipheriv("aes-256-gcm", sessionKey, nonce);
  decipher.setAuthTag(tag);
  let plaintextBytes: Buffer;
  try {
    plaintextBytes = Buffer.concat([decipher.update(ct), decipher.final()]);
  } catch {
    throw new Error("decryption failed (wrong key or tampered ciphertext)");
  }
  return {
    plaintext: JSON.parse(plaintextBytes.toString("utf8")),
    consumerPublicKey,
  };
}

/**
 * Encrypt a response body with the same session key as the request (re-derived
 * from the consumer's ephemeral pubkey). Fresh nonce per direction so the
 * request and response ciphertexts never share an (key, nonce) pair — the
 * cardinal sin of nonce-misuse with GCM.
 */
export function encryptResponse(
  body: unknown,
  consumerPublicKey: Uint8Array,
  operatorPrivateKey: Uint8Array
): EncryptedEnvelope {
  const sessionKey = deriveSessionKey(operatorPrivateKey, consumerPublicKey);
  const nonce = randomBytes(12);
  const plaintext = Buffer.from(JSON.stringify(body), "utf8");
  const cipher = createCipheriv("aes-256-gcm", sessionKey, nonce);
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    v: ENCRYPTION_VERSION,
    alg: ENCRYPTION_ALG,
    // Response carries the operator's own ephemeral counterpart only for
    // protocol symmetry / debuggability — the consumer already knows it from
    // the announce, but echoing it here means a future scheme that does
    // per-request ratcheting has a place to put it. For v1 it's the same as
    // the static operator pubkey derived from operatorPrivateKey.
    epk: bufToHex(x25519.getPublicKey(operatorPrivateKey)),
    nonce: bufToHex(nonce),
    ct: bufToHex(Buffer.concat([ct, tag])),
  };
}

// ── Consumer side (encrypt request to operator, decrypt operator's reply) ─────

export interface EphemeralKeyPair {
  /** 32-byte X25519 public key, hex (no 0x). Sent as the envelope `epk`. */
  publicKeyHex: string;
  /** 32-byte X25519 private key — held in memory for one request. */
  privateKey: Uint8Array;
}

/** Fresh per-request ephemeral X25519 keypair (consumer side). */
export function generateEphemeralKeypair(): EphemeralKeyPair {
  const privateKey = x25519.utils.randomPrivateKey();
  return { publicKeyHex: bufToHex(x25519.getPublicKey(privateKey)), privateKey };
}

/** Parse a 32-byte hex X25519 pubkey (e.g. an operator's announced key). */
export function hexToPubkey(hex: string): Uint8Array {
  const buf = hexToBuf(hex);
  if (buf.length !== 32) throw new Error(`operator pubkey must be 32 bytes, got ${buf.length}`);
  return buf;
}

/**
 * Encrypt a request body to the operator's announced X25519 pubkey so the RELAY
 * only ever sees ciphertext. Mirrors the frontend; the operator's `decryptRequest`
 * reads it byte-for-byte. The caller keeps `model` (and `stream`) in cleartext
 * outside the envelope for routing.
 */
export function encryptRequest(
  body: unknown,
  operatorPublicKey: Uint8Array,
  ephemeral: EphemeralKeyPair
): EncryptedEnvelope {
  const sessionKey = deriveSessionKey(ephemeral.privateKey, operatorPublicKey);
  const nonce = randomBytes(12);
  const plaintext = Buffer.from(JSON.stringify(body), "utf8");
  const cipher = createCipheriv("aes-256-gcm", sessionKey, nonce);
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    v: ENCRYPTION_VERSION,
    alg: ENCRYPTION_ALG,
    epk: ephemeral.publicKeyHex,
    nonce: bufToHex(nonce),
    ct: bufToHex(Buffer.concat([ct, tag])),
  };
}

/**
 * Decrypt the operator's `_enc` response with the same session key (re-derived
 * from our ephemeral private key + the operator's pubkey). Returns the parsed
 * JSON body. Throws on a tag mismatch (wrong key / tampered).
 */
export function decryptResponse(
  envelope: EncryptedEnvelope,
  operatorPublicKey: Uint8Array,
  ephemeralPrivateKey: Uint8Array
): unknown {
  if (envelope.v !== ENCRYPTION_VERSION || envelope.alg !== ENCRYPTION_ALG) {
    throw new Error(`unsupported envelope: v=${envelope.v} alg=${envelope.alg}`);
  }
  const sessionKey = deriveSessionKey(ephemeralPrivateKey, operatorPublicKey);
  const nonce = hexToBuf(envelope.nonce);
  const sealed = hexToBuf(envelope.ct);
  if (sealed.length < 16) throw new Error("ct too short to contain GCM tag");
  const tag = sealed.subarray(sealed.length - 16);
  const ct = sealed.subarray(0, sealed.length - 16);
  const decipher = createDecipheriv("aes-256-gcm", sessionKey, nonce);
  decipher.setAuthTag(tag);
  let pt: Buffer;
  try {
    pt = Buffer.concat([decipher.update(ct), decipher.final()]);
  } catch {
    throw new Error("response decryption failed (wrong key or tampered ciphertext)");
  }
  return JSON.parse(pt.toString("utf8"));
}

function bufToHex(buf: Uint8Array | Buffer): string {
  return Buffer.from(buf).toString("hex");
}

function hexToBuf(hex: string): Uint8Array {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  return Buffer.from(clean, "hex");
}
