/**
 * Confidential (TEE) inference client — consumer side of the NEAR AI Cloud
 * end-to-end encryption + attestation verification, used by `halo consume` and
 * `halo pay` when serving a TEE provider.
 *
 * The flow (all verified live against cloud-api.near.ai):
 *   1. Fetch the model's attestation report (PUBLIC, no key) → the model's
 *      ECDSA `signing_public_key` (64-byte secp256k1) + the attested
 *      `signing_address` (an EVM address).
 *   2. Encrypt the message CONTENT to the model's pubkey (ECIES: secp256k1
 *      ECDH → HKDF-SHA256(info="ecdsa_encryption") → AES-256-GCM). Only the
 *      enclave can decrypt it. The envelope (model, max_tokens) stays cleartext.
 *   3. Send with X-Signing-Algo / X-Client-Pub-Key / X-Model-Pub-Key; the
 *      operator relays the ciphertext and CANNOT read it.
 *   4. Decrypt the response (encrypted by the enclave to our ephemeral key).
 *   5. Verify the operator-forwarded signature (`X-Halo-TEE-Signature`):
 *      ethers.verifyMessage(text, signature) MUST recover to the attested
 *      `signing_address`. The operator can't forge it — only withhold it, in
 *      which case verification fails closed.
 *
 * Wire format (ECDSA/ECIES): [ephemeral_pubkey 65][nonce 12][ciphertext+tag].
 */
import * as crypto from "crypto";
import { ethers } from "ethers";

// Attestation/collateral fetches hit external services (the TEE provider's
// /attestation/report and Intel's PCS at api.trustedservices.intel.com for the
// DCAP quote collateral). Those have transient blips; without a retry a single
// blip turns confidential inference into a hard 502. Bound each attempt so a
// wedged endpoint can't hang the request, and retry transient failures.
const ATTEST_TIMEOUT_MS = 20_000;
const ATTEST_RETRIES = 2;
const ATTEST_RETRY_BASE_DELAY_MS = 600;

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

/** Transient enough to retry: network faults, timeouts, 5xx, and the DCAP
 *  collateral fetch failing (Intel PCS blip). NOT a genuine verification
 *  failure (a forged/invalid quote) — that should fail closed immediately. */
function isTransientAttestErr(err: unknown): boolean {
  const msg = (err instanceof Error ? err.message : String(err)).toLowerCase();
  if (/invalid|mismatch|forged|does not|not verified|tcb|expired certificate|signature/.test(msg)) {
    // Looks like a real verification verdict — don't paper over it with retries.
    return /collateral|timeout|timed out|network|fetch failed/.test(msg);
  }
  return /collateral|timeout|timed out|econn|enotfound|eai_again|fetch failed|socket hang up|network|502|503|504|temporarily/.test(
    msg
  );
}

/** Run an attestation step with bounded retries + backoff on transient faults. */
async function withAttestRetry<T>(label: string, fn: () => Promise<T>): Promise<T> {
  let lastErr: unknown;
  for (let attempt = 0; attempt <= ATTEST_RETRIES; attempt++) {
    try {
      return await fn();
    } catch (err) {
      lastErr = err;
      if (attempt >= ATTEST_RETRIES || !isTransientAttestErr(err)) break;
      await sleep(ATTEST_RETRY_BASE_DELAY_MS * 2 ** attempt);
    }
  }
  throw lastErr instanceof Error ? lastErr : new Error(`${label} failed: ${String(lastErr)}`);
}

export interface ModelAttestation {
  signingPublicKey: string; // 64-byte secp256k1 hex (no 0x04 prefix)
  signingAddress: string; // attested EVM signer
}

/** HKDF-SHA256 with a zero salt (matches NEAR's vllm-proxy). */
function hkdf(ikm: Buffer, info: string, length: number): Buffer {
  const prk = crypto.createHmac("sha256", Buffer.alloc(32)).update(ikm).digest();
  const h = crypto.createHmac("sha256", prk).update(Buffer.from(info)).update(Buffer.from([1]));
  return h.digest().slice(0, length);
}

/** secp256k1 ECDH shared X-coordinate (matches Node createECDH.computeSecret). */
function sharedSecret(privKeyHex: string, peerPubPoint: Buffer): Buffer {
  const ecdh = crypto.createECDH("secp256k1");
  ecdh.setPrivateKey(Buffer.from(privKeyHex.replace(/^0x/, ""), "hex"));
  return ecdh.computeSecret(peerPubPoint);
}

/** Uncompressed secp256k1 public key (0x04 + 128 hex) from a private key. */
function uncompressedPub(privKey: string): string {
  return ethers.SigningKey.computePublicKey(privKey, false);
}

/** Encrypt `plaintext` to the model's 64-byte secp256k1 pubkey (ECIES). */
export function encryptToTee(plaintext: string, modelPub64: string): string {
  const point = Buffer.concat([Buffer.from([4]), Buffer.from(modelPub64, "hex")]);
  const eph = ethers.Wallet.createRandom();
  const aesKey = hkdf(sharedSecret(eph.privateKey, point), "ecdsa_encryption", 32);
  const nonce = crypto.randomBytes(12);
  const c = crypto.createCipheriv("aes-256-gcm", aesKey, nonce);
  const enc = Buffer.concat([c.update(Buffer.from(plaintext, "utf-8")), c.final()]);
  const ephPub = Buffer.from(uncompressedPub(eph.privateKey).slice(2), "hex"); // 65 bytes
  return Buffer.concat([ephPub, nonce, enc, c.getAuthTag()]).toString("hex");
}

/** Decrypt a TEE response (encrypted to our ephemeral key). */
export function decryptFromTee(encHex: string, clientPrivKey: string): string {
  const buf = Buffer.from(encHex, "hex");
  const ephPub = buf.slice(0, 65),
    nonce = buf.slice(65, 77),
    ctTag = buf.slice(77);
  const aesKey = hkdf(sharedSecret(clientPrivKey, ephPub), "ecdsa_encryption", 32);
  const d = crypto.createDecipheriv("aes-256-gcm", aesKey, nonce);
  d.setAuthTag(ctTag.slice(-16));
  return Buffer.concat([d.update(ctTag.slice(0, -16)), d.final()]).toString("utf-8");
}

/** A fresh client keypair for one confidential request. `pubHex` is the 64-byte
 *  uncompressed key (no 0x04) sent as X-Client-Pub-Key. */
export function newClientKey(): { privateKey: string; pubHex: string } {
  const w = ethers.Wallet.createRandom();
  return { privateKey: w.privateKey, pubHex: uncompressedPub(w.privateKey).slice(4) };
}

/** Fetch the model's attestation (PUBLIC endpoint — no operator key required). */
export async function fetchModelAttestation(
  baseUrl: string,
  model: string
): Promise<ModelAttestation> {
  const url =
    `${baseUrl.replace(/\/+$/, "")}/attestation/report` +
    `?model=${encodeURIComponent(model)}&signing_algo=ecdsa`;
  return withAttestRetry("attestation report", async () => {
    const res = await fetch(url, { signal: AbortSignal.timeout(ATTEST_TIMEOUT_MS) });
    if (!res.ok) throw new Error(`attestation report ${res.status}`);
    const rep = (await res.json()) as {
      model_attestations?: Array<{ signing_public_key?: string; signing_address?: string }>;
    };
    const m = (rep.model_attestations || []).find((a) => a.signing_public_key && a.signing_address);
    if (!m) throw new Error("no model attestation with a signing key");
    return { signingPublicKey: m.signing_public_key!, signingAddress: m.signing_address! };
  });
}

/**
 * Full TRUSTLESS hardware attestation verification — parity with the frontend.
 * Fetches the model's complete attestation and cryptographically verifies the
 * Intel TDX quote chains to Intel's SGX Root CA, the NVIDIA H200 evidence, and
 * that the quote's report_data binds the attested signing address + nonce. Unlike
 * `verifyTeeSignature` (which only checks the response signature recovers to the
 * attested signer, trusting the attestation source), this proves the enclave is
 * genuine hardware running NEAR's image — so a rogue relay/operator can't fake a
 * confidential guarantee with a substituted key. Returns the verified signing
 * address (lowercased) on success; throws on any verification failure.
 *
 * ~1.5–2s + collateral fetches, so callers cache the result per (model, signer)
 * — see verifiedSignerForModel.
 */
export async function verifyAttestationHardware(baseUrl: string, model: string): Promise<string> {
  const url =
    `${baseUrl.replace(/\/+$/, "")}/attestation/report` +
    `?model=${encodeURIComponent(model)}&signing_algo=ecdsa`;
  // The DCAP verify fetches the Intel quote's collateral from Intel's PCS, which
  // has transient blips — retry the whole report-fetch + verify on transient
  // faults (a genuine quote-verification failure is NOT retried; it fails closed).
  return withAttestRetry("hardware attestation", async () => {
    const res = await fetch(url, { signal: AbortSignal.timeout(ATTEST_TIMEOUT_MS) });
    if (!res.ok) throw new Error(`attestation report ${res.status}`);
    const rep = (await res.json()) as {
      model_attestations?: Array<{
        signing_address?: string;
        intel_quote?: string;
        nvidia_payload?: string;
        request_nonce?: string;
      }>;
    };
    const ma = (rep.model_attestations || []).find((a) => a.signing_address && a.intel_quote);
    if (!ma) throw new Error("attestation report missing intel_quote / signing_address");
    // Lazy import: the verifier pulls in the DCAP WASM — keep it off the cold path
    // for non-confidential serve/consume.
    const { verifyModelAttestation, assertModelAttestationVerified } = await import(
      "nearai-cloud-verifier"
    );
    const v = await verifyModelAttestation(ma as Parameters<typeof verifyModelAttestation>[0]);
    // Throws if the TDX quote / NVIDIA evidence / report_data binding don't verify.
    assertModelAttestationVerified(
      v as Parameters<typeof assertModelAttestationVerified>[0],
      ma.request_nonce || "",
      ma.signing_address || ""
    );
    return ma.signing_address!.toLowerCase();
  });
}

// Cache of hardware-verified signers per `${baseUrl}::${model}`. The enclave's
// signing key is stable across a serving period; re-verify after TTL or on a
// signer change (enclave rotation). Bounds the ~2s verify to once per window.
const verifiedSignerCache = new Map<string, { signer: string; at: number }>();
const ATTEST_VERIFY_TTL_MS = 10 * 60 * 1000; // 10 min

/**
 * Hardware-verified signing address for a model, cached. Runs the full DCAP
 * verification on a cache miss / expiry; otherwise returns the cached verified
 * signer instantly. Throws if verification fails (fail closed). Callers then
 * confirm the per-request attestation's signer EQUALS this verified value.
 */
export async function verifiedSignerForModel(baseUrl: string, model: string): Promise<string> {
  const key = `${baseUrl.replace(/\/+$/, "")}::${model}`;
  const hit = verifiedSignerCache.get(key);
  if (hit && Date.now() - hit.at < ATTEST_VERIFY_TTL_MS) return hit.signer;
  const signer = await verifyAttestationHardware(baseUrl, model);
  verifiedSignerCache.set(key, { signer, at: Date.now() });
  return signer;
}

/**
 * Verify the operator-forwarded response signature recovers to the attested
 * signer. `sigB64` is the base64 X-Halo-TEE-Signature blob the operator fetched
 * with its key. Returns true only on a genuine match (fails closed otherwise).
 */
export function verifyTeeSignature(sigB64: string, attestedSigner: string): boolean {
  try {
    const p = JSON.parse(Buffer.from(sigB64, "base64").toString("utf-8")) as {
      text: string;
      signature: string;
      signing_address: string;
    };
    const recovered = ethers.verifyMessage(p.text, p.signature);
    return (
      recovered.toLowerCase() === p.signing_address.toLowerCase() &&
      recovered.toLowerCase() === attestedSigner.toLowerCase()
    );
  } catch {
    return false;
  }
}
