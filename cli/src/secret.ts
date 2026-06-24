/**
 * Symmetric encryption for sensitive config values (currently: upstream
 * provider API keys).
 *
 * Same threat model as the wallet keystore: protect a stolen
 * `~/.halo/` directory against an attacker who has the files but
 * not the operator's passphrase. We piggyback on the keystore passphrase
 * the operator already enters to unlock the wallet on `halo serve`,
 * so encryption-at-rest adds zero new prompts at runtime.
 *
 * Scheme: scrypt(passphrase, salt, 32 bytes) → AES-256-GCM(plaintext, iv).
 * scrypt parameters are gentle on purpose (N=2^15 ≈ 16 MB / ~100 ms on a
 * laptop) — strong enough to make offline brute force expensive, weak
 * enough not to wedge a serve startup.
 */
import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from "crypto";

export interface EncryptedSecret {
  /** Schema version. Bump if KDF or cipher changes. */
  v: 1;
  /** "aes-256-gcm" — explicit so a future swap is unambiguous. */
  alg: "aes-256-gcm";
  /** "scrypt" — explicit so a future swap is unambiguous. */
  kdf: "scrypt";
  /** Hex-encoded scrypt salt. */
  salt: string;
  /** Hex-encoded AES-GCM IV (12 bytes). */
  iv: string;
  /** Hex-encoded AES-GCM auth tag (16 bytes). */
  tag: string;
  /** Hex-encoded ciphertext. */
  data: string;
}

const SCRYPT_N = 1 << 15; // CPU/memory cost — ~100 ms on a 2020 laptop
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const KEY_LEN = 32;
// Memory required by scrypt = 128 * N * r bytes.
// With N=2^15 and r=8 → exactly 32 MB. Node's `scryptSync` default `maxmem`
// is 32 MB and OpenSSL enforces it as strict `<`, so the call fails at the
// boundary on Node 18 (and on some 20.x builds). We pass an explicit
// `maxmem` with 2× headroom so the call succeeds on any conformant build
// without compromising the memory-hardness of the KDF.
const SCRYPT_MAXMEM = 128 * SCRYPT_N * SCRYPT_R * 2;

function deriveKey(passphrase: string, salt: Buffer): Buffer {
  return scryptSync(passphrase, salt, KEY_LEN, {
    N: SCRYPT_N,
    r: SCRYPT_R,
    p: SCRYPT_P,
    maxmem: SCRYPT_MAXMEM,
  });
}

export function encryptSecret(plaintext: string, passphrase: string): EncryptedSecret {
  if (!plaintext) throw new Error("encryptSecret: plaintext is empty");
  if (!passphrase) throw new Error("encryptSecret: passphrase is empty");
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const key = deriveKey(passphrase, salt);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const enc = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  return {
    v: 1,
    alg: "aes-256-gcm",
    kdf: "scrypt",
    salt: salt.toString("hex"),
    iv: iv.toString("hex"),
    tag: cipher.getAuthTag().toString("hex"),
    data: enc.toString("hex"),
  };
}

export function decryptSecret(s: EncryptedSecret, passphrase: string): string {
  if (!passphrase) throw new Error("decryptSecret: passphrase is empty");
  if (s.v !== 1 || s.alg !== "aes-256-gcm" || s.kdf !== "scrypt") {
    throw new Error(`decryptSecret: unsupported envelope v=${s.v} alg=${s.alg} kdf=${s.kdf}`);
  }
  const key = deriveKey(passphrase, Buffer.from(s.salt, "hex"));
  const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(s.iv, "hex"));
  decipher.setAuthTag(Buffer.from(s.tag, "hex"));
  try {
    const out = Buffer.concat([decipher.update(Buffer.from(s.data, "hex")), decipher.final()]);
    return out.toString("utf8");
  } catch {
    // GCM auth-tag mismatch == wrong passphrase (or tampered ciphertext).
    // Surface a flat message; the difference doesn't matter to the operator.
    throw new Error("wrong passphrase or corrupted encrypted secret");
  }
}

/** True if `value` looks like a v1 EncryptedSecret envelope. */
export function isEncryptedSecret(value: unknown): value is EncryptedSecret {
  if (!value || typeof value !== "object") return false;
  const v = value as Record<string, unknown>;
  return (
    v.v === 1 &&
    v.alg === "aes-256-gcm" &&
    v.kdf === "scrypt" &&
    typeof v.salt === "string" &&
    typeof v.iv === "string" &&
    typeof v.tag === "string" &&
    typeof v.data === "string"
  );
}
