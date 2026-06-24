/**
 * halo link — pair this operator with a dashboard wallet via short code.
 *
 * Generates a 9-digit code (XXX-XXX-XXX), signs the attestation with the
 * operator key, POSTs /link/init to the indexer, and prints the code. The
 * human then opens the dashboard, pastes the code, signs from their wallet,
 * and the indexer finalizes the link.
 */
import prompts from "prompts";
import { randomBytes, randomInt } from "crypto";
import { loadConfig } from "../config";
import { loadWallet } from "../wallet";

function generateCode(): string {
  // CSPRNG (crypto.randomInt), not Math.random — this is a pairing secret.
  const groups = Array.from({ length: 3 }, () =>
    randomInt(0, 1000).toString().padStart(3, "0")
  );
  return groups.join("-");
}

export async function cmdLink(): Promise<void> {
  const cfg = loadConfig();

  const { passphrase } = await prompts({
    type: "password",
    name: "passphrase",
    message: "Keystore passphrase",
  });
  if (!passphrase) process.exit(130);

  const wallet = await loadWallet(cfg.operator.keystorePath, passphrase);

  const code = generateCode();
  const nonce = "0x" + randomBytes(32).toString("hex");
  const expiresAt = Math.floor(Date.now() / 1000) + 300; // 5 min

  const message = `halo-link-init:${wallet.address.toLowerCase()}:${code}:${nonce}:${expiresAt}`;
  const operatorSig = await wallet.signMessage(message);

  const url = `${cfg.indexerUrl.replace(/\/+$/, "")}/link/init`;
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      code,
      operatorAddress: wallet.address,
      operatorSig,
      nonce,
      expiresAt,
    }),
  });

  if (!res.ok) {
    console.log(`\n✖ /link/init failed: ${res.status} ${await res.text()}\n`);
    process.exit(1);
  }

  console.log("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
  console.log(`  Pairing code`);
  console.log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
  console.log(`\n                 ${code}\n`);
  console.log(`  Open the dashboard, connect your wallet, paste this code,`);
  console.log(`  and sign to finalize the link. Valid 5 minutes.\n`);
}
