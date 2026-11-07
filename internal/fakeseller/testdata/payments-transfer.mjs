// Prints payments-transfer.json from bugnet-payments' own builder and signer and public labels
import { execFileSync } from "node:child_process";
import { createHash, createPrivateKey, createPublicKey } from "node:crypto";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

const payments = resolve(process.argv[2] ?? "../../../bugnet-payments");
const load = (path) => import(pathToFileURL(resolve(payments, path)).href);
const { buildSellerPayment, signSellerPayment } = await load("src/x402/build.ts");
const { usdcAta } = await load("src/solana/accounts.ts");
const { loadKeypair } = await load("src/solana/keys.ts");

// pkcs8 is the DER prefix of an Ed25519 private key, before its 32-byte seed
const pkcs8 = Buffer.from("302e020100300506032b657004220420", "hex");

async function signer(label) {
    const seed = createHash("sha256").update(`bugnet fakeseller test ${label}`).digest();
    const der = Buffer.concat([pkcs8, seed]);
    const key = createPrivateKey({ key: der, format: "der", type: "pkcs8" });
    const pub = Buffer.from(createPublicKey(key).export({ format: "jwk" }).x, "base64url");
    return loadKeypair(JSON.stringify([...seed, ...pub]), label);
}

const allowance = await signer("allowance");
const feePayer = await signer("fee payer");
const payTo = await signer("pay to");
const blockhash = (await signer("blockhash")).address;
const source = await usdcAta(allowance.address);
const destination = await usdcAta(payTo.address);
const amount = 1000n;
const tx = buildSellerPayment({
    feePayer: feePayer.address,
    hotTokenAccount: source,
    destination,
    authority: allowance.address,
    amount,
    memo: new TextEncoder().encode("0123456789abcdef0123456789abcdef"),
    computeUnitLimit: 20_000,
    computeUnitPriceMicroLamports: 1n,
    blockhash,
    lastValidBlockHeight: 1000n,
});
const { wireBase64 } = await signSellerPayment(tx, allowance);
const commit = execFileSync("git", ["-C", payments, "rev-parse", "--short", "HEAD"])
    .toString()
    .trim();
const fixture = {
    made_with: `bugnet-payments ${commit} buildSellerPayment and signSellerPayment`,
    transaction: wireBase64,
    fee_payer: feePayer.address,
    authority: allowance.address,
    pay_to: payTo.address,
    source,
    destination,
    amount: Number(amount),
    blockhash,
};
console.log(JSON.stringify(fixture, null, 4));
