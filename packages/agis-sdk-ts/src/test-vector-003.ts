import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parseAgisDnsTxt, validateAgisDnsBinding } from "./dnsBinding.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const dnsDir = path.resolve(__dirname, "../../../test-vectors/dns");
const txtPath = path.join(dnsDir, "valid-dns-binding.txt");
const manifestPath = path.join(dnsDir, "valid-dns-binding.manifest.json");

if (!fs.existsSync(txtPath)) {
  throw new Error(`DNS TXT file not found: ${txtPath}`);
}
if (!fs.existsSync(manifestPath)) {
  throw new Error(`DNS manifest not found: ${manifestPath}`);
}

const rawTxt = fs.readFileSync(txtPath, "utf8").trim();
const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
const expected = manifest.expected as {
  agis: string;
  agent: string;
  card: string;
  jkt: string;
  card_sha256: string;
  valid: boolean;
};

console.log("Raw DNS TXT record:");
console.log(rawTxt);
console.log("");

const binding = parseAgisDnsTxt(rawTxt);

console.log("Parsed binding:");
console.log(JSON.stringify(binding, null, 2));
console.log("");

console.log("Expected:");
console.log(JSON.stringify(expected, null, 2));
console.log("");

const result = validateAgisDnsBinding({
  binding,
  expectedAgentId: expected.agent,
  expectedCardUrl: expected.card,
  expectedJwkThumbprint: expected.jkt,
  expectedCardSha256: expected.card_sha256,
});

if (result.valid && expected.valid) {
  console.log("PASS: DNS binding is valid and matches all expected fields");
} else if (!result.valid) {
  const errList = result.errors.join("\n  ");
  throw new Error(`FAIL: DNS binding validation failed:\n  ${errList}`);
} else {
  throw new Error(
    `FAIL: manifest expected valid=false but binding validated as valid`
  );
}
