import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { canonicalizeAgentCard, sha256Hex } from "./canonicalizeAgentCard.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const agisRoot = path.resolve(__dirname, "../../../");
const vectorPath = path.join(agisRoot, "test-vectors/agent-card/valid-agent-card.json");
const manifestPath = path.join(agisRoot, "test-vectors/agent-card/valid-agent-card.manifest.json");

if (!fs.existsSync(vectorPath)) {
  throw new Error(`Agent Card not found: ${vectorPath}`);
}
if (!fs.existsSync(manifestPath)) {
  throw new Error(`Manifest not found: ${manifestPath}`);
}

const raw = fs.readFileSync(vectorPath, "utf8");
const card = JSON.parse(raw);

const canonical = canonicalizeAgentCard(card);
const hash = sha256Hex(canonical);

const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
const expected = manifest.expected?.canonical_sha256 as string;

console.log("Vector:");
console.log(vectorPath);
console.log("");
console.log("Canonical:");
console.log(canonical);
console.log("");
console.log("SHA-256 (computed):", hash);
console.log("SHA-256 (expected):", expected);
console.log("");

if (hash === expected) {
  console.log("PASS: Agent Card canonical hash matches manifest");
} else {
  throw new Error(
    `FAIL: Agent Card hash mismatch\n  expected: ${expected}\n  computed: ${hash}`
  );
}
