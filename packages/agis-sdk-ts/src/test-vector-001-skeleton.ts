import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { sha256Hex } from "./canonicalizeAgentCard.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const agisRoot = path.resolve(__dirname, "../../../");

const canonicalPath = path.join(
  agisRoot,
  "test-vectors/agent-card/skeleton-agent-card.canonical.json"
);
const manifestPath = path.join(
  agisRoot,
  "test-vectors/agent-card/skeleton-agent-card.manifest.json"
);

if (!fs.existsSync(canonicalPath)) {
  throw new Error(`Skeleton canonical not found: ${canonicalPath}`);
}
if (!fs.existsSync(manifestPath)) {
  throw new Error(`Skeleton manifest not found: ${manifestPath}`);
}

const canonical = fs.readFileSync(canonicalPath, "utf8").trimEnd();
const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
const expected = manifest.expected?.sha256 as string;
const computed = sha256Hex(canonical);

console.log("Skeleton canonical hash verification");
console.log("Canonical:");
console.log(canonical);
console.log("");
console.log("SHA-256 (computed):", computed);
console.log("SHA-256 (expected):", expected);
console.log("");

if (computed === expected) {
  console.log("PASS: skeleton Agent Card hash matches manifest");
} else {
  throw new Error(
    `FAIL: skeleton hash mismatch\n  expected: ${expected}\n  computed: ${computed}`
  );
}
