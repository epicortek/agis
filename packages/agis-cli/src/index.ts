#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { execSync } from "node:child_process";
import { Command } from "commander";

import {
  canonicalizeAgentCard,
  sha256Hex,
  jwkThumbprintSha256Base64Url,
  parseAgisDnsTxt,
  sha256ContentDigestHeader,
  validateAgentStatus,
  verifyAgentOffline,
  verifyDelegationToken,
} from "@epicortek/agis-sdk-ts";

// ── Helpers ──────────────────────────────────────────────────────────────────

function readJson(filePath: string): Record<string, unknown> {
  const abs = path.resolve(filePath);
  if (!fs.existsSync(abs)) {
    console.error(`Error: file not found: ${abs}`);
    process.exit(1);
  }
  try {
    return JSON.parse(fs.readFileSync(abs, "utf8")) as Record<string, unknown>;
  } catch (err) {
    console.error(`Error: failed to parse JSON from ${abs}: ${String(err)}`);
    process.exit(1);
  }
}

function readText(filePath: string): string {
  const abs = path.resolve(filePath);
  if (!fs.existsSync(abs)) {
    console.error(`Error: file not found: ${abs}`);
    process.exit(1);
  }
  return fs.readFileSync(abs, "utf8").replace(/\r\n/g, "\n");
}

function printJson(value: unknown): void {
  console.log(JSON.stringify(value, null, 2));
}

// ── CLI setup ─────────────────────────────────────────────────────────────────

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const pkgJson = JSON.parse(
  fs.readFileSync(path.join(__dirname, "../package.json"), "utf8")
) as { version: string };

const program = new Command();

program
  .name("agis")
  .description("AgIS — offline Agent Identity System CLI tools")
  .version(pkgJson.version);

// ── agis card hash ────────────────────────────────────────────────────────────

const card = program.command("card").description("Agent Card commands");

card
  .command("hash")
  .description("Canonicalize an Agent Card and print its SHA-256 hash")
  .requiredOption("--card <path>", "Path to Agent Card JSON")
  .action((opts: { card: string }) => {
    const agentCard = readJson(opts.card);
    try {
      const canonical = canonicalizeAgentCard(agentCard);
      const hash = sha256Hex(canonical);
      console.log(hash);
    } catch (err) {
      console.error(`Error: ${String(err)}`);
      process.exit(1);
    }
  });

// ── agis jwk thumbprint ───────────────────────────────────────────────────────

const jwk = program.command("jwk").description("JWK commands");

jwk
  .command("thumbprint")
  .description("Compute the RFC 7638 JWK Thumbprint of a public JWK")
  .requiredOption("--jwk <path>", "Path to public JWK JSON")
  .action((opts: { jwk: string }) => {
    const jwkObj = readJson(opts.jwk);
    try {
      const thumbprint = jwkThumbprintSha256Base64Url(jwkObj);
      console.log(thumbprint);
    } catch (err) {
      console.error(`Error: ${String(err)}`);
      process.exit(1);
    }
  });

// ── agis dns parse ────────────────────────────────────────────────────────────

const dns = program.command("dns").description("DNS TXT binding commands");

dns
  .command("parse")
  .description("Parse an AgIS DNS TXT binding record")
  .requiredOption("--txt <path>", "Path to DNS TXT record file")
  .action((opts: { txt: string }) => {
    const raw = readText(opts.txt).trim();
    try {
      const binding = parseAgisDnsTxt(raw);
      printJson(binding);
    } catch (err) {
      console.error(`Error: ${String(err)}`);
      process.exit(1);
    }
  });

// ── agis digest body ──────────────────────────────────────────────────────────

const digest = program.command("digest").description("Content-Digest commands");

digest
  .command("body")
  .description("Compute the sha-256 Content-Digest header for a request body file")
  .requiredOption("--body <path>", "Path to request body file")
  .action((opts: { body: string }) => {
    const body = readText(opts.body);
    try {
      const header = sha256ContentDigestHeader(body);
      console.log(header);
    } catch (err) {
      console.error(`Error: ${String(err)}`);
      process.exit(1);
    }
  });

// ── agis status validate ──────────────────────────────────────────────────────

const status = program.command("status").description("Agent Status commands");

status
  .command("validate")
  .description("Validate an Agent Status document against an expected agent ID")
  .requiredOption("--status <path>", "Path to Agent Status JSON")
  .requiredOption("--agent <id>", "Expected agent ID (e.g. agent://example.com/name)")
  .action((opts: { status: string; agent: string }) => {
    const statusDoc = readJson(opts.status);
    const result = validateAgentStatus({
      statusDocument: statusDoc,
      expectedAgentId: opts.agent,
    });
    printJson(result);
    if (!result.valid) process.exit(1);
  });

// ── agis verify identity ──────────────────────────────────────────────────────

const verify = program.command("verify").description("Offline verification commands");

verify
  .command("identity")
  .description("Run offline composite AgIS identity verification")
  .requiredOption("--dns <path>", "Path to DNS TXT binding file")
  .requiredOption("--card <path>", "Path to signed Agent Card JSON")
  .requiredOption("--status <path>", "Path to Agent Status JSON")
  .action(async (opts: { dns: string; card: string; status: string }) => {
    const dnsTxt = readText(opts.dns).trim();
    const signedCard = readJson(opts.card);
    const statusDoc = readJson(opts.status);
    try {
      const result = await verifyAgentOffline({
        dnsTxtRecord: dnsTxt,
        signedAgentCard: signedCard,
        statusDocument: statusDoc,
      });
      printJson(result);
      if (result.decision !== "allow") process.exit(1);
    } catch (err) {
      console.error(`Error: ${String(err)}`);
      process.exit(1);
    }
  });

// ── agis delegation verify ────────────────────────────────────────────────────

const delegation = program.command("delegation").description("Delegation token commands");

delegation
  .command("verify")
  .description("Verify a delegation token from a manifest")
  .requiredOption("--token-manifest <path>", "Path to delegation token manifest JSON")
  .requiredOption("--public-jwk <path>", "Path to issuer public JWK JSON")
  .action(async (opts: { tokenManifest: string; publicJwk: string }) => {
    const manifest = readJson(opts.tokenManifest);
    const publicJwk = readJson(opts.publicJwk);

    const expected = manifest.expected as Record<string, unknown>;
    const token = expected.compact_jws as string | undefined;
    if (!token) {
      console.error("Error: manifest does not contain expected.compact_jws — run test:vector:011 first");
      process.exit(1);
    }

    const issuer = expected.issuer as string;
    const subject = expected.subject as string;
    const audience = expected.audience as string;
    const requiredScopes = (expected.required_scopes as string[] | undefined) ?? [];
    const verifierTime = (expected.verifier_time as string | undefined) ?? new Date().toISOString();

    try {
      const result = await verifyDelegationToken({
        token,
        publicJwk,
        expectedIssuer: issuer,
        expectedSubject: subject,
        expectedAudience: audience,
        requiredScopes,
        verifierTime,
      });
      printJson(result);
      if (!result.valid) process.exit(1);
    } catch (err) {
      console.error(`Error: ${String(err)}`);
      process.exit(1);
    }
  });

// ── agis test-vectors ─────────────────────────────────────────────────────────

program
  .command("test-vectors")
  .description("Run the AgIS SDK test vector suite")
  .action(() => {
    const sdkDir = path.resolve(__dirname, "../../agis-sdk-ts");  // dist/ → agis-cli/ → packages/ → agis-sdk-ts
    if (fs.existsSync(sdkDir)) {
      try {
        execSync("npm run test:vectors", { cwd: sdkDir, stdio: "inherit" });
      } catch {
        process.exit(1);
      }
    } else {
      console.log("Run this from packages/agis-sdk-ts:");
      console.log("  npm run test:vectors");
    }
  });

// ── Parse and execute ─────────────────────────────────────────────────────────

program.parseAsync(process.argv).catch((err: unknown) => {
  console.error(`Fatal: ${String(err)}`);
  process.exit(1);
});
