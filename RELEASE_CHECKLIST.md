# Release Checklist

Use this checklist before tagging or publishing any release of `@epicortek/agis-sdk-ts` or `@epicortek/agis-cli`.

---

## 1. Local verification

Run the full build, type-check, test-vector, and smoke-test pipeline:

```bash
npm install
npm run verify
npm run smoke:pack
npm run verify:release
npm run release:audit
npm run release:check
```

All commands must exit with code 0. No test vectors may be skipped.

> Before public release, confirm security@epicortek.com is active and monitored.

---

## 2. Package dry run

Confirm what each package will publish without actually publishing:

```bash
# SDK
cd packages/agis-sdk-ts && npm publish --dry-run --tag alpha

# CLI
cd packages/agis-cli && npm publish --dry-run --tag alpha
```

Or via root scripts:

```bash
npm run publish:dry-run
```

> **Note:** The `--tag alpha` flag is required for prerelease versions (`x.y.z-alpha.N`). Without it, npm refuses to publish to prevent accidentally overwriting the `latest` dist-tag.

Review the file list in the dry-run output. Confirm:
- Only `dist/`, `README.md`, `LICENSE`, and `package.json` are included in the SDK tarball.
- Only `dist/`, `README.md`, and `package.json` are included in the CLI tarball.
- No source files, test vectors, or private keys are included.

---

## 3. Manual CLI smoke

```bash
node packages/agis-cli/dist/index.js --version
node packages/agis-cli/dist/index.js card hash --card test-vectors/agent-card/valid-agent-card.json
node packages/agis-cli/dist/index.js jwk thumbprint --jwk test-vectors/keys/ed25519-test-public.jwk.json
node packages/agis-cli/dist/index.js dns parse --txt test-vectors/dns/valid-dns-binding.txt
node packages/agis-cli/dist/index.js digest body --body test-vectors/requests/valid-request-body.json
```

---

## 4. Security

- [ ] Confirm no private keys are present except deterministic test keys under `test-vectors/keys/`.
- [ ] Confirm no `.env` file is tracked by git.
- [ ] Confirm no production secrets appear in any source or data file.
- [ ] Confirm `security@epicortek.com` is active and monitored before public release.

---

## 5. Versioning

- [ ] `packages/agis-sdk-ts/package.json` version matches the intended release.
- [ ] `packages/agis-cli/package.json` version matches the intended release.
- [ ] Root `package.json` version matches.
- [ ] `CHANGELOG.md` has an entry for this version.
- [ ] Tag name candidate: `v0.2.2-alpha.1`

---

## 6. Not yet included in this release

The following features are **out of scope** for `v0.2.2-alpha.1` and must not be implied as supported:

- Live DNS resolution
- Live HTTP fetching of Agent Cards or status documents
- Resolver API
- DNSSEC validation
- Persistent replay cache (in-memory only)
- Production trust registry
- OAuth / OIDC integration
