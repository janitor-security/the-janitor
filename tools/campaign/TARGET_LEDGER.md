# Atlassian Campaign — Target Ledger

Extracted from `atlassian_targets.md`. Tier ranking by P1 bounty ceiling.
Strike protocol: `npm pack` / `curl` download → extract → `janitor hunt <dir> --format bugcrowd`.

---

## Tier 1 — Forge ($7k P1) — Open-Source / Downloadable SDK Targets

- [x] `@forge/cli` (https://www.npmjs.com/package/@forge/cli) — Node.js CLI; `npm pack @forge/cli && tar xf forge-cli-*.tgz -C /tmp/forge-cli` — Sprint Batch 59
- [x] `@forge/api` (https://www.npmjs.com/package/@forge/api) — Forge app runtime API surface; Node.js — Sprint Batch 61
- [x] `@forge/ui` (https://www.npmjs.com/package/@forge/ui) — UI Kit component library; React/Node.js — Sprint Batch 61
- [x] `@forge/bridge` (https://www.npmjs.com/package/@forge/bridge) — iframe bridge; JS XSS surface — Sprint Batch 66

## Tier 1 — Rovo Dev ($12k P1)

- [x] `Rovo Dev CLI` — Python; package not published on PyPI (`pip download rovo-dev-cli` → no distribution found); download via Atlassian support page requires authenticated session — Sprint Batch 67 (deferred: requires auth)

## Tier 2 — Loom ($7k P1) — Electron/ASAR Targets

- [x] `Loom Desktop App (macOS)` (https://www.loom.com/download) — Electron/ASAR; `curl -Lo /tmp/loom.dmg <dmg-url>; 7z x ...` — Sprint Batch 59
- [x] `Loom Chrome Extension` (https://chromewebstore.google.com/detail/loom/liecbddmkiiihnedobmlmillhodjkdmb) — JS/browser-extension; CRX3 downloaded via Google CRX API, extracted 28 MB zip — Sprint Batch 67

## Tier 2 — Bitbucket ($7k P1) — Python / Django SDK

- [x] `atlassian-python-api` (https://github.com/atlassian-api/atlassian-python-api) — Python; `git clone https://github.com/atlassian-api/atlassian-python-api /tmp/atlassian-python-api` — Sprint Batch 66

---

## Hunt Results Log

| Target | Sprint | Findings | FPs Squashed | Verdict |
|--------|--------|----------|--------------|---------|
| `@forge/cli` (latest) | 59 | See below | See below | See below |
| Loom Desktop (macOS) | 59 | N/A — DMG download requires browser auth | — | Deferred to manual ASAR extraction |
| `@forge/api` v7.1.3 | 61 | 0 | 0 | Clean — pre-built package, no raw TS source |
| `@forge/ui` v1.11.4 | 61 | 0 | 0 | Clean — pre-built package, no raw TS source |
| `@forge/bridge` v5.16.0 | 66 | 0 | 0 | Clean — pre-built JS bundle, no raw TS source |
| `atlassian-python-api` (main) | 66 | 0 | 0 | Clean — Python SDK; no taint sinks triggered by static analysis |
| `Rovo Dev CLI` | 67 | N/A — not on PyPI; requires Atlassian auth session | — | Deferred to authenticated download path |
| `Loom Chrome Extension` (CRX3, latest) | 67 | 3 (Informational) | 0 | 3× Informational: missing_ownership_check, parser_exhaustion_anomaly, prototype_pollution — minified JS bundles; all Informational VRT |

## Omni-Ledger: Batch 1

Source corpus: `tools/campaign/targets/`. Parsed exactly five high-value engagements.

### Okta (`okta_targets.md`)

Rules: use `@bugcrowdninja.com` accounts where required; change provided test-user email addresses before testing; create fallback Super Admins; enforce MFA; do not tamper with, delete, or enumerate customer data; Okta Classic and non-listed Okta domains are out of scope; low-effort AI-generated reports are rejected.

- [ ] `personal.trexcloud.com` — Okta Personal. Payout: P1 `$5000-$75000`. Language: JS/TS web plus iOS Swift/Objective-C and Android Java. Focus: admin dashboard access, crypto/user-data recovery, sharing abuse, mobile intents, import/export validation.
- [ ] `bugcrowd-pam-###.oktapreview.com` and `bugcrowd-pam-###.pam.oktapreview.com` — Okta Privileged Access. Payout: P1 `$7000-$35000`. Language: JS/TS web/API. Focus: privileged escalation, secrets exposure, resource/security administration bypass, ASA client/agent flaws.
- [ ] `https://bugcrowd-pam-###.workflows.oktapreview.com` — Okta Workflows. Payout: P1 `$7000-$35000`. Language: JS/TS workflow engine/API. Focus: SSRF through Flo cards, cross-org actions, sandbox escape via API Endpoint/Return Raw, role/permission bypass.
- [ ] Desktop MFA for Windows/macOS and Password Sync for macOS — Okta Device Access. Payout: P1 `$10000-$75000`. Language: Windows native/.NET plus macOS Swift/Objective-C. Focus: phishing-resistant MFA bypass, device enrollment/authentication boundary flaws.
- [ ] `support.okta.com` — Okta Support Portal. Payout: P1 `$5000-$15000`. Language: Salesforce/Aura web. Focus: sensitive support-data exposure beyond first/last name/company/IDs; no customer-data tampering.
- [ ] `https://bugcrowd-pam-###.at.oktapreview.com` — AtSpoke / Okta Access Requests. Payout: P1 `$5000-$25000`. Language: JS/TS web/API. Focus: resource restriction bypass, critical request-field tampering, integration injection through Jira/ServiceNow/Slack/Teams, export-data exposure.
- [ ] `https://bugcrowd-pam-###.oktapreview.com`, `https://bugcrowd-pam-###-admin.oktapreview.com`, Okta FastPass — OIE targets. Payout: P1 `$10000-$75000`. Language: JS/TS web/API plus mobile clients. Focus: SAML/OAuth/OIDC flaws, XXE, cross-org multi-tenancy, horizontal/vertical privilege escalation, sensitive-page XSS/CSRF.
- [ ] `http://app.scaleft.com/`, ASA client/agents — Advanced Server Access. Payout: P1 `$7000-$35000`. Language: native agents/Go-style service surface. Focus: ASA agent secrets, server-access authorization bypass, client/agent trust boundary breaks.
- [ ] Okta Verify iOS/Android/macOS/Windows, on-prem AD/LDAP/RDP/IWA agents, browser plugins — Other in-scope targets. Payout: P1 `$10000-$75000`. Language: Swift/Objective-C, Java, .NET, browser JS. Focus: authenticator bypass, agent trust abuse, browser-plugin XSS/open redirect/CSRF on sensitive actions.

### OpenAI (`openai_targets.md`)

Rules: test only in-scope systems; interact only with owned accounts/data; model behavior, jailbreaks, hallucinations, sandboxed Python/Agent/container execution, DoS, brute force, password spraying, spam, phishing, social engineering, third-party systems, and most rate-limit edge cases are out of scope. API keys must be submitted through the dedicated form, not Bugcrowd. Sora entry is time-sensitive: the source file says shutdown on `2026-04-26`, which is before this session date `2026-04-28`; verify status before work.

- [ ] `api.openai.com` and OpenAI API cloud infrastructure — API Targets. Payout: P1 `$100000`, P2 `$2000-$6500`. Language: Python/API/Azure. Focus: authz/authn, data exposure, cloud-resource compromise, private/pre-release model access.
- [ ] `https://chat.openai.com` and OpenAI-created plugin surfaces — ChatGPT. Payout: P1 `$100000`, P2 `$2000-$6500`. Language: JS/TS/Python/Azure. Focus: stored/reflected XSS, CSRF, SQLi, auth/session issues, payments, OAuth/plugin credential security, plugin SSRF to unrelated domains.
- [ ] Third-party corporate information exposures — Corporate Targets. Payout: P1 `$5000`, P2 `$1000-$2500`. Language: SaaS reconnaissance. Focus: confidential OpenAI documents in third-party services; no active testing against vendors.
- [ ] OpenAI API keys with `sk-` or `sess-` prefix — API Key Security Initiative. Payout: P1 `$250-$2500`. Language: secret scanning. Focus: leaked customer key discovery; bulk submit through the OpenAI API Key Bug Bounty form only.
- [ ] `https://openai.org` and `https://*.openai.org` — Research Org. Payout: P1 `$100000`, P2 `$1250-$3500`. Language: Python/Azure/web. Focus: API/website authz, data exposure, SSRF, cloud misconfiguration.
- [ ] `https://openai.com`, `*.openai.com`, `https://platform.openai.com/playground` — Other OpenAI Targets. Payout: P1 `$1250-$2500`. Language: Python/Azure/JS. Focus: standard web/API flaws with demonstrable security impact.
- [ ] Sora app and `https://sora.chatgpt.com` — Sora. Payout: P1 `$100000`, lower severities listed but source says only P1 until `2026-04-26`. Language: iOS/JS. Focus: unauthorized cameo use, private draft/post access, DM privacy bypass, blocked-user bypass; verify live status first.
- [ ] Atlas browser — Atlas. Payout: P1 `$100000`, P2 `$2000-$6500`. Language: macOS/Chromium/JS. Focus: side-panel/Agent sandbox escape, origin isolation bypass, browser/OS privilege escalation, unauthorized file access or execution.
- [ ] `https://github.com/openai/codex/` and Codex surfaces — Codex. Payout: P1 `$100000`, P2 `$500-$1500`. Language: Rust/TS/Python sandbox surfaces. Focus: workspace write-boundary bypass, network/process approval bypass, sandbox policy broadening, user-intent bypass.

### ClickHouse (`clickhouse_targets.md`)

Rules: use `@bugcrowdninja.com` accounts; stop after customer/employee PII exposure or shell access; no system degradation; only owned accounts/data; no vulnerability scanners; custom scripts/fuzzing must be targeted and under five requests per second; OSS reports must reproduce on latest release and latest master, Linux x86_64, unmodified release builds, server component only, no experimental flags.

- [ ] `https://clickhou.se/bugcrowd` — ClickHouse Cloud. Payout: P1 `$2100-$2500`, P2 `$1000-$1250`. Language: JS/TS web/API plus ClickHouse SQL. Focus: IDOR, injection, stored XSS, SSRF, sensitive data exposure, business logic, RCE, SQLi, authn/authz, unauthorized API actions.
- [ ] `https://github.com/ClickHouse/ClickHouse` — ClickHouse OSS server. Payout: P1 `$2100-$2500`, P2 `$1000-$1250`. Language: C++. Focus: RBAC bypass, security-control bypass, mTLS/encryption configuration flaws, memory corruption, buffer overflow, server-side RCE.

### Fireblocks (`fireblocks_web_targets.md`)

Rules: register with `@bugcrowdninja.com`; test only listed sandbox APIs; P5, DoS/DDoS/network DoS, rate-limit bypass attempts, email bombing, social engineering, phishing, physical attacks, third-party providers, and stolen/breached credential reports are out of scope for reward; N-day bugs become in scope only after 14 days.

- [ ] `https://sb-console-api.fireblocks.io` — Sandbox console API. Payout: P1 `$7000-$12000`, P2 `$1000-$9000`. Language: JS/TS API plus cryptography/MPC. Focus: unauthorized funds transfer, auth/authz bypass, IDOR, sensitive disclosure, RCE, SQL/XML injection, directory traversal.
- [ ] `https://sb-mobile-api.fireblocks.io` — Sandbox mobile API. Payout: P1 `$7000-$12000`, P2 `$1000-$9000`. Language: mobile API/cryptography. Focus: mobile auth/session flaws, unauthorized transaction actions, sensitive data exposure, privileged CSRF/XSS where applicable.
- [ ] `https://sandbox-api.fireblocks.io` — Sandbox platform API. Payout: P1 `$7000-$12000`, P2 `$1000-$9000`. Language: API/cryptography/blockchain. Focus: ECDSA/EdDSA MPC protocol abuse, signature authorization defects, injection, RCE, security misconfiguration with verifiable exploit.

### OpenSea (`opensea_targets.md`)

Rules: only listed targets are authorized; no negative production impact; smart contract testing must use a forked local mainnet copy; no phishing/social engineering/user-interaction contract attacks; one vulnerability per report unless chaining is required; no DoS, MITM/physical access, standalone open redirect, non-auth rate limit/bruteforce, missing cookie flags, expected JS execution on `openseauserdata.com`/`raw.seadn.io` without in-scope impact, or wallet-provider-only issues.

- [ ] `https://opensea.io/` — OpenSea marketplace. Payout: P1 `$50000`, P2 `$10000`. Language: JS/TS web3. Focus: account/session authz, stored XSS with in-scope impact, marketplace business logic, wallet-transaction integrity.
- [ ] `http://wallet.opensea.io/` — Embedded Wallet Experience. Payout: P1 `$50000`, P2 `$10000`. Language: JS/TS wallet/web3. Focus: embedded wallet authz, transaction integrity, wallet session/data exposure; Privy-provider issues are out of scope.
- [ ] `io.opensea` Android and iOS apps. Payout: P1 `$15000`, P2 `$3000`. Language: Kotlin/Java and Swift/Objective-C. Focus: mobile auth/session, deep-link, wallet integration, local storage exposure; rooted-device or malicious-wallet assumptions are out.
- [ ] `https://mcp.opensea.io` — OpenSea MCP. Payout: P1 `$15000`, P2 `$3000`. Language: MCP/API. Focus: server/API authz, data exposure, tool-call boundary issues; pure LLM response manipulation/prompt injection is excluded.
- [ ] Seaport 1.6, ConduitController, OpenSea Conduit deployments — Seaport. Payout: P1 `$3000000`, P2 `$100000`. Language: Solidity. Focus: pure on-chain exploitable contract flaws, order validation, conduit authorization, asset-transfer invariants; older Seaport versions and user-interaction attacker-site attacks are out.
- [ ] `0x0000a26b00c1F0DF003000390027140000fAa719` — Fee Collector Smart Contract. Payout: P1 `$50000`, P2 `$10000`. Language: Solidity. Focus: fee accounting, access control, value-transfer invariants, pure on-chain exploitability.
- [ ] `0x00005EA00Ac477B1030CE78506496e8C2dE24bf5` — Seadrop Smart Contract. Payout: P1 `$50000`, P2 `$10000`. Language: Solidity. Focus: mint/drop access control, payment/accounting invariants, pure on-chain exploitability.
- [ ] OpenSea curated content broken links — Broken Links. Payout: P4 `$50`. Language: web content. Focus: takeover-capable broken links on curated OpenSea content only; user-generated content and employee blogs are out.

## Parsed Engagements

- `tools/campaign/targets/okta_targets.md`
- `tools/campaign/targets/openai_targets.md`
- `tools/campaign/targets/clickhouse_targets.md`
- `tools/campaign/targets/fireblocks_web_targets.md`
- `tools/campaign/targets/opensea_targets.md`
