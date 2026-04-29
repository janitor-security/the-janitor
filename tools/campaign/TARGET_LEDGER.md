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

## Omni-Ledger: Batch 2

Source corpus: `tools/campaign/targets/`. Parsed exactly five additional high-value engagements not listed in Batch 1.

### Binance (`binance_targets.md`)

Rules: cryptocurrency-component issues should be reported directly to the relevant program when applicable; rewards paid in BNB; only working PoCs with security impact qualify; extraordinary impact may be rewarded up to `$100000`; non-security issues go through Binance support.

- [ ] `*.binance.com`, `https://www.binance.com/`, `api.binance.com`, Binance desktop/macOS apps, Binance Android/iOS apps — Binance exchange. Payout: P1 up to `$100000`, P2 `$5000-$10000`. Language: React/JS, API, Java/Kotlin, Swift/Objective-C, desktop native. Focus: auth/session compromise, trading/API authorization, wallet/account data exposure, SSRF/SQLi/RCE with user-fund impact.
- [ ] `api.coinmarketcap.com`, `pro-api.coinmarketcap.com`, `pro.coinmarketcap.com`, `portal-api.coinmarketcap.com`, `coinmarketcap.com`, `3rdparty-apis.coinmarketcap.com`, CoinMarketCap Android/iOS apps — CoinMarketCap surfaces. Payout: P1 up to `$100000`, P2 `$5000-$10000`. Language: API/JS/mobile. Focus: API authz, data integrity, account takeover, mobile storage/session flaws.
- [ ] `*.binance.us`, `https://www.binance.us/`, `binance.tr`, `https://binance.tr` — regional Binance web properties. Payout: P1 up to `$100000`, P2 `$5000-$10000`. Language: React/JS/API. Focus: regional account boundary bypass, payment/trading authorization, sensitive data exposure.
- [ ] Trust Wallet Android/iOS apps, Trust Wallet Chrome Extension, `https://github.com/trustwallet/wallet-core/` — Trust Wallet. Payout: P1 up to `$100000`, P2 `$5000-$10000`. Language: Kotlin/Java, Swift/Objective-C, JS extension, C++ crypto core. Focus: wallet key/session exposure, signing-flow integrity, extension XSS, crypto invariant breaks.

### Cisco ThousandEyes (`cisco_thousandeyes_targets.md`)

Rules: append `Bugcrowd-<BugcrowdUsername>` to all HTTP user agents; no automated vulnerability scans or brute-force enumeration; use `@bugcrowdninja.com` signup; do not access, alter, or download customer data; no DoS; no manually crafted or altered agent ingress/controller traffic; edited binaries do not qualify.

- [ ] `https://app.thousandeyes.com/` — ThousandEyes SaaS application. Payout: P1 `$4100-$4500`, P2 `$1500-$1750`. Language: Java/Vue.js. Focus: IDOR, authentication bypass, cross-account access, incorrect permissions, SQLi, XSS, RCE, file inclusion/traversal.
- [ ] `https://api.thousandeyes.com/` — customer API. Payout: P1 `$4100-$4500`, P2 `$1500-$1750`. Language: HTTP API/Java service surface. Focus: API authorization, data exposure, command injection, auth/session flaws.
- [ ] `https://www.thousandeyes.com/` — public website. Payout: P1 `$4100-$4500`, P2 `$1500-$1750`. Language: Java/jQuery/Moment.js web. Focus: account creation/auth flows, XSS with impact, injection, sensitive disclosure.
- [ ] ThousandEyes Enterprise Agent and Endpoint Agent — Linux and Windows agents. Payout: P1 `$4100-$4500`, P2 `$1500-$1750`. Language: Linux/Windows native agent surface. Focus: local privilege escalation, agent configuration/test-setting abuse, authorization boundary issues without crafted controller traffic.

### Cloudinary (`cloudinary_targets.md`)

Rules: use `@bugcrowdninja.com`; no automated scanners; no webshell upload or persistent connections; do not access/modify data beyond proof; no support-system testing; external SSRF through intended fetch/upload URL behavior is out unless internal-network or significant security impact is shown.

- [ ] `https://cloudinary.com/console` — Cloudinary console. Payout: P1 `$7000`, P2 `$2000-$4000`. Language: Ruby on Rails/web. Focus: IDOR, privilege escalation, auth vulnerabilities, XSS/CSRF with impact, business logic bypass.
- [ ] `https://api.cloudinary.com` — Cloudinary API. Payout: P1 `$7000`, P2 `$2000-$4000`. Language: Ruby on Rails/JSON API. Focus: API authz, injection, server-side code execution, sensitive data exposure, internal SSRF through media-ingest primitives.
- [ ] `https://res.cloudinary.com` — resource delivery and transformation surface. Payout: P1 `$7000`, P2 `$2000-$4000`. Language: Ruby on Rails/JSON/media pipeline. Focus: transformation authorization, internal fetch abuse, file handling, cache/data isolation.
- [ ] `https://mediaflows.cloudinary.com/`, `https://dimensions.cloudinary.com` — Tier II tools. Payout: P1 `$500-$1000`, P2 up to `$500`. Language: AWS/API/web. Focus: auth/session, API authorization, injection, security misconfiguration.

### Mattermost (`mattermost_targets.md`)

Rules: sign up with `@bugcrowdninja.com`; use listed cloud/self-hosted targets and official plugins; `*.mattermost.com` is in scope but ineligible for bounty; no brute force, DDoS, social engineering, rooted/jailbroken-only mobile issues, public plugin findings beyond informational, or Enterprise Edition unlock attacks.

- [ ] `https://bugcrowd-*your-own-instance*.cloud.mattermost.com/` and Mattermost source install — core platform. Payout: P1 `$2000`, P2 `$750`. Language: Go/React/TypeScript. Focus: authz, cross-team isolation, role/permission bypass, plugin trust boundaries, XSS/SSRF where cloud-impacting.
- [ ] Mattermost Android/iOS/mobile and desktop apps — clients. Payout: P1 `$2000`, P2 `$750`. Language: TypeScript/React Native/Java/Objective-C/Electron. Focus: session/local storage, deep links, desktop IPC, mobile auth boundary issues.
- [ ] Mattermost Jira, Zoom, GitHub, GitLab, Calls, Playbooks, Boards, Copilot, MS Calendar, MSTeams, and Confluence plugins — official plugin ecosystem. Payout: P1 `$2000`, P2 `$750`. Language: Go/TypeScript/React. Focus: OAuth/integration token handling, webhook verification, cross-plugin authz, command injection, stored XSS in workflow content.

### Tesla (`tesla_targets.md`)

Rules: research must use owned accounts or owned Tesla products; immediately stop and report if other-customer data or accounts become accessible; hardware research on owned vehicles/Powerwall must be registered with Tesla first; do not brute force or DoS without written approval; vehicle/product issues should be reported through Tesla's direct channel.

- [ ] `*.tesla.com`, `*.teslamotors.com`, `*.tesla.cn`, `*.tesla.services`, `*.solarcity.com`, `*.teslainsuranceservices.com`, and Tesla-owned verified hosts/IP space — non-vehicle web properties. Payout: P1 `$3000-$10000`, P2 `$500-$4000`. Language: Drupal/web/API/CDN. Focus: account/authz, sensitive data exposure, injection, SSRF, business logic, cloud/CDN misconfiguration with exploitability.
- [ ] Official Tesla iOS and Android apps — mobile clients. Payout: P1 `$3000-$10000`, P2 `$500-$4000`. Language: Swift/Objective-C, Java/Kotlin. Focus: mobile auth/session, deep-link abuse, local storage, API authorization, vehicle/account command boundary issues using owned assets.

## Omni-Ledger: Batch 3

Source corpus: `tools/campaign/targets/`. Parsed exactly five additional engagements not listed in Batches 1-2.

### Canva (`canva_targets.md`)

Rules: focus on user-data confidentiality, collaboration boundaries, developer platform isolation, and exploitable third-party misconfiguration; legacy authentication issues in some Canva-branded apps may be ineligible if they match known deprecation patterns.

- [ ] `https://www.canva.com` — Canva Editor and core product. Payout: P1 `$15000`, P2 `$4000`. Language: Java/web/JS. Focus: authn/authz, team/org access control, design/data exposure, AI tool boundary issues, SQLi/RCE, content injection.
- [ ] `https://www.canva.com/developers/`, `https://api.canva.com`, Apps SDK Sandboxing — Developer Platform. Payout: P1 `$15000`, P2 `$4000`. Language: API/JS sandbox. Focus: Connect API IDOR, developer key/app settings access, sandbox escape, injected content in developer tooling.
- [ ] `*.canva.com`, `*.canva-apps.com`, `*.canva.tech` — services and infrastructure. Payout: P1 `$15000`, P2 `$4000`. Language: Java/MySQL/web/cloud. Focus: Canva-operated service compromise, customer-data exposure, AWS/Cloudflare misconfiguration with tangible impact.

### Fivetran (`fivetran_targets.md`)

Rules: use only `@bugcrowdninja.com` accounts; do not access or modify customer data beyond proof; no DoS; no AI tools during research; do not contact Fivetran directly for follow-up; only P1-P3 rewarded.

- [ ] `*.fivetran.com`, `https://fivetran.com/login` — Fivetran product surface. Payout: P1 `$2500-$7500`, P2 `$1000-$2500`, P3 `$500-$1000`. Language: Java/Kubernetes/web. Focus: auth/session, connector/data-plane authorization, sensitive data exposure, service compromise.
- [ ] Fivetran Connector SDK CTF at `https://fivetran.com/login` — sandboxed connector feature. Payout: P1 `$15000`. Language: Python/Kubernetes sandbox. Focus: connector sandbox escape, target-account secret extraction, internal-service reachability from untrusted connector execution.

### SAP (`sap_targets.md`)

Rules: this page is an invitation funnel; direct submissions to this page are Not Applicable. Eligibility requires Bugcrowd background check, SAP NDA, >=80% accuracy, and a valid P3+ submission. No DoS, resource exhaustion, DNS poisoning, rootkits, real PII, or non-listed SAP domains.

- [ ] SAP SuccessFactors, S/4HANA Cloud Public/Private, Integrated Business Planning, Cloud ALM, Customer Data Cloud/CDP, Business Network, BusinessObjects BI, SAP AI Core, WalkMe, Signavio, BusinessOne, and listed SAP SaaS products — private SAP engagements. Payout: P1 `$4000-$20000`, P2 `$2000-$7500`, P3 `$700-$2500`, P4 `$250-$600`. Language: enterprise Java/SAP web/mobile/API. Focus: authz, tenant isolation, PII exposure, workflow/business-logic compromise, AI Core model/data boundary issues, mobile/web application flaws.

### Mastercard (`mastercard_targets.md`)

Rules: regional sites are in scope only on core Mastercard domains; use provided test data where specified; Recorded Future, `biz360.mastercard.com`, and `mybiz360.mastercard.com` are out of scope; Public Other/vendor applications pay lower bounties; subdomain takeover has separate payout rules.

- [ ] Mastercard regional public sites, `https://developer.mastercard.com`, `https://performancemarketing.mastercard.com/portal/`, `https://src.mastercard.com/*`, Finicity APIs/apps, Priceless demo, Donate, and listed Mastercard assets — Public Targets. Payout: P1 `$5000`, P2 `$2000`. Language: Java/AEM/Vue/ASP.NET/Node/PHP/API. Focus: payment/auth flows, API authorization, checkout/SRC integration, account/data exposure, SQLi/RCE, subdomain takeover with impact.
- [ ] Public Other Mastercard-owned or M&A targets — lower-tier catch-all. Payout: P1 `$700-$2500`, P2 `$300-$1000`. Language: web/API/vendor apps. Focus: demonstrable Mastercard-owned security impact; vendor lower environments pay 50% of standard.

### Recorded Future (`recorded_future_targets.md`)

Rules: test only listed targets; non-listed Recorded Future assets are appreciated but not reward-eligible; use `@bugcrowdninja.com` for self-provisioned accounts where available; no DoS, non-auth brute force/rate limit, missing cookie/security headers, software-version disclosure, or low-impact open redirects.

- [ ] `https://www.recordedfuture.com`, `https://tria.ge`, `https://id.recordedfuture.com`, `https://hatching.io`, `https://geminiadvisory.io`, `https://app.recordedfuture.com`, `https://api.recordedfuture.com`, `https://securitytrails.com` — Recorded Future web/API estate. Payout: P1 `$5000`, P2 `$2000`, P3 `$750`, P4 `$250`. Language: web/API/threat-intel platforms. Focus: auth/session, API authorization, tenant/data exposure, XSS with impact, injection, account boundary issues.
- [ ] Recorded Future iOS and Android apps — mobile clients. Payout: P1 `$5000`, P2 `$2000`. Language: iOS/Android. Focus: mobile auth/session, local data exposure, deep links, API authorization, threat-intel data boundary issues.

## Parsed Engagements

- `tools/campaign/targets/okta_targets.md`
- `tools/campaign/targets/openai_targets.md`
- `tools/campaign/targets/clickhouse_targets.md`
- `tools/campaign/targets/fireblocks_web_targets.md`
- `tools/campaign/targets/opensea_targets.md`
- `tools/campaign/targets/binance_targets.md`
- `tools/campaign/targets/cisco_thousandeyes_targets.md`
- `tools/campaign/targets/cloudinary_targets.md`
- `tools/campaign/targets/mattermost_targets.md`
- `tools/campaign/targets/tesla_targets.md`
- `tools/campaign/targets/canva_targets.md`
- `tools/campaign/targets/fivetran_targets.md`
- `tools/campaign/targets/sap_targets.md`
- `tools/campaign/targets/mastercard_targets.md`
- `tools/campaign/targets/recorded_future_targets.md`
