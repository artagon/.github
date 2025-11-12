<h1 align="center">Artagon Identity Platform</h1>
<p align="center"><strong>Trusted Identity for Machines and Humans — Verified. Private. Attested.</strong></p>

<p align="center">
  <a href="#why-artagon">Why Artagon</a> •
  <a href="#platform-highlights">Platform</a> •
  <a href="#standards--specs">Standards</a> •
  <a href="#roadmap">Roadmap</a> •
  <a href="#get-started">Get Started</a>
</p>

---

## TL;DR

Artagon is a **next-generation identity and authorization platform** that unifies three historically siloed domains:

- **High-Assurance Identity** — Passkey-primary authentication for humans and machines (**OIDC** 2.1, **GNAP**)
- **Decentralized & Verifiable Identity** — **DIDs**, **VCs** (**SD-JWT** & **BBS+**), **OID4VCI/VP**
- **Graph-Native Authorization** — Zanzibar-style **ReBAC** + **Cedar**/**OPA**/**XACML** policy engine

**The Bridge Strategy:** Legacy **OIDC** apps keep working, but now consume **cryptographically verified claims** bridged from **VCs** — introducing verifiable trust without refactoring existing systems.

---

## Why Artagon

### 🔐 Verifiable Everything
Every identity, attribute, device, and client is **cryptographically verified**, not merely "asserted." Move from trust-by-database to trust-by-cryptography.

### ⚡ Zero-Friction Security
The most secure path is the **default path**:
- **Passkey-primary** authentication (phishing-resistant by design)
- Hardened **OAuth**/**GNAP** profiles: **PAR**, **JAR**, **DPoP**, **RAR**, **mTLS**
- Invisible **device attestation** (Android Play Integrity, Apple App Attest, WebAuthn)

### 🛡️ Privacy-by-Design
Privacy embedded at the protocol level:
- **Selective disclosure** — prove facts without revealing raw data
- **Unlinkable presentations** — **BBS+** signatures prevent tracking across verifiers
- **Privacy-preserving revocation** — StatusList2021 (no "phone home" on every check)

---

## Platform Highlights

### Identity & Authentication Core
- **Unified OIDC 2.1 / GNAP provider** with passkey-primary authentication
- **Cryptographic multi-tenancy** — each tenant isolated with dedicated keys (**KMS**/**HSM**)
- **Device & app attestation** engine for machine identity (Android, iOS, Web)

### Decentralized Trust Layer
- **DID methods**: `did:web`, `did:key`, `did:ion`, `did:peer`
- **VC formats**: **SD-JWT** (selective disclosure), **BBS+** (unlinkable ZKP)
- **OID4VCI/VP bridge** — the critical "Trojan Horse" for enterprise adoption:
  - Legacy **OIDC** app initiates standard login
  - Artagon requests **VC** from user's wallet via **OID4VP**
  - Artagon verifies **VC**, mints standard **ID Token** with verified claims
  - **Result**: App gets high-assurance data without knowing VCs were involved

### Authorization Engine
- **Hybrid ReBAC + ABAC model**:
  - **Zanzibar graph** (fast path) — relationship checks in **milliseconds**
  - **Policy overlay** (fine-grained) — **Cedar**, **OPA** (Rego), **XACML** 3.0+
- Full policy lifecycle: **PAP** (Git-backed), **PDP** (runtime), **PEP** (enforcement SDKs)
- Advanced features: decision caching, obligations/advice, audit/explain **APIs**

### Identity Proofing Pipeline
- Pluggable orchestration (not a doc verification vendor)
- Issues **Proofing VC** (**NIST** IAL2/3, **eIDAS** compliant)
- Portable, reusable verification credential

### Delegation & Authority Brokering
The platform's unique synthesis:
- **GNAP** negotiates fine-grained, cross-user delegation
- **Zanzibar** stores delegation as durable relationship tuples
- **Cedar/OPA** enforces conditional, time-bound policies
- **DelegationVC** makes grants portable across trust domains

> **Compounding Trust Chain:**
> User Passkey → Device Attestation → Client **DPoP** Key → Presented **VC** → Policy Engine
> = Cryptographically-bound proof of **trusted user** + **trusted device** + **trusted application**

---

## Standards & Specs

We implement and contribute to:

### Authentication & Authorization
- **OIDC** — OpenID Connect 2.1 (provider, discovery, **JWKS**)
- **GNAP** (**RFC 9635**) — Grant Negotiation and Authorization Protocol
- **PAR** (**RFC 9126**) — Pushed Authorization Requests
- **JAR/JARM** (**RFC 9101**) — **JWT**-secured requests/responses
- **DPoP** (**RFC 9449**) — Demonstrating Proof of Possession
- **RAR** (**RFC 9396**) — Rich Authorization Requests
- **mTLS** (**RFC 8705**) — Mutual TLS client authentication

### Decentralized Identity
- **DIDs** — Decentralized Identifiers (`did:web`, `did:key`, `did:ion`, `did:peer`)
- **VCs** — Verifiable Credentials (**SD-JWT**, **BBS+** signatures)
- **OID4VCI** — OpenID for Verifiable Credential Issuance
- **OID4VP** — OpenID for Verifiable Presentations
- **StatusList2021** — Privacy-preserving credential revocation

### Authorization
- **Zanzibar** — Google's relationship-based access control model
- **Cedar** — Amazon's policy language
- **OPA** (Rego) — Open Policy Agent
- **XACML** 3.0+ — eXtensible Access Control Markup Language

---

## What You Can Build

### High-Assurance Applications
- **Passwordless authentication** with passkeys + device attestation
- **Compliance-ready** identity (**NIST** 800-63, **eIDAS**, **KYC**/**AML**)
- **Phishing-resistant** login for sensitive operations

### Verifiable Credentials Use Cases
- **Bring-your-own-wallet** flows: issue Proofing **VC**, present selectively
- **Cross-domain data sharing** without complex **SAML** federations
- **Privacy-preserving age/attribute verification** (prove without revealing)

### Complex Authorization
- **Customer service delegation** — **CSR** acts on behalf of customer with consent
- **Cross-organization access** — specialist consultation across trust domains
- **AI agent authorization** — bounded, auditable authority for autonomous systems
- **Fine-grained API access** — relationship checks + contextual policy in **<10ms**

---

## Roadmap

### Phase 1: **V1** — Core Trust Layer
**Horizon:** 0–3 months

**Focus:** Minimally viable trust infrastructure

**Milestones:**
- **OIDC**/**GNAP** **MVP** server (Java 25/26 + Virtual Threads + Rust sidecars)
- Hardened profiles: **PAR**, **JAR**, **DPoP**, **RAR**, **mTLS**
- Passkey-primary authentication
- Device attestation **MVP** (Apple App Attest)

**Goal:** **OIDC** conformance certification, secure design partner

---

### Phase 2: **V2** — Verifiable Credentials Layer
**Horizon:** 3–6 months

**Focus:** Activate "Verifiable Everything" pillar

**Milestones:**
- **SD-JWT** issuance via **OID4VCI**
- **OID4VP** verification flows
- **OIDC** bridge (legacy apps consume verified claims)
- StatusList2021 revocation

**Goal:** Enable "verified employee/customer" use cases for partners

---

### Phase 3: **V3** — Policy & Graph Engine
**Horizon:** 6–9 months

**Focus:** Next-generation authorization

**Milestones:**
- Zanzibar graph store (off-heap, globally replicated)
- Polyglot **PDP**: **Cedar**, **OPA**, **XACML**
- **API** **SDKs** (**PEPs**) for Java, Rust, **TS**, Go, Swift
- Git-backed **PAP**

**Goal:** Move beyond "**AuthN**" to "**AuthZ**"; enable complex access control

---

### Phase 4: **V4** — Identity Proofing & **VC** Network
**Horizon:** 9–12 months

**Focus:** Root trust in the real world

**Milestones:**
- Pluggable Proofing **API** (integrate doc verification vendors)
- Issue Proofing **VC** (**NIST** **IAL**2/3)
- **VC** Trust Registry (verifier/issuer trust management)

**Goal:** **NIST** 800-63 / **eIDAS**-compliant provider for regulated markets

---

### Phase 5: **V5** — Federation & **AI** Agents
**Horizon:** 12–18 months

**Focus:** Scale from platform to ecosystem

**Milestones:**
- Multi-issuer trust registry (decentralized federation)
- **BBS+** **VC** support (unlinkable **ZKP** presentations)
- Autonomous agent keys (provision **DIDs** for **AI** agents)
- DelegationVC for cross-domain authority

**Goal:** Trust backbone for ecosystems; "**IAM** for **AI**"

---

## Technology Stack

### Core Services
- **Java 25/26** **LTS** — Virtual Threads (Project Loom) for **I/O**-bound protocols
- **Rust sidecars** — Performance-critical crypto ops (**BBS+**, **ZKP**, graph traversal)
- **FFM API** — High-performance Java ↔ Rust bridge (no **JNI**)

### Data Plane
- **PostgreSQL** — Ground truth (tenants, policies, metadata, audit logs)
- **Redis**/KeyDB — Hot store (sessions, **OIDC** states, nonces, caches)
- **Off-heap graph** — Zanzibar store (avoids **GC** pauses, globally replicated)
- **KMS**/**HSM** — Cryptographic material (tenant keys, issuer keys)

### Observability
- Structured logs, Prometheus metrics, OpenTelemetry tracing
- Replay caches, risk-based analytics

---

## Security Model

**Phishing-Resistant, Zero-Trust by Default:**

| Layer | Mechanism |
|-------|-----------|
| **Authentication** | Passkey-primary (unphishable) |
| **Token Security** | **DPoP** (binds tokens to client key) |
| **Client Security** | Device Attestation + **mTLS** |
| **Transport Security** | **PAR** (back-channel auth requests) |
| **Tenant Isolation** | Cryptographic multi-tenancy (**KMS**/**HSM**) |

**Privacy Model:**

- **Data Minimization** — Zero-knowledge selective disclosure (**SD-JWT**, **BBS+**)
- **Unlinkability** — Ephemeral `did:peer`, **BBS+** unlinkable presentations
- **Portability** — User holds Proofing **VC** in wallet of choice
- **Revocation Privacy** — StatusList2021 (no "call home" to reveal credential)

---

## Competitive Differentiation

Artagon is the **only platform** architected to unify three historically siloed markets:

| Capability | Artagon | Legacy **IAM** (Okta) | Modern **CIAM** (Auth0) | Decentralized Tooling (Trinsic) |
|------------|---------|---------------------|----------------------|--------------------------------|
| **Phishing-Resistant AuthN** | ✅ Passkey-Primary | ⚠️ **MFA** add-on | ⚠️ **MFA** add-on | ❌ Not a provider |
| **Core Protocol** | ✅ **OIDC** 2.1 + **GNAP** | ✅ **OIDC**/**SAML** | ✅ **OIDC** | ❌ Not a provider |
| **Verifiable Credentials** | ✅ **OID4VC**, **SD-JWT**, **BBS+** | ❌ | ❌ | ✅ Core product |
| **Identity Proofing** | ✅ Integrated Proofing **VC** | ⚠️ Partner add-on | ⚠️ Partner add-on | ⚠️ Partner add-on |
| **Device/Machine Identity** | ✅ Hardware Attestation | ❌ | ❌ | ❌ |
| **Authorization Model** | ✅ Zanzibar + **Cedar**/**OPA** | ⚠️ Basic **RBAC**/**ABAC** | ⚠️ Simple Rules/Hooks | ❌ |
| **Developer Experience** | ✅ Playground, **SDKs**, **CLI** | ❌ Enterprise-focused | ✅ Strong DX | ⚠️ Library-focused |

### The "Beachhead" Strategy

We don't compete on "rip-and-replace." We outflank:

1. **Initial:** Target greenfield projects (cloud-native, high-security, complex **AuthZ**)
2. **Establish:** Become "system of record for verifiable trust"
3. **Federate:** Use **OIDC**/**OID4VP** bridge to federate with legacy Okta/**Azure AD**
4. **Consume:** Over time, relegate legacy **IAM** to simple on-premise directory

**Win by** changing the definition of identity from "authentication" to "cryptographic verification."

---

## Developer Experience

### Core Tooling
- **SDKs** — Idiomatic libraries for Java, Rust, **JS**/**TS**, Go, Swift
- **CLI** — Command-line interface for client registration, policy management, **VC** issuance, conformance tests
- **APIs** — Dual **GraphQL** + **REST** (flexibility + standards)

### The Artagon Playground
- **"Docs-as-Code"** site with live playgrounds
- Run real **OIDC**/**GNAP**/**OID4VC** flows in browser
- Test **OPA**/**Cedar** policies interactively
- Dramatically reduce "time-to-first-call"

### Conformance & Trust
- Public **Sandbox** (no signup friction)
- Downloadable conformance test harness
- Prove compliance with **OIDC**, **OID4VC**, other standards

### Ecosystem Engagement
Active participant in standards bodies:
- **IETF** — **GNAP**, **DPoP**, **PAR**
- **OpenID Foundation** — **OIDC**, **OID4VC**
- **W3C** — **DIDs**, **VCs**

**Role:** Reference implementation for next-generation protocols

---

## Use Cases

### 1. Customer Service Delegation (Human → Human, Same Domain)

**Scenario:** **CSR** Alice needs to act on behalf of customer Bob.

**Flow:**
1. Alice clicks "Act on Behalf" → **GNAP** grant request
2. Artagon sends push notification to Bob's passkey-bound app
3. Bob approves "Allow Alice to view account status for 15 minutes"
4. Artagon writes relationship to Zanzibar: `(alice, is_temp_delegate_for, bob)`
5. Issues DelegationVC to Alice, bound to her **DPoP** key
6. Alice's **API** calls → **PEP** checks:
   - **ReBAC**: Does alice have relation to bob? ✅
   - **ABAC**: Is action in **VC** scope? Is **VC** valid? Is **IP** corporate? ✅

**Value:** Least privilege, explicitly consented, time-bound, cryptographically auditable

---

### 2. Specialist Consultation (Human → Human, Cross-Domain)

**Scenario:** Dr. Evans (General Hospital) grants Dr. Smith (Heart Clinic) temporary read access to patient file. Organizations don't share identity systems.

**Flow:**
1. Both orgs use Artagon; Dr. Smith has DoctorVC from Heart Clinic
2. Dr. Evans adds delegate: `did:web:heart-clinic.com:dr-smith`
3. Writes relationship: `(did:...dr-smith, is_viewer_for, patient_file_456)`
4. Dr. Smith accesses file from her clinic portal
5. General Hospital **PEP** challenges via **OID4VP**, requests DoctorVC
6. **PEP** checks:
   - **ABAC**: Is issuer (`did:web:heart-clinic.com`) trusted? ✅
   - **ReBAC**: Does Dr. Smith have `is_viewer_for` relation? ✅

**Value:** Zero-trust cross-domain sharing without **SAML** federations or guest accounts

---

### 3. "Valet Key" for Third-Party Services (Human → Machine, Ephemeral)

**Scenario:** User grants "Financial Analyzer" app one-time read access to last 90 days of transactions.

**Flow:**
1. App initiates **GNAP** flow: `type: "transactions", actions: ["read"], constraints: { date_range: "90d" }`
2. User approves specific, fine-grained request
3. Artagon issues DelegationVC (not broad bearer token), bound to app's attested client key
4. App calls Transaction **API** with DelegationVC + **DPoP** signature
5. **PEP** verifies **VC**, **DPoP** binding, claims

**Value:** Least-privilege capability; no credential sharing; explicit, auditable

---

### 4. **AI** Agent Authorization (Human → Machine, Autonomous)

**Scenario:** **CFO** Jane authorizes **AI** Procurement Agent to sign contracts **<$50,000**.

**Flow:**
1. **AI** Agent has **DID**, keys in **TPM**/**HSM**, software integrity proven by attestation
2. Jane authors long-lived DelegationVC with `policy_reference: "cedar_p-123"`
3. Agent autonomously negotiates contract, calls Procurement **API**
4. **PEP** checks:
   - Verifies DelegationVC signature + **DPoP** binding ✅
   - **ReBAC**: Is agent authorized delegate of Jane? ✅
   - **ABAC**: Fetches **Cedar** policy:
     ```cedar
     permit when { action == "sign_contract" && resource.contract_value_usd < 50000 }
     ```
   - $45K contract: ✅ GRANTED
   - $75K contract: ❌ DENIED

**Value:** Verifiable cryptographic "leash" for **AI**; fuses human authority (**ReBAC**) with auditable rules (**ABAC**)

---

## Vision 2030

### From "Identity" to "Authority"

In a world of **AI** agents and complex data-sharing, the critical question shifts:
- ❌ "Who are you?" (authentication)
- ✅ "What authority do you have?" (authorization)

Artagon's synthesis (Zanzibar + **Cedar**/**OPA**) is purpose-built to answer this.

### **AI** Agents as First-Class Citizens

By 2030, **AI** agents will be primary economic actors, requiring:
- Own **DIDs** and **VCs** (`VC(capability="execute_trade_<$1M")`)
- Governed by fine-grained Artagon policies

**Artagon = "IAM for AI"** — critical trust, governance, and audit layer.

### The "Verifiable Web"

Users move frictionlessly between services:
- Carrying Proofing **VC**, Payment **VC**, Employee **VC** in wallet
- Grant "just-in-time" selective access
- No forms, no new accounts

**Artagon's OID4VP/OIDC bridge** connects "old web" to "verifiable web."

---

## Get Started

### For Developers
- **📚 Documentation:** [docs.artagon.io](#) *(coming soon)*
- **🎮 Playground:** Try live **OIDC**, **GNAP**, and **VC** flows
- **📦 SDKs:** Java, Rust, **TS**, Go, Swift
- **💬 Community:** [GitHub Discussions](#)

### For Enterprises
- **📧 Contact:** enterprise@artagon.io
- **📅 Request Demo:** See Artagon in action
- **🤝 Design Partner Program:** Help shape the future of identity

### For Contributors
- **🌟 GitHub:** [github.com/artagon](https://github.com/artagon)
- **📖 Contributing Guide:** Learn how to contribute
- **🐛 Report Issues:** Help us improve

---

## Community & Contributing

- **💬 Questions / RFCs:** [GitHub Discussions](#)
- **🐞 Issues:** Use repo templates; include logs & versions
- **🤝 Pull Requests:** Welcome! Run conformance tests before review
- **🏛️ Governance:** See [GOVERNANCE.md](#) for decision-making process

---

<p align="center">
  <sub>© 2024 Artagon — Building the trust layer for the next two decades of digital interaction</sub>
</p>

<p align="center">
  <sub>By unifying identity of humans and machines, embedding privacy and zero-friction security at the protocol level, and grounding all trust in cryptographic verification — we're architecting the future of digital trust.</sub>
</p>
