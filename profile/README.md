# **The Unified Identity Platform: Trusted Identity for Machines and Humans - Verified, Private, Attested**

---

## **1. Executive Summary**

The digital landscape is in the midst of a profound identity crisis. The foundational model of perimeter-based security has failed, giving way to an epidemic of data breaches fueled by compromised credentials.

The very concept of "identity" has become dangerously fragmented, split between human-centric systems (**CIAM**) and a separate, ad-hoc world of machine and device identity (**M2M**/**IoT**). This fragmentation, coupled with the erosion of consumer privacy, creates a landscape of significant risk, friction, and missed opportunity.

Artagon Identity Platform is architected to solve this crisis. The platform's mission is to deliver: **"Trusted Identity for Machines and Humans — Verified, Private, Attested."**

This mission statement is not a platitude; it is an architectural blueprint. Artagon is not merely another identity provider (**IdP**) or a simple **CIAM** solution. It is a next-generation trust infrastructure platform designed from the ground up to unify the three most critical, and historically siloed, domains of digital trust:

- **High-Assurance Identity:** A unified, passkey-primary foundation for phishing-resistant human authentication, built on the most secure, modern protocols (**[OIDC][oidc]**, **[GNAP][gnap]**).

- **Decentralized & Verifiable Identity:** A complete **[VC][vc]** engine for issuing and verifying portable, holder-controlled, and privacy-preserving credentials.

- **Next-Generation Authorization:** A high-performance, graph-based authorization engine that fuses relationship-based and policy-based access control for complex, fine-grained decisions.

The Artagon vision is built on three strategic pillars:

- **Verifiable Everything:** Every identity, attribute, device, and software client can be cryptographically verified, moving the world from "asserted" identity to "proven" identity.

- **Zero-Friction Security:** The most secure posture is delivered as the path of least resistance. This is achieved through passkey-primary authentication (simpler and more secure than passwords) and invisible, hardware-level device attestation.

- **Privacy-by-Design:** Privacy is embedded at the protocol level, not as a compliance checkbox. The platform uses selective disclosure and zero-knowledge primitives, allowing users to prove facts about themselves without revealing underlying personal data.

For enterprises, Artagon de-risks digital transformation, eliminates the primary vector of account takeover, and provides a clear path to proving compliance with frameworks like **[NIST 800-63-3][nist-800-63]** and **[eIDAS][eidas]**.

For developers, Artagon provides a single, unified "trust **API**," abstracting the immense complexity of modern cryptography, protocols, and policy.

For end-users, it delivers on the long-held promise of a truly portable, private, and secure digital identity.

This document outlines the strategic vision, core capabilities, and pragmatic multi-phase roadmap for the Artagon Identity Platform. The roadmap details a practical execution plan, beginning with a core trust layer (V1) and scaling methodically to a federated, **AI**-enabled trust ecosystem (V5).

[oidc]: https://openid.net/connect/
[gnap]: https://datatracker.ietf.org/doc/rfc9635/
[vc]: https://www.w3.org/TR/vc-data-model-2.0/
[nist-800-63]: https://csrc.nist.gov/publications/detail/sp/800-63/3/final
[eidas]: https://digital-strategy.ec.europa.eu/en/policies/eidas-regulation

---

## **2. Product Vision & Value Proposition**

**Mission: Trusted Identity for Machines and Humans — Verified, Private, Attested.**

The Artagon mission is a deliberate, strategic synthesis of capabilities that are essential for the next era of digital interaction. A breakdown of this mission reveals the core of the product vision:

- **"Trusted Identity...":** This signifies a fundamental shift in perspective. The goal is not merely "authentication"—proving a user knows a secret—but establishing verifiable trust and assurance. This trust is rooted in cryptographic proofs, not in a centralized, mutable database profile.

- **"...for Machines and Humans...":** This is an explicit rejection of the market's current fragmentation. The platform is architected to unify the **CIAM** (human) and **M2M**/**IoT** (machine) identity markets.
  - **Human Identity** is secured via phishing-resistant passkeys (**[WebAuthn][webauthn]**) and verifiable attributes from the Identity Proofing pipeline.
  - **Machine Identity** is secured via platform-native device attestation (**[Android Play Integrity][play-integrity]**, **[Apple App Attest][app-attest]**), automatic per-instance credential rotation, and **[mTLS][mtls]**.

- **"...Verified, Private, Attested.":** These three words map directly to the platform's core technical pillars and capabilities:
  - **Verified:** All identity assertions are verifiable. This is enabled by the Identity Proofing pipeline, which produces a Proofing **VC**, and the Verifiable Credentials layer, which issues and verifies these proofs.
  - **Private:** User privacy is a non-negotiable architectural primitive. This is enabled by the Decentralized & Verifiable Identity Layer, which supports zero-knowledge selective disclosure (**[SD-JWT][sd-jwt]**, **[BBS+][bbs]**) and unlinkable presentations.
  - **Attested:** Trust in the client is as important as trust in the user. This is enabled by the Device & Application Attestation engine, which proves the integrity of the device and application initiating a request.

### **The Three Pillars of the Artagon Vision**

The product strategy is executed through three foundational pillars that guide architecture, feature development, and market positioning.

**Pillar 1: Verifiable Everything**

This is the central strategic thesis. The future of digital trust cannot rely on siloed, organization-specific assertions stored in proprietary databases. The future is portable, interoperable, and cryptographically verifiable proofs.

This pillar is technically enabled by the platform's dual support for standard **OIDC**/**OAuth** and the emerging **[W3C][w3c]**/**[OpenID][openid]** standards. Every key interaction, from initial onboarding (which mints a Proofing **VC**) to transactional authorization, is rooted in a verifiable credential. This makes trust explicit, auditable, and portable.

**Pillar 2: Zero-Friction Security**

This pillar directly confronts the historical tradeoff between security and user experience. Artagon's position is that this tradeoff is a false choice, a symptom of outdated architecture. The most secure path must also be the path of least resistance.

- **Passkey-primary authentication** is the prime example. It is simultaneously simpler for the user (no passwords to remember) and exponentially more secure (phishing-resistant, unphishable).

- **Device attestation** is another. It provides a powerful, invisible layer of security by binding trust to hardware, without requiring any action from the end-user. By mandating hardened profiles like **[PAR][par]** and **[DPoP][dpop]**, the platform builds in security by default, rather than as an optional, complex add-on.

**Pillar 3: Privacy-by-Design**

In an age of rampant data surveillance and stringent regulations (**[GDPR][gdpr]**, **[CCPA][ccpa]**), privacy cannot be an afterthought. Artagon embeds privacy at the protocol level.

This is most powerfully demonstrated by the verifiable credentials layer. Using zero-knowledge selective disclosure (**[SD-JWT][sd-jwt]**), a user can prove a specific fact (e.g., "is over 18," "is a resident of California") without revealing the sensitive underlying data (their full date of birth or home address).

This capability for "minimum disclosure" and unlinkable presentations (via **[BBS+][bbs]** **VCs**) shifts control back to the user and fundamentally de-risks data handling for enterprises.

### **Business Value Proposition**

The synthesis of these three pillars delivers a unique and compelling value proposition for all stakeholders in the ecosystem.

- **For Enterprises (CISOs, CPOs, CIOs):**
  - **Radical Risk Reduction:** Eliminates the #1 attack vector—credential phishing and account takeover (**ATO**)—by standardizing on passkeys and device attestation.
  - **Verifiable Compliance:** Achieves and proves compliance with high-assurance frameworks (**[NIST 800-63-3][nist-800-63]**, **[eIDAS][eidas]**, **KYC**) using the integrated proofing pipeline and the resulting Proofing **VC**.
  - **Architectural Future-Proofing:** Bridges the gap between legacy **OIDC**/**OAuth** applications and the future of decentralized identity (**DIDs**/**VCs**) with a single platform.
  - **Fine-Grained Control:** Solves complex authorization challenges for modern applications using the hybrid **[Zanzibar][zanzibar]**/**[OPA][opa]**/**[Cedar][cedar]** policy engine.

- **For Developers (Heads of Engineering, Architects):**
  - **A Unified "Trust API":** A single, developer-first **API** that abstracts the immense complexity of identity, attestation, cryptography, and fine-grained authorization.
  - **Accelerated Time-to-Market:** The "Docs-as-Code" playground, a complete conformance harness, and polyglot **SDKs** (Java, Rust, **JS**/**TS**, Go, Swift) remove friction from the development lifecycle.
  - **Policy Flexibility:** The polyglot policy engine (**[XACML][xacml]**, **[Cedar][cedar]**, **[OPA][opa]**) allows development teams to use the right tool for the job, rather than forcing a one-size-fits-all language.

- **For Ecosystems & Partners (Consortia, Networks):**
  - **A Neutral Trust-Broker:** The platform's federated trust registry and multi-issuer **VC** model enable the creation of high-trust, interoperable networks (e.g., verified travel, healthcare credentials, or educational diplomas).

### **Unifying Identity, Security, and Authorization**

The true power of the Artagon vision lies in its synthesis of three domains that legacy vendors treat as separate, loosely-coupled products: **Identity (AuthN)**, **Security (Attestation)**, and **Authorization (AuthZ)**.

Historically, a system might authenticate a user (**AuthN**), separately check their device's posture (Security), and finally consult a policy engine (**AuthZ**). An attacker with valid credentials on an untrusted device might still be blocked by policy, but this is a reactive, brittle defense.

Artagon's approach is a proactive synthesis. These domains are not just connected; they are cryptographically bound.

- A client application's identity is established via **Device Attestation** (D4).
- This attestation is not just a signal; it is bound to the client's per-instance credential during **Dynamic Client Registration** (D1, D4).
- The client's **[DPoP][dpop]** key (D1), used to prove possession of access tokens, is itself bound to the device's hardware, and this binding is verified via attestation.
- The user authenticates with a **Passkey** (D1), which is bound to the device.
- The user presents a **Verifiable Credential** (D2), which is bound to their passkey.
- The claims from this verified stack (user + device + client + **VC**) become the input to the **Policy Engine** (D5).

This creates a chain of "compounding trust." Authentication is no longer just "proof of user." It is the verifiable, cryptographically-bound proof of a trusted user on a trusted device using a trusted application. This unified, high-assurance model is the core technical and strategic differentiator of the Artagon Identity Platform.

[webauthn]: https://www.w3.org/TR/webauthn-2/
[play-integrity]: https://developer.android.com/google/play/integrity
[app-attest]: https://developer.apple.com/documentation/devicecheck/appattest
[mtls]: https://datatracker.ietf.org/doc/html/rfc8705
[sd-jwt]: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt
[bbs]: https://w3c-ccg.github.io/BBS-Signature-Suite-v1.0/
[w3c]: https://www.w3.org/
[openid]: https://openid.net/
[par]: https://datatracker.ietf.org/doc/html/rfc9126
[dpop]: https://datatracker.ietf.org/doc/html/rfc9449
[gdpr]: https://gdpr-info.eu/
[ccpa]: https://oag.ca.gov/privacy/ccpa
[zanzibar]: https://research.google.com/pubs/zanzibar-googles-consistent-global-authorization-system/
[opa]: https://www.openpolicyagent.org/
[cedar]: https://www.cedarpolicy.com/
[xacml]: https://docs.oasis-open.org/xacml/3.0/xacml-3.0-core-spec-os-en.html

---

## **3. Architectural Principles**

The Artagon platform architecture is a direct expression of its product vision. It is guided by five core principles that ensure security, scalability, and flexibility.

- **Principle 1: High-Assurance by Default**

  The platform will always choose the secure-by-default path. Security is not an optional feature or an enterprise-tier add-on; it is the default posture for all tenants and all interactions. This is demonstrated by the choice of Passkey-primary authentication (phishing-resistant) over password-based flows, and the mandated use of hardened **OAuth**/**GNAP** profiles (**[PAR][par]**, **[DPoP][dpop]**, **[mTLS][mtls]**) for all clients. Weaker, insecure flows are not "legacy options"; they are explicitly unsupported.

- **Principle 2: Cryptographic Agility & Isolation**

  The platform is built on a foundation that is agile to new cryptographic standards. This is embodied in the modular Rust sidecars for crypto operations (**[BBS+][bbs]**, **[ZKP][zkp]**) and the native support for multiple **VC** formats (**[SD-JWT][sd-jwt]** and **BBS+**). This agility ensures the platform can adapt to future requirements, such as post-quantum cryptography, without a full re-architecture. Furthermore, the multi-tenant architecture provides cryptographic isolation, not just logical separation. Each tenant has its own dedicated issuance keys, **JWKS**, and encryption context, managed via a **[KMS][kms]**/**[HSM][hsm]**, making cross-tenant breaches an architectural impossibility.

- **Principle 3: Policy-as-Code & Verifiable Audit**

  All authorization and business logic must be expressed as explicit, human-readable, and auditable policy. This is the core of the authorization engine, with its Git-backed Policy Administration Point (**PAP**). By supporting modern policy languages (**[Cedar][cedar]**, **[OPA][opa]**) and the enterprise standard (**XACML** 3.0+), Artagon treats policy as code. This enables versioning, automated testing, and a verifiable, immutable audit trail for all decisions. The **Zanzibar**-style graph store provides the corresponding verifiable "ground truth" for all relationships and permissions.

- **Principle 4: Holder-Centric & Privacy-Preserving**

  The user (the "holder") is the ultimate owner of their identity. The platform's architecture reflects this fundamental shift away from the traditional "profile-in-a-database" **CIAM** model. Artagon acts as an issuer, verifier, and authorization engine, but the user holds their own Verifiable Credentials. Selective disclosure (**ZKP**/**SD-JWT**) is a first-class primitive, ensuring the user reveals only the minimum necessary data for any given transaction, fulfilling the privacy-by-design pillar.

- **Principle 5: Developer-First Abstraction**

  The platform's immense power must be made simple and accessible to developers. The complexity of **[OIDC][oidc]**, **GNAP**, **[DIDs][did]**, **[VCs][vc]**, and **Zanzibar** graph traversal will be abstracted behind a clean, unified **API** and a set of idiomatic **SDKs**. The "Docs-as-Code" site, complete with live playgrounds, and the polyglot policy engine are direct manifestations of this principle: Artagon handles the protocol-level and cryptographic complexity, allowing developers to focus on building their applications.

[zkp]: https://en.wikipedia.org/wiki/Zero-knowledge_proof
[kms]: https://aws.amazon.com/kms/
[hsm]: https://csrc.nist.gov/glossary/term/hardware_security_module
[did]: https://www.w3.org/TR/did-core/

---

## **4. Core Components and Capabilities**

The Artagon platform is composed of five deeply integrated components that together deliver on the mission of unified, verifiable trust.

### **4.1. Unified Identity & Authorization Core**

This component is the foundation for all identity transactions, serving as a best-in-class provider for both human and machine identities.

- **Protocol Unification (OIDC 2.1 & GNAP):** Artagon provides a single, unified server that bridges the present and future of identity protocols.
  - **[OIDC][oidc]:** Provides full support for all standard web and mobile single sign-on (**SSO**), federation, and existing enterprise workloads.
  - **[GNAP][gnap]:** This is the strategic, next-generation core. **GNAP** is architected to handle complex authorization scenarios that **OIDC** struggles with, including **IoT** devices, complex delegation, multi-access tokens, and seamless user-in-the-loop interactions.

- **Hardened Security Profiles (The "Zero-Trust" Token):** The platform enforces a "high-assurance by default" posture by mandating the most secure, modern **IETF** profiles for all clients:
  - **[PAR][par]:** Protects against request forgery and data leakage by moving authorization request parameters from the browser (front-channel) to a secure, direct back-channel request.
  - **[JAR][jar]:** Ensures the integrity and authenticity of the authorization request itself.
  - **[DPoP][dpop]:** Binds access tokens to a client's specific private key, rendering stolen bearer tokens useless to an attacker.
  - **[RAR][rar]:** Allows clients to request fine-grained, structured authorization scopes (e.g., "permission to read file_A and write to invoice_B") rather than broad, opaque strings.
  - **[mTLS][mtls]:** Mandated for all high-assurance client-to-server back-channel communication.

- **Passkey-Primary Authentication:** The platform is architected around **[WebAuthn][webauthn]** as the primary authentication factor. This is not just an **MFA** add-on; it is the default, passwordless, phishing-resistant login method, providing both superior security and a simpler user experience.

- **Cryptographic Multi-Tenancy:** Tenants are not just logical database rows. They are cryptographically isolated entities, each with their own dedicated **JWKS**, issuance keys, and encryption context, all managed and secured via a dedicated **[KMS][kms]**/**[HSM][hsm]**.

### **4.2. Decentralized Trust Layer**

This component activates the "Verifiable Everything" pillar, transforming Artagon from an **IdP** into a comprehensive trust-issuance and verification engine.

- **DID & VC Primitives:** The platform is a full-featured "**DID**/**VC** Swiss Army knife," providing issuance and verification support for:
  - **[DIDs][did]:** Including did:web (domain-based, simple adoption), did:key (ephemeral, simple), and did:ion/peer (scalable, Layer-2 decentralized).
  - **VC Formats:** Bilingual support for the two leading formats:
    - **[SD-JWT][sd-jwt]:** For **JSON**-native, web-friendly selective disclosure, ideal for most web and mobile use cases.
    - **[BBS+][bbs]:** For advanced, zero-knowledge, and fully unlinkable presentations, ideal for high-privacy scenarios.

- **The OID4VC "On-Ramp" ([OID4VC][oid4vc]):** This is the critical bridge that connects the **OIDC**/**OAuth** world to the **VC** world, enabling enterprise adoption.
  - **[OID4VCI][oid4vci]:** An **API** flow allowing a user to authenticate (using **OIDC** or **GNAP**) and be issued a Verifiable Credential. This is the mechanism used to deliver the Proofing **VC**.
  - **[OID4VP][oid4vp]:** An **API** flow that allows a relying party to request a **VC** presentation using a standard **OIDC** authorization flow.

- **Privacy & Revocation:**
  - **Holder Binding:** **VCs** are not just "claims"; they are cryptographically bound to the holder's passkey or device key. A user proves possession of a **VC** by signing a challenge with the same **FIDO2** key they use to authenticate.
  - **Revocation:** The platform implements modern, scalable, and privacy-preserving revocation via **[Status List 2021][status-list]** (a bitmap-based list) and Merkle proofs.

The **OID4VP** flow is the single most important strategic component for enterprise adoption. Enterprises have thousands of existing applications that speak **OIDC**. They cannot and will not rewrite them all to understand "native" **DID** and **VC** protocols. A pure-play **VC** vendor fails because it cannot integrate with this legacy. A pure-play **OIDC** vendor fails because it cannot offer the privacy and portability of **VCs**.

Artagon's **OID4VP** flow solves this dilemma by acting as a translation layer. The flow is as follows:

- A legacy enterprise application (Relying Party) initiates a standard **OIDC** login.
- Artagon, as the **OIDC** Provider, recognizes the request requires high assurance (e.g., **IAL**2).
- Artagon uses **OID4VP** to request the Proofing **VC** from the user's digital wallet.
- The user approves and presents the **VC** (e.g., proving they are **IAL**2 verified and over 21, without sharing their **DOB** or address).
- Artagon cryptographically verifies the **VC**.
- Artagon mints a standard **OIDC** **ID** Token and Access Token containing the verified claims (e.g., ial: "ial2", is_over_21: "true") and returns them to the legacy application.

The result is revolutionary: the legacy application gets the high-assurance, verified data it needs without ever knowing a Verifiable Credential was involved. This "Trojan Horse" strategy allows Artagon to seamlessly introduce next-generation verifiable identity into existing enterprise ecosystems.

### **4.3. Integrated Identity Proofing Pipeline**

This component solves the "cold start" problem of identity: how to root a digital identity in the real world.

- **The "Proofing VC":** The central product of this pipeline. Upon successful onboarding, the user is issued a **[VC][vc]**—the Proofing **VC**. This **VC** is a portable, reusable, and cryptographically signed attestation of their identity assurance level (e.g., **[NIST 800-63-3][nist-800-63]**, **[eIDAS][eidas]**).

- **Orchestration, Not Origination:** Artagon is not a document verification company. The platform provides a "pluggable" proofing orchestration pipeline. This allows enterprises to plug in their preferred best-in-class providers for document verification, liveness checks, biometric matching, and issuer network (e.g., bank) verification.

- **Compliance-as-Code:** The pipeline is architected to be dynamically configurable to meet specific regional and industry frameworks, including **[NIST 800-63-3][nist-800-63]**, **[eIDAS][eidas]**, and regional **KYC**/**AML** regulations.

- **Onboarding UX:** The entire proofing process is exposed to end-users via a seamless **[GNAP][gnap]** or **OIDC** subject-interaction flow, making high-assurance onboarding a simple, integrated part of the initial authentication or registration.

### **4.4. Device & Application Attestation Engine**

This component delivers on the "Machines" part of the mission, establishing verifiable trust in the client itself.

- **Multi-Platform Attestation:** The engine verifies attestation evidence from all major platforms, proving that a request is originating from a legitimate, untampered client:
  - **[Android Play Integrity][play-integrity]**
  - **[Apple App Attest][app-attest]**
  - **[WebAuthn][webauthn]** (for passkeys and hardware tokens)

- **Device Trust Scoring:** Based on the attestation evidence, the engine produces a trust score (e.g., "hardware-backed," "software-only," "unverified"), which is a critical input for the authorization engine.

- **The Trust-Binding Loop:** This is the deep synthesis of the Identity Core (4.1) and the Attestation Engine (4.4).
  - **Attestation-Bound DCR:** A mobile app uses App Attest to prove its authenticity during Dynamic Client Registration.
  - **Per-Instance Credentials:** Artagon rejects the weak "shared secret" model. It issues unique, per-instance credentials to every single device.
  - **Automatic Rotation:** These credentials are not static; they are part of an automatic client-key rotation and lifecycle management policy, driven by attestation health.
  - **Hardware-Bound [DPoP][dpop]:** The **DPoP** key used to sign access token requests is itself bound to the device's secure element (e.g., Secure Enclave, Android Keystore). Attestation is used to prove this binding. This makes stolen tokens useless, and even a stolen **DPoP** key is useless, as it cannot be exfiltrated from the original device's hardware.

### **4.5. Next-Generation Authorization Engine**

This component delivers the "Authority" part of the vision, providing a fine-grained, high-performance engine for answering the question: "What is this identity allowed to do?"

- **The Hybrid Model: ReBAC + ABAC:** Artagon's core authorization differentiator is its fusion of two complementary models:
  - **[Zanzibar][zanzibar]:** A globally distributed, high-performance graph store. This "fast path" is optimized for answering large-scale **[ReBAC][rebac]** questions (e.g., "Does User X have a relation (owner, editor, viewer) to Resource Y?").
  - **Polyglot Policy Engine (ABAC):** A runtime Policy Decision Point (**PDP**) that provides a fine-grained, **[ABAC][abac]** overlay. It answers complex, conditional questions (e.g., "...if Resource Y has tag: 'sensitive' and User X's ip_address is 'internal'").

- **Why Both?** This hybrid model solves the limitations of each. **Zanzibar** is extremely fast for **ReBAC** but clumsy for complex **ABAC**. **OPA**/**Cedar** are excellent for **ABAC** but cannot scale to check billions of user-resource relationships. The "Graph checks as fast path, policy layer as fine-grained overlay" architecture is the optimal solution for modern, complex applications.

- **Polyglot Language Support:** The **PDP** supports the three most important policy languages, allowing teams to choose the right tool:
  - **[Cedar][cedar]:** For simple, schema-driven, and verifiable policies.
  - **[OPA Rego][opa-rego]:** For cloud-native integrations and complex data-driven policies.
  - **[XACML][xacml] 3.0+:** For deep enterprise integration and standards-based interoperability.

- **Full Policy Lifecycle (PAP/PDP/PEP):**
  - **PAP (Policy Administration Point):** A Git-backed policy registry where policy is managed, versioned, and tested as code.
  - **PDP (Policy Decision Point):** The high-performance, modular runtime evaluator.
  - **PEP (Policy Enforcement Point):** Delivered as lightweight **SDKs** and sidecars that integrate with applications, **APIs**, and microservices.

- **Advanced Features:** The engine includes decision caching, zookie-based consistency for the graph store, and a full obligations/advice system (e.g., "Grant, but redact the **PII** field," "Grant, but log this action," or "Deny, and apply rate limit").

### **4.6 Advanced Delegation & Authority Brokering Engine**

This component is the capstone of the Artagon platform, representing a powerful synthesis of our core capabilities. It elevates Artagon from an "Identity Provider" (**IdP**) into a true "Authority Broker."

This engine is not a single service but an architectural pattern that delivers _Verifiable Authority_: the ability for any entity (human or machine) to securely, auditably, and provably delegate specific, fine-grained, and time-bound capabilities to another entity, even across disparate trust domains.

This functionality is achieved by the unique, deliberate fusion of our Unified Core (**[GNAP][gnap]**), Decentralized Trust Layer (**[VCs][vc]**), and Next-Generation Authorization Engine (**[Zanzibar][zanzibar]** + **[Cedar][cedar]**/**[OPA][opa]**). This combination creates a solution that legacy **IAM** vendors, modern **CIAM** providers, and pure-play decentralized tooling vendors cannot replicate, as established in Section 8 of this document.

The engine is built on four distinct pillars that function in concert:

#### **4.6.1 Pillar 1: GNAP as the Negotiated Delegation Protocol**

This pillar leverages the **Unified Identity & Authorization Core (Section 4.1)**, specifically its native support for the **[GNAP][gnap]**. Where **[OAuth 2.0][oauth2]** is a rigid, prescriptive protocol, **GNAP** is the _flexible, conversational protocol_ by which delegation is requested, negotiated, and granted. This moves far beyond the static grants of **OAuth** 2.0, which was not designed for the complex, multi-party delegation scenarios of the modern web.

- **Conversational, Multi-Party Negotiation:** Unlike **OAuth** 2.0, which locks the client into a specific "grant type" from the beginning, **GNAP** is designed as a dynamic _conversation_. The client instance (the party requesting delegate access) _asks_ for what it wants and _presents_ what it knows (e.g., its identity, its attestation). The Artagon Authorization Server (**AS**) can then respond based on that request, potentially engaging in a multi-step flow that involves the resource owner for consent when needed.

- **Native "Cross-User" Authentication:** The common business request for a customer service representative (**CSR**) to act "on behalf of" a customer is a classic "cross-user" scenario. These flows are notoriously difficult and non-standard in **[OIDC][oidc]**/**OAuth**. **GNAP**, however, is explicitly designed to handle cases where the user operating the client (the **CSR**) is _not_ the resource owner (the customer) but is requesting authorization from them. Artagon's **GNAP** server will manage this interaction seamlessly, for example, by pausing the **CSR**'s flow and providing a continuation endpoint, while it interacts with the customer on their trusted device (e.g., mobile app) to gain explicit consent.

- **Fine-Gained, Structured Access Requests:** Artagon's core supports **[RAR][rar]**, a concept directly back-ported from **GNAP**'s design. This allows a delegate to request highly specific, structured access. Instead of opaque **OAuth** scopes like billing.read, the request can be structured **JSON**, such as: {"type": "billing_api", "actions": ["read_invoice", "issue_refund"], "locations": ["/api/v2/customer/123/"]}. This "intent registration" is critical for enforcing the principle of least privilege in all delegation grants.

- **Cryptographic Binding by Default:** As detailed in Section 4.1, Artagon mandates hardened profiles like **[DPoP][dpop]**. **GNAP** reinforces this security-by-design posture by binding all communication to the client's key from the very first request. This means the delegation grant, once issued, is cryptographically bound to the delegate's specific, attested client instance, rendering the token or grant artifacts useless if stolen.

#### **4.6.2 Pillar 2: Zanzibar as the Relationship Graph for Delegation**

This pillar leverages the **Next-Generation Authorization Engine (Section 4.5)**, specifically its **[Zanzibar][zanzibar]**-style graph index (**ReBAC**). While **GNAP** handles the _request_ and _negotiation_ of a delegation, the **Zanzibar** graph stores the _fact_ and _nature_ of that delegation as a durable, queryable, and high-performance relationship.

- **Modeling Delegation as a Relationship (ReBAC):** Delegation is, at its core, a relationship problem. "User A is a delegate for User B," "User C is the manager of Document D," "Agent X is an agent of Organization Y." These are not "roles" in the static, traditional **RBAC** sense. Artagon's **[ReBAC][rebac]** engine models these permissions as relationship tuples in a graph. For example: (user:csr_alice, is_temp_delegate_for, user:customer_bob) or (ai_agent:did_007, has_authority_from, user:exec_jane).

- **Scalability and Chained Delegation:** The **Zanzibar** model is designed for global scale, capable of handling trillions of relationships (Access Control Lists) and millions of authorization checks per second. This architecture allows Artagon to manage complex, multi-level or "chained" delegation (e.g., a **CEO** delegates authority to a **VP**, who further delegates a subset of that authority to a Director). The graph structure, which can be pre-indexed, allows these hierarchical relationships to be resolved with millisecond latency.

- **Decoupling Policy from Application Code:** By storing all delegation relationships in a centralized, dedicated graph store, Artagon removes this complex, stateful logic from the applications themselves. An application's resource server no longer needs to know _why_ a user has access. It simply asks the Artagon Policy Enforcement Point (**PEP**), "Does Alice have 'edit' permission on this document?" The **PEP** handles the complex graph traversal to determine if Alice is an owner, an editor, or a valid delegate of an owner.

#### **4.6.3 Pillar 3: Cedar/OPA as the Fine-Grained Policy Overlay**

This pillar represents the "hybrid model" of the **Authorization Engine (Section 4.5)**. It fuses the **ReBAC** graph with an **[ABAC][abac]** policy layer, using languages like **[Cedar][cedar]** or **[OPA Rego][opa-rego]**. This fusion is the key to solving complex, real-world delegation scenarios that are conditional and contextual.

- **The Hybrid Model: ReBAC + ABAC:** This architecture solves the limitations of each model. **Zanzibar** (**ReBAC**) is extremely fast and scalable for answering "what is the _relationship_?" but is clumsy for complex, attribute-based rules. Conversely, **OPA**/**Cedar** (**ABAC**) are excellent for expressive, attribute-based rules but cannot scale to check trillions of user-resource relationships without being provided all the data at evaluation time. Artagon's hybrid engine uses both in a two-stage check:
  1. **ReBAC Check (Zanzibar):** "Does a delegation _relationship_ exist between the CSR and the Customer?" (This is a fast, scalable graph query).
  2. **ABAC Check (Cedar):** "IF YES, _do the attributes_ of the request, user, and resource satisfy the conditional policy?" (e.g., ...where { csr.on_shift == true and customer.account_status != "locked" }).

- **Policy-as-Code for Delegation:** This hybrid model allows all delegation _rules_ to be managed as explicit, auditable, human-readable policy. This is a core tenant of the Artagon vision (Principle 3). A policy for our **CSR** use case, written in **Cedar**, would look like this:

  ```cedar
  permit (principal, action, resource)
  when {
    // ReBAC check (implicit call to Zanzibar graph)
    principal.is_delegate_of(resource.owner)

    // ABAC checks (Cedar policy)
    && principal.job_title == "CSR_Level_2"
    && context.time.hour >= 9 && context.time.hour < 17
    && action in [actions.read, actions.update_contact]
  };
  ```

- **Enforcing Temporal and Conditional Grants:** This **ABAC** overlay is the mechanism that enforces the _conditions_ of the delegation grant negotiated via **GNAP**, such as time limits (e.g., "for 15 minutes"), action limits (e.g., "read-only"), or environmental constraints (e.g., "from internal **IP** address only").

#### **4.6.4 Pillar 4: Verifiable Credentials as Portable Delegation Grants**

This pillar activates the **"Verifiable Everything"** vision (Pillar 1) by leveraging the **Decentralized Trust Layer (Section 4.2)**. It transforms the delegation grant from an abstract concept or an internal database entry into a tangible, portable, and cryptographically provable _artifact_: a Delegation**VC**.

- **The "DelegationVC":** Artagon's platform is architected to _issue_ a **[VC][vc]** that _represents_ the delegation grant itself. This Delegation**VC** is a signed, tamper-evident attestation from the Artagon platform (acting on the resource owner's authority). Its claims would include:
  - issuer: The Artagon platform (or the owner's **[DID][did]**)
  - subject: The Delegatee's **DID**
  - credentialSubject: {
    type: "DelegationCredential",
    grant: {
      owner: The Owner's **DID**,
      actions: ["read", "write"],
      resource: "urn:artagon:doc:12345",
      valid_from: "2024-10-27T10:00:00Z",
      valid_until: "2024-10-27T11:00:00Z"
    }
  }

- **Issuance (OID4VCI) and Presentation (OID4VP):** This flow seamlessly integrates with Artagon's existing **[OID4VC][oid4vc]** components (Section 4.2).
  1. **Issuance:** After the **GNAP** negotiation (Pillar 1) is complete and consent is given, the Artagon platform uses **[OID4VCI][oid4vci]** to issue this Delegation**VC** to the delegate's digital wallet (e.g., the **CSR**'s enterprise wallet).
  2. **Presentation:** When the delegate (**CSR**) makes a request to a resource server (**PEP**), they present this Delegation**VC** via **[OID4VP][oid4vp]**. The **PEP** can now _cryptographically verify_ the delegation without having to make a high-latency, real-time call back to a central database for every check.

- **Cross-Domain Portability & Revocation:** This is the key architectural differentiator that enables true cross-domain delegation. The Delegation**VC** is _portable_. A delegate can present their authority to a resource server in a _completely different trust domain_ (e.g., another company, another cloud platform). That verifier only needs to trust Artagon's public **DID** (as the issuer) and check the revocation status. This revocation is handled efficiently via the platform's existing **[Status List 2021][status-list]** mechanism (Section 4.2), providing a privacy-preserving way to invalidate a delegation grant before its expiry. This architecture even supports "chained" delegation, where a **VC** can be used to prove the authority to issue another, more limited, delegation **VC**.

#### **Table: The Artagon Delegation Synergy**

This integrated, four-pillar approach creates a verifiable authority model that is fundamentally superior to legacy approaches.

| Feature                  | Legacy IAM (e.g., OIDC act claim + RBAC)                                                                                  | Artagon Verifiable Authority (GNAP + Zanzibar + Cedar + VCs)                                                                                                                                                                                                                                                                                   |
| :----------------------- | :------------------------------------------------------------------------------------------------------------------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Delegation Protocol**  | Clumsy. Often non-standard token exchange (act_as) or over-broad scope grants. Rigid, non-conversational.                  | **[GNAP][gnap]:** A flexible, multi-party _negotiation_. Natively supports cross-user flows and fine-grained **[RAR][rar]**.                                                                                                                                                                                                                    |
| **Grant Model**          | Implicit. Stored in a proprietary, internal database (e.g., an "admin" flag) or a temporary session. Brittle.              | **[Zanzibar][zanzibar] Graph:** An explicit, durable, and scalable (delegate, relation, owner) **[ReBAC][rebac]** relationship.                                                                                                                                                                                                                 |
| **Policy Enforcement**   | Basic, coarse-grained RBAC (e.g., "CSRs can act as Customers") or simple ABAC rules. Hard-coded logic.                     | **Hybrid (ReBAC + ABAC):** A two-stage check. **1) Zanzibar** verifies the _relationship_ (ReBAC), **2) [Cedar][cedar]/[OPA][opa]** verifies the _fine-grained policy_ (ABAC).                                                                                                                                                                 |
| **Portability / Domain** | **Domain-Locked.** The delegation "fact" lives inside one monolithic IAM. Cannot be presented to external systems.         | **Globally Portable:** The grant is issued as a **[VC][vc]**. The delegate can _present_ this provable artifact to _any_ verifier, in _any_ trust domain.                                                                                                                                                                                       |
| **Auditability**         | Opaque. Logs show "Admin X did Y," not "Admin X, acting on behalf of Customer Z with explicit, time-bound consent, did Y." | **Verifiable & Explicit.** The entire chain is provable. The **GNAP** consent flow, the Delegation**VC**, and the hybrid policy decision create a cryptographically auditable, "Verifiable Everything" trail.                                                                                                                                   |

[jar]: https://datatracker.ietf.org/doc/html/rfc9101
[rar]: https://datatracker.ietf.org/doc/html/rfc9396
[oid4vc]: https://openid.net/sg/openid4vc/
[oid4vci]: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html
[oid4vp]: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html
[status-list]: https://www.w3.org/TR/vc-status-list-2021/
[rebac]: https://www.osohq.com/academy/relationship-based-access-control-rebac
[abac]: https://csrc.nist.gov/projects/access-control/abac
[opa-rego]: https://www.openpolicyagent.org/docs/latest/policy-language/
[oauth2]: https://datatracker.ietf.org/doc/html/rfc6749

---

## **5. Technology Stack & Implementation Notes**

The Artagon platform is architected for extreme performance, security, and scalability, using a "best-of-both-worlds" technology stack.

- **Core Services Rationale ([Java 25/26][java]):**
  - The core services (issuer-core, gnap-server, policy-engine, session-authn) will be built on the Java 25/26 **LTS** stack.
  - **Why Java?** The Java ecosystem is unmatched in its maturity, enterprise adoption, and robust, battle-tested cryptography libraries.
  - **Why Java 25/26?** The strategic reason is **Virtual Threads (Project Loom)**. This is a game-changer for I/O-bound identity protocols (like **OIDC**, **GNAP**, and **API** calls). It allows the platform to use simple, maintainable, "thread-per-request" code that scales to millions of concurrent, non-blocking connections, achieving the performance of reactive frameworks with the simplicity of traditional code.
  - The runtime will be built on a modern, non-blocking framework like Netty, Helidon, or Vert.x to fully leverage Virtual Threads.

- **Performance Hot-Paths ([Rust][rust] Sidecars):**
  - **Why Rust?** For performance-critical and security-sensitive operations, Rust provides C-level speed with guaranteed memory safety.
  - **Use Cases:** These operations will be isolated into dedicated Rust sidecars:
    - crypto-ops: All complex, CPU-bound cryptography (**BBS+** signatures, **ZKP** verification).
    - graph-traversal: The hot-path for **Zanzibar** graph lookups.
  - **Integration:** The Java core will communicate with these Rust libraries using Java's new **FFM** (Foreign Function & Memory **API**). This provides a high-performance, **JNI**-free bridge for "best-of-both-worlds" architecture: Java for scalable I/O, Rust for safe, high-speed computation.

- **Data Plane Strategy:**
  - **Primary Store ([PostgreSQL][postgres]):** The "ground truth" for tenant configuration, policies, user metadata, and audit logs.
  - **Hot Store ([Redis][redis]/KeyDB):** For ephemeral, high-throughput data: sessions, **OIDC** states, nonces, and caches.
  - **Graph Store (Off-heap):** The **Zanzibar** graph cannot live in Postgres. It will be a purpose-built, in-memory, off-heap graph store to avoid Java Garbage-Collection (**GC**) pauses, replicated globally for low-latency checks.
  - **Secrets ([KMS][kms]/[HSM][hsm]):** All cryptographic material (tenant keys, issuer keys) will be managed exclusively by a dedicated Key Management Service or Hardware Security Module.

- **Service Modularity & Observability:**
  - The platform is built as a set of modular, independent services (issuer-core, gnap-server, policy-engine, graph-store, sdk-*, etc.).
  - Full-stack observability is a Day 1 requirement, including structured logs, Prometheus metrics, OpenTelemetry tracing, replay caches for debugging, and risk-based analytics.

[java]: https://openjdk.java.net/projects/jdk/25/
[rust]: https://www.rust-lang.org/
[postgres]: https://www.postgresql.org/
[redis]: https://redis.io/

---

## **6. Security and Privacy Model**

The platform's security and privacy models are not features, but are the foundational design principles.

### **Security Model: Phishing-Resistant, Zero-Trust**

Artagon's security model is designed to be "secure-by-default" and "phishing-resistant" at every layer.

- **Authentication:** Passkey-primary authentication provides built-in, unphishable security for users.

- **Token Security:** **[DPoP][dpop]** binds tokens to the client, making bearer token theft (the most common **API** attack) a useless endeavor.

- **Client Security:** Device Attestation and **[mTLS][mtls]** ensure that only legitimate, healthy, and registered clients (human or machine) can even initiate a request.

- **Transport Security:** **[PAR][par]** protects the authorization request itself from leakage or tampering by moving it to a secure back-channel.

- **Tenant Isolation:** Cryptographic multi-tenancy ensures that even in a worst-case scenario, a breach in one tenant cannot affect any other.

### **Privacy Model: Holder-Controlled, Minimum Disclosure**

The privacy model is built on the principle of returning data control to the user.

- **Data Minimization:** The core primitive is Zero-Knowledge Selective Disclosure, enabled by **[SD-JWT][sd-jwt]** and **[BBS+][bbs]**. A user can prove a fact (e.g., "is over 18," "is a valid employee") without revealing the raw, sensitive data (their date of birth, their employee **ID**).

- **Unlinkability:** **BBS+** **VCs** and ephemeral did:peer identifiers enable unlinkable presentations, preventing a verifier from correlating a user's activity across different services.

- **Data Portability:** The Proofing **VC** is a portable, interoperable **[VC][vc]**. The user holds it in their wallet of choice and can reuse it, decoupling them from the Artagon platform. This is a fundamental "data liberation" feature.

- **Revocation Privacy:** The use of **[Status List 2021][status-list]** provides a privacy-preserving revocation mechanism. It allows a verifier to check if a **VC** has been revoked without "calling home" to the issuer and revealing which credential they are checking.

---

## **7. Developer Experience and Ecosystem Plan**

The primary adoption vector for Artagon is a world-class, developer-first experience. The platform's "DX-as-Product" philosophy is designed to emulate the success of developer-centric companies like Stripe and Auth0.

- **Core Tooling:**
  - **SDKs:** A suite of idiomatic, full-featured **SDKs** for all major ecosystems: **[Java][java]**, **[Rust][rust]**, **[TypeScript][typescript]**, **[Go][golang]**, and **[Swift][swift]**. These **SDKs** will handle **OIDC**/**GNAP** flows, **VC**/**VP** management, and **PEP** integration.
  - **CLI:** A powerful command-line interface for all platform operations: dynamic client registration, policy management (testing and deploying), issuing test **VCs**, and running conformance tests.
  - **APIs:** A dual **[GraphQL][graphql]** + **[REST][rest]** **API** set. **GraphQL** provides flexibility for client-side applications to query for specific data, while **REST** provides a standard, machine-to-machine interface.

- **The Artagon Playground (Documentation):**
  - Documentation will be built as a "Docs-as-Code" site using modern frameworks (e.g., **[Astro][astro]**, **[Docusaurus][docusaurus]**).
  - The single most important feature will be live **OAuth** / **GNAP** / **VC** playgrounds. This allows developers to run real **OIDC**/**OID4VC** flows, issue **VCs**, and test **OPA**/**Cedar** policies directly in the browser, dramatically reducing the "time-to-first-call."

- **Conformance and Trust:**
  - A public-facing Sandbox environment will be available for all developers.
  - A downloadable conformance test harness will be provided, allowing developers and enterprise customers to prove their integration is compliant with **OIDC**, **OID4VC**, and other standards. This builds trust and simplifies procurement.

- **Ecosystem Engagement:**
  - Artagon will be an active participant and contributor to the standards bodies that define this technology: **[IETF][ietf]** (**GNAP**, **DPoP**, **PAR**), **[OpenID][openid]** (**OIDC**, **OID4VC**), and **[W3C][w3c]** (**DIDs**, **VCs**). The platform will serve as a reference implementation for these next-generation protocols.

[typescript]: https://www.typescriptlang.org/
[golang]: https://go.dev/
[swift]: https://developer.apple.com/swift/
[graphql]: https://graphql.org/
[rest]: https://restfulapi.net/
[astro]: https://astro.build/
[docusaurus]: https://docusaurus.io/
[ietf]: https://www.ietf.org/

---

## **8. Competitive Differentiation**

Artagon's defensible "moat" is that it is the only platform architected from the ground up to unify three distinct, and typically siloed, identity markets.

- **The Competitors:**
  - **Legacy IAM/IDaaS (e.g., Okta, Ping Identity):** These vendors are strong in enterprise federation (**[OIDC][oidc]**/**[SAML][saml]**) but are architecturally built on an aging, password-centric, database-profile model. They have no credible path to Verifiable Credentials, weak-to-non-existent **M2M** device attestation, and basic, role-based (**RBAC**/**ABAC**) authorization models.
  - **Modern CIAM (e.g., Auth0, Cognito):** These vendors are developer-first and strong in web/mobile authentication. However, they are "black boxes" with limited authorization (simple rules/hooks), no **VC** support, and no high-assurance device identity.
  - **Decentralized-Only (e.g., Trinsic, Spruce, Affinidi):** These companies are experts in **[DIDs][did]** and **[VCs][vc]**. But they provide tooling (libraries, **SDKs**), not a platform. They do not provide a scalable **OIDC** provider, a **[Zanzibar][zanzibar]**-style authorization engine, or a **CIAM** user lifecycle. They are "bring-your-own-everything-else," which is a non-starter for enterprises.

- **Artagon's Unique Value:** Artagon bridges all three. It provides the developer-first experience and modern **CIAM** flows of Auth0, the enterprise-grade **OIDC**/federation of Okta, and the next-generation privacy and portability of the decentralized world.

This synthesis is best illustrated in a direct comparison:

### **Table 1: Competitive Landscape Summary**

| Capability               | Artagon Identity Platform                                                                         | Legacy IAM (e.g., Okta) | Modern CIAM (e.g., Auth0) | Decentralized Tooling (e.g., Trinsic) |
| :----------------------- | :------------------------------------------------------------------------------------------------ | :---------------------- | :------------------------ | :------------------------------------ |
| Phishing-Resistant AuthN | ✅ (Passkey-Primary)                                                                               | ⚠️ (MFA add-on)         | ⚠️ (MFA add-on)           | ❌ (Not a provider)                   |
| Core Protocol (Web/API)  | ✅ (OIDC 2.1 + [GNAP][gnap])                                                                       | ✅ (OIDC/SAML)          | ✅ (OIDC)                 | ❌ (Not a provider)                   |
| Verifiable Credentials   | ✅ ([OID4VC][oid4vc], [SD-JWT][sd-jwt], [BBS+][bbs])                                              | ❌                      | ❌                        | ✅ (Core product)                     |
| Identity Proofing        | ✅ (Integrated Proofing VC)                                                                        | ⚠️ (Partner add-on)     | ⚠️ (Partner add-on)       | ⚠️ (Partner add-on)                   |
| Device/Machine Identity  | ✅ (Hardware Attestation)                                                                          | ❌                      | ❌                        | ❌                                    |
| Authorization Model      | ✅ ([Zanzibar][zanzibar] Graph + [OPA][opa]/[Cedar][cedar])                                       | ⚠️ (Basic RBAC/ABAC)    | ⚠️ (Simple Rules/Hooks)   | ❌                                    |
| Developer Experience     | ✅ (Playground, SDKs, CLI)                                                                         | ❌ (Enterprise-focused) | ✅ (Strong DX)            | ⚠️ (Library-focused)                  |

Artagon's competitive strategy is not to attempt a "rip-and-replace" of legacy vendors like Okta on day one. The strategy is to outflank them.

Legacy vendors are architecturally "stuck" in a centralized, mutable user profile model. Artagon's architecture—verifiable, immutable, graph-based—is fundamentally different. The go-to-market strategy is a "beachhead" approach:

- Artagon is initially sold to new, greenfield projects inside an enterprise. These are the projects legacy vendors cannot service: cloud-native, high-security, privacy-critical, and requiring complex authorization (e.g., a new consumer-facing app, an **IoT** platform, or a regulated data-sharing initiative).

- As these high-visibility projects succeed, Artagon becomes the "system of record for verifiable trust" within the organization.

- From this beachhead, Artagon uses its **OIDC**/**OID4VP** bridge to federate with the legacy Okta or **[Azure AD][azure-ad]** instance.

- Over time, Artagon consumes the legacy provider's functions, relegating it to the role of a simple on-premise directory. Artagon wins not by competing on "better **OIDC**," but by changing the definition of identity from "authentication" to "cryptographic verification."

[saml]: https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
[azure-ad]: https://azure.microsoft.com/en-us/products/entra-id

---

## **9. Product Use Cases: Advanced Delegation & Authority**

The following narrative use cases illustrate the power of Artagon's Advanced Delegation & Authority Brokering Engine in solving real-world, high-value problems. These scenarios demonstrate the platform's ability to manage delegation within a single domain and across complex, multi-domain ecosystems.

### **9.1 Use Case 1: Human-to-Human (Same Domain) — The Customer Service Mandate**

This scenario directly addresses the common requirement for a trusted employee to act on behalf of a customer, as requested by the user.

- **Scenario:** A customer, Bob, calls his bank's support center. He needs help to resolve a locked-out-account. The Customer Service Representative (**CSR**), Alice, needs to perform actions on Bob's account on his behalf.

- **Artagon Flow:**
  1. **Request ([GNAP][gnap]):** Alice (Human), using her attested **CSR** dashboard (Machine Client), searches for Bob's account. She clicks "Act on Behalf of Customer." This initiates a **GNAP** grant request to the Artagon platform, specifying a "cross-user" flow and requesting fine-grained access (e.g., actions: ["read_account_status", "trigger_password_reset"] for resource: "urn:bank:customer:bob123").

  2. **Owner Interaction (GNAP):** Artagon's **GNAP** server receives the request and sees it requires the resource owner's consent. It sends a secure push notification to Bob's trusted, passkey-bound banking app.

  3. **Grant ([VC][vc]):** Bob authenticates to his app using his passkey (as per Section 4.1). The app displays the **GNAP** grant request: "Allow Alice K. (CSR) to: [x] View Account Status, [x] Trigger Password Reset. Grant for: 15 minutes." Bob approves.

  4. **Issuance ([OID4VCI][oid4vci]):** Upon receiving Bob's authenticated approval, the Artagon platform (as the issuer) immediately:
     a. Writes a relationship to the **Zanzibar** graph: (user:alice, is_temp_delegate_for, user:bob).
     b. Issues a short-lived Delegation**VC** to Alice's session, cryptographically bound to her client's **[DPoP][dpop]** key. This **VC** contains the explicit, approved permissions and the 15-minute expiry.

  5. **Authorization ([ReBAC][rebac] + [ABAC][abac]):** Alice now performs the actions. Her dashboard makes **API** calls to the internal banking services, which are protected by the Artagon **PEP**. For every **API** call:
     a. Alice's client presents the Delegation**VC** (via **[OID4VP][oid4vp]**) and signs the request with her **DPoP** key.
     b. The Artagon **PEP** performs the Hybrid Check:
        i. **ReBAC Check:** It queries the **Zanzibar** graph: "Does user:alice have the relation is_temp_delegate_for on user:bob?" Result: Yes.
        ii. **ABAC Check:** It evaluates the **Cedar** policy: "Is the action (trigger_password_reset) in the presented Delegation**VC**'s scope? Is the **VC**'s timestamp still valid? Is Alice's **IP** in the corporate range?" Result: Yes.
     c. The **API** request is Granted.

- **Value:** This flow eliminates insecure "shared screen" or "admin override" anti-patterns. The access is governed by the principle of least privilege, explicitly consented to by the customer, time-bound, and cryptographically auditable from end to end.

### **9.2 Use Case 2: Human-to-Human (Cross-Domain) — The Specialist Consultation**

This scenario demonstrates how Artagon's architecture enables secure, verifiable delegation across different identity trust domains.

- **Scenario:** A Primary Care Physician (**PCP**), Dr. Evans, at "General Hospital" (Domain A) needs to grant a specialist, Dr. Smith, at a separate "Heart Clinic" (Domain B) temporary, read-only access to a specific patient's file. The two organizations do not share an identity system.

- **Artagon Flow:**
  1. **Identity:** Both organizations use Artagon as their identity platform. Dr. Smith (Domain B) has a Doctor**VC** (a verifiable credential) issued by "Heart Clinic," and her identity is did:web:heart-clinic.com:dr-smith.

  2. **Grant ([Zanzibar][zanzibar]):** Dr. Evans (Domain A) opens the patient's chart in the "General Hospital" portal (which uses Artagon for authorization). She clicks "Share" -> "Add Delegate" and enters Dr. Smith's external identity (did:web:heart-clinic.com:dr-smith). This action _writes a relationship_ to the General Hospital's **Zanzibar graph**: (user:did:web:heart-clinic.com:dr-smith, is_viewer_for, resource:patient_file_456).

  3. **Federation ([OID4VP][oid4vp]):** Dr. Smith (Domain B) logs into her _own_ "Heart Clinic" portal. She clicks a link to "View Referred Patient File." Her portal (a client in Domain B) contacts the "General Hospital" resource server (Domain A).

  4. **Presentation ([VC][vc]):** The "General Hospital" server (protected by Artagon **PEP**) does not recognize Dr. Smith's session. It challenges her for credentials via **OID4VP**, requesting a Doctor**VC**.

  5. **Authorization ([ReBAC][rebac] + [ABAC][abac]):** Dr. Smith's wallet presents her Doctor**VC**. The Artagon **PEP** at "General Hospital" (Domain A) now performs its Hybrid Check:
     a. **ABAC Check (Policy):** It first evaluates its "Federation Policy" against the attributes of the presented **VC**: "Is the issuer (did:web:heart-clinic.com) in our trusted_issuer_list? Is the credentialSubject.type equal to Doctor**VC**?" Result: Yes.
     b. **ReBAC Check (Graph):** Now that the external identity is trusted, it checks the relationship: "Does the subject of this **VC** (did:web:heart-clinic.com:dr-smith) have the is_viewer_for relation on resource:patient_file_456?" Result: Yes.
     c. The request is Granted.

- **Value:** Secure, zero-trust, cross-domain data sharing is achieved without complex **[SAML][saml]** federations or provisioning guest accounts. Trust is established by _verifying_ the external doctor's credentials and _checking_ the internal, explicit relationship graph.

### **9.3 Use Case 3: Human-to-Machine (Ephemeral) — The "Valet Key" for Services**

This scenario demonstrates how **GNAP** and **VCs** can replace insecure, scope-based **OIDC** flows for third-party applications.

- **Scenario:** A user wants to grant a new "Financial Analyzer" app (a machine client) one-time, read-only access to their bank transactions (a resource server) for the last 90 days. The user does not want to give this app their login credentials or a broad, permanent transactions.read scope.

- **Artagon Flow:**
  1. **Negotiation ([GNAP][gnap]):** The Analyzer app (Client) initiates a **GNAP** flow to the Artagon authorization server, requesting type: "transactions", actions: ["read"], constraints: { "date_range": "90d" }.

  2. **Grant ([VC][vc]):** The user is prompted by Artagon (via a redirect or push) to approve this _specific, fine-grained_ request. The user approves.

  3. **Issuance ([OID4VCI][oid4vci]):** Artagon _does not_ issue a broad, bearer-style access token. Instead, it _issues a Delegation**VC**_ directly to the application, bound to its attested client key (as per Section 4.4). This **VC** _is_ the "valet key"—it _is_ the capability.

  4. **Access:** The Analyzer app calls the bank's Transaction **API** (the **PEP**). It presents its Delegation**VC** and signs the request with its **[DPoP][dpop]** key. The **PEP** cryptographically verifies the **VC**, its **DPoP** binding, and its claims (action, resource, constraints). No "user session" is ever established.

- **Value:** This is true, least-privilege, "passwordless" access for third-party services. The app receives a _verifiable capability_, not a powerful, broad-scoped bearer token that could be stolen and misused. The user's grant is explicit, auditable, and requires no credential sharing.

### **9.4 Use Case 4: Human-to-Machine (Autonomous) — The AI Agent Mandate**

This scenario fulfills the V5 Roadmap and long-term vision, demonstrating how Artagon provides the "**IAM** for **AI**."

- **Scenario:** A **CFO**, Jane, needs to authorize an autonomous **AI** Procurement Agent (Machine) to negotiate and sign contracts with suppliers, but only for contracts valued under $50,000.

- **Artagon Flow:**
  1. **Identity ([DID][did]):** The **AI** Agent is a first-class "machine" identity in the Artagon platform (as per Section 2.0). It has its own **DID** and its cryptographic keys are secured in a hardware module (**[TPM][tpm]**/**[HSM][hsm]**). Its software integrity is proven by the **Device & Application Attestation Engine (Section 4.4)**.

  2. **Issuance ([OID4VCI][oid4vci]):** Jane (Human) authenticates to the Artagon Policy Administration Point (**PAP**, Section 4.5). She authors a long-lived Delegation**VC** for her agent. The credential's claims are:
     - issuer: did:artagon:exec:jane_doe
     - subject: did:artagon:agent:procure_007
     - credentialSubject: {
       type: "AgentAuthorizationCredential",
       capability: "sign_contract",
       policy_reference: "urn:artagon:policy:cedar_p-123"
     }

  3. **Authorization ([ReBAC][rebac] + [ABAC][abac]):** The **AI** Agent (procure_007) autonomously negotiates a contract and calls the "Procurement **API**" to sign it. The Artagon **PEP** intercepts the request. The agent presents its Delegation**VC** and signs the request with its hardware-bound key. The **PEP** executes the full Hybrid Check:
     a. **VC Verification:** The **PEP** cryptographically verifies the Delegation**VC**'s signature (from Jane) and its **[DPoP][dpop]** binding (from the agent).
     b. **ReBAC Check:** The **PEP** queries the **Zanzibar** graph: "Is did:artagon:agent:procure_007 (the **VC** subject) an authorized delegate of did:artagon:exec:jane_doe (the **VC** issuer)?" Result: Yes.
     c. **ABAC Check:** The **PEP** sees the policy_reference in the **VC**. It fetches the **Cedar** policy cedar_p-123 and evaluates it against the request's attributes:
        ```cedar
        permit (principal, action, resource)
        when {
          action == "sign_contract"
          && resource.contract_value_usd < 50000
        };
        ```
     d. The request to sign a $45,000 contract is Granted. A later request for $75,000 would be Denied by the **ABAC** policy, even though the **VC** and **ReBAC** relationship are valid.

- **Value:** This is the essential trust, governance, and audit layer for an autonomous machine-driven economy (as per Section 11). Artagon provides a verifiable, cryptographic "leash" for **AI** agents, fusing human-issued authority (**ReBAC**) with fine-grained, auditable rules (**ABAC**).

[tpm]: https://trustedcomputinggroup.org/resource/tpm-library-specification/

---

## **10. Multi-phase Roadmap**

This roadmap is a pragmatic, five-phase execution plan to build the Artagon platform. It is designed to deliver incremental, compounding value, focusing first on core trust infrastructure, then layering verifiable data, enterprise policy, and finally, ecosystem federation.

### **10.1. Roadmap Narrative**

- **Phase 1: V1 - Core Trust Layer (Horizon: 0–3 months)**
  - **Focus:** Establishing the "minimally viable trust" infrastructure. This is the core **OIDC**/**GNAP** server, built on the Java + Virtual Threads + Rust architecture.
  - **Milestones:** A functional, high-performance **[OIDC][oidc]**/**[GNAP][gnap]** **MVP** server. This includes the non-negotiable hardened profiles: **[DPoP][dpop]**, **[PAR][par]**, and **[JAR][jar]**. We will support basic **JWT** issuance (**JWKS**) and an Attestation **MVP** (verifying a single platform, e.g., Apple App Attest) to prove the binding model.
  - **Business Goal:** Achieve **OIDC** conformance certification and secure a "design partner" for a greenfield mobile/web application.

- **Phase 2: V2 - Verifiable Credentials Layer (Horizon: 3–6 months)**
  - **Focus:** Activating the "Verifiable Everything" pillar. This layer builds directly on the V1 issuer.
  - **Milestones:** Full **[SD-JWT][sd-jwt]** issuance (via **[OID4VCI][oid4vci]**) and **[OID4VP][oid4vp]** verification flows. This must include the strategic **OIDC** "bridge" flow. We will also implement our first-generation revocation method, **[Status List 2021][status-list]**.
  - **Business Goal:** Enable "verifiable identity" use cases (e.g., "verified employee," "verified customer") for our design partner, proving the value of portable identity.

- **Phase 3: V3 - Policy and Graph Engine (Horizon: 6–9 months)**
  - **Focus:** Delivering the next-generation authorization engine. This is the core enterprise "upsell" and a massive technical differentiator.
  - **Milestones:** A v1.0 **[Zanzibar][zanzibar]** graph store (off-heap, replicated) for **ReBAC**, integrated with the polyglot **PDP** (**[XACML][xacml]**/**[Cedar][cedar]**/**[OPA][opa]**). We will ship the first **API** **SDKs** (**PEPs**) and the Git-backed **PAP**.
  - **Business Goal:** Move the product conversation beyond "**AuthN**" to "**AuthZ**," enabling complex, fine-grained access control for high-value applications.

- **Phase 4: V4 - Identity Proofing & VC Network (Horizon: 9–12 months)**
  - **Focus:** Solving the "cold start" identity problem. How do we root trust in the real world?
  - **Milestones:** The pluggable Proofing **API** connected to at least one major document verification vendor. The first Proofing **VC** (e.g., **[NIST 800-63-3][nist-800-63]**) is issued. We also build the v1 **VC** trust registry for managing verifier/issuer trust.
  - **Business Goal:** Become a **[NIST 800-63-3][nist-800-63]** / **[eIDAS][eidas]**-compliant identity provider, opening up regulated markets (finance, healthcare, government).

- **Phase 5: V5 - Federation & AI Agents (Horizon: 12–18 months)**
  - **Focus:** Scaling from a platform to an ecosystem.
  - **Milestones:** A Multi-issuer trust registry for true, decentralized federation. We will add support for **[BBS+][bbs]** (for high-privacy **ZKP**). We will also provision autonomous agent keys—equipping **AI** agents and bots with their own **DIDs** and keys, bound by Artagon policy, fulfilling the "Machines" part of our mission.
  - **Business Goal:** Become the trust backbone for a multi-tenant ecosystem (e.g., a "verified travel" network) and the essential identity layer for the emerging **AI**-driven economy.

### **10.2. Roadmap Table**

| Phase | Horizon      | Focus                          | Milestones                                                                                                    | KPIs                            |
| :---- | :----------- | :----------------------------- | :------------------------------------------------------------------------------------------------------------ | :------------------------------ |
| V1    | 0–3 months   | Core Trust Layer               | [OIDC][oidc]/[GNAP][gnap] MVP, [DPoP][dpop], [PAR][par], JWKS, Attestation MVP                               | OIDC conformance %, Latency p95 |
| V2    | 3–6 months   | Verifiable Credentials Layer   | [SD-JWT][sd-jwt] issuance + [OID4VP][oid4vp] verification + [Status List 2021][status-list]                  | VC throughput ops/sec           |
| V3    | 6–9 months   | Policy and Graph Engine        | [XACML][xacml]/[Cedar][cedar]/[OPA][opa] PDP + [Zanzibar][zanzibar] graph store + API SDKs                   | Decision p95 < 10 ms            |
| V4    | 9–12 months  | Identity Proofing & VC Network | Proofing API + Proofing VC issuance + VC registry integration                                                | Proofing success rate %         |
| V5    | 12–18 months | Federation & AI Agents         | Multi-issuer trust registry + autonomous agent keys + [ZKP][zkp] credentials                                 | Federated issuers count         |

---

## **11. Long-term Outlook (Vision 2030)**

The 18-month roadmap (V1-V5) establishes the core infrastructure. The long-term vision for 2030 is to leverage this infrastructure to become the default trust layer for an increasingly ambient and autonomous digital world.

- **From "Identity" to "Authority":** The platform will evolve from an "Identity Provider" (**IdP**) to an "Authority Broker." In a world populated by **AI** agents and complex data-sharing agreements, the most important question is not "Who are you?" (authentication) but "What authority do you have to perform this action?" (authorization). Artagon's synthesis of a verifiable graph (**[Zanzibar][zanzibar]**) and fine-grained policy (**[OPA][opa]**/**[Cedar][cedar]**) is purpose-built to answer this question.

- **AI Agents as First-Class Citizens:** The "autonomous agent keys" from the V5 milestone are the seed of this future. By 2030, **AI** agents will be primary economic actors, not just tools. These agents will require their own **[DIDs][did]**, their own **[Verifiable Credentials][vc]** (e.g., **VC**(capability="execute_trade_<$1M"), **VC**(issuer="corp_hr", claim="is_authorized_agent")), and will be governed by fine-grained Artagon policies. Artagon will be the "**IAM** for **AI**," providing the critical trust, governance, and audit layer for this new economy.

- **The "Verifiable Web":** Artagon's synthesis of **[GNAP][gnap]**, **[Verifiable Credentials][vc]**, and the **[OID4VP][oid4vp]** bridge will be the engine for a new, "verifiable web." In this web, users will move frictionlessly between services, carrying their Proofing **VC**, Payment **VC**, and Employee **VC** in their wallet. They will grant "just-in-time" selective access to verifiers, all without filling out forms or creating new accounts. Artagon's **OID4VP**/**[OIDC][oidc]** bridge will be the critical, pragmatic infrastructure that connects the "old web" to this new "verifiable web."

Artagon's mission is to build the trust layer for the next two decades of digital interaction. By unifying the identity of humans and machines, by building in privacy and zero-friction security from the protocol level, and by grounding all trust in cryptographic verification, we are not just building a product; we are architecting the future of digital trust.

---
