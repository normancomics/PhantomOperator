---
name: phantom-operator
description: Multi-operator privacy and OPSEC framework for OSINT threat scans, automated data-broker opt-outs, breach checks, metadata audits, and OPSEC scoring.
tags: [privacy, opsec, security, osint, x402]
---

# PhantomOperator: Multi-Operator Privacy & OPSEC Skill

PhantomOperator is an autonomous privacy and OPSEC framework designed to locate personal identifiable information (PII), calculate operational security exposure scores, execute data-broker opt-outs, audit web/file metadata, and check credential breaches.

## Core Capabilities & Sub-Operators

### 1. Threat Scan (threat-scan)
- Objective: Conduct OSINT and public web searches for PII including full names, usernames, phone numbers, and addresses.
- Output: exposure report with threat tiers (critical, high, medium, low).

### 2. Data Broker Removal Request (data-removal)
- Objective: Submit opt-out and suppression requests to known people-search engines and data brokers.

### 3. Full Privacy Sweep (full-privacy-sweep)
- Objective: End-to-end workflow: threat scan, listing extraction, removal requests, audit log.

### 4. OPSEC Exposure Scoring (opsec-score)
- Objective: Multi-vector operational security assessment with a composite score (0-100) and prioritized mitigations.

### 5. Breach & Credential Check (breach-check)
- Objective: Check emails and passwords (SHA-1 k-anonymity, no plaintext disclosed) against known breaches.

### 6. Metadata Privacy Audit (metadata-audit)
- Objective: Audit URLs for metadata leakage, tracking and fingerprinting vectors.

## On-Chain & Payment Integrations

- Base Chain (8453):
  - Identity Registry: 0x8004A169FB4a3325136EB29fA0ceB6D2e539a432
  - Reputation Registry: 0x8004BAa17C55a88189AE136b182e5fdA19dE9b63
  - Accepted Payment: USDC / x402 protocol / Superfluid streaming (USDCx: 0xD04383398dD2426297da660F9CCA3d439AF9ce1b).
- Solana:
  - Independent program registry for skill invocations with SOL micropayments.

## Execution Rules
- Always obtain explicit user authorization before triggering active opt-out requests or scanning third-party personal identities.
- Format all scan results cleanly, grouping findings by urgency and actionable next steps.
