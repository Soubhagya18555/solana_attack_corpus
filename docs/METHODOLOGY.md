# Solana Forensic Methodology

Investigation playbook for suspected on-chain attacks, wallet drains, and protocol exploits. Complements corpus entries in `attacks/` with procedural steps from alert triage through root cause attribution.

**Audience:** security engineers, incident responders, blockchain analysts  
**Scope:** Solana mainnet and devnet; applicable to private cluster forks for replay

## Phase 0: Preparation

### Tooling baseline

| Tool | Use |
|------|-----|
| `solana-cli` | Account fetch, tx decode, program dump |
| RPC provider (Helius, Triton, QuickNode) | Enhanced transaction history, webhooks |
| Block explorer (Solscan, SolanaFM, Orb) | Human-readable instruction traces |
| `anchor` / `shank` | IDL generation for discriminator mapping |
| Python + `solders` / `solana-py` | Batch analysis scripts |
| Graph DB or notebook | Wallet clustering, fund flow |

### Evidence preservation

1. Record UTC timestamps, slot numbers, and cluster (mainnet-beta vs devnet).
2. Export full transaction JSON via `getTransaction` with `maxSupportedTransactionVersion: 0`.
3. Snapshot relevant account state **before** and **after** slot range (`getAccountInfo` at `minContextSlot` when available).
4. Hash and archive RPC responses; chain state is mutable only forward, but RPC APIs can prune history.

## Phase 1: Triage

### 1.1 Classify the incident type

| Symptom | Likely corpus mapping |
|---------|----------------------|
| User reports NFT or token gone after one signature | nft_phishing_signature, unlimited_approve |
| Protocol TVL drop without announced upgrade | cpi_reentrancy, authority_drain, oracle_manipulation |
| Unexpected program behavior post deployment | program_upgrade_hijack |
| Governance proposal passed with anomalous turnout | flash_loan_governance |
| Mass wallet notifications for unknown token | fake_airdrop |

### 1.2 Scope victims and assets

- Enumerate affected mints, program IDs, and estimated loss denomination (SOL, USDC, NFT collections).
- Identify first and last malicious transaction signatures.
- Determine if attack is **targeted** (single victim) or **broadcast** (drainer campaign).

### 1.3 Containment (operational)

- For protocols: pause program if emergency brake exists; rotate upgrade authority to cold multisig.
- For users: revoke token delegates; move remaining assets to fresh wallet; burn compromised session keys.
- Publish canonical program IDs and official domains to reduce continued phishing success.

## Phase 2: Transaction reconstruction

### 2.1 Decode instruction tree

For each suspect signature:

1. Parse top-level `message.accountKeys` and `header` (numRequiredSignatures, numReadonlySignedAccounts).
2. Walk `meta.innerInstructions` to build CPI tree with program id per frame.
3. Map instruction data to discriminators using IDL or known SPL opcodes.
4. Correlate `meta.logMessages` for `invoke` depth and program errors.

### 2.2 Account state diff analysis

For each writable account in the transaction:

```
post_balance - pre_balance (lamports)
post_token_balance - pre_token_balance (per mint)
owner / data length changes (red flag if owner changed)
```

Flag:

- `SetAuthority` on mint or token account
- `Approve` with amount `18446744073709551615`
- Metadata `updateAuthority` rotation
- Program `Upgrade` on allowlisted protocol ID

### 2.3 Timeline alignment

Plot transactions on slot axis. Overlay:

- DEX swaps affecting oracle-relevant pools
- Governance votes
- Program upgrades
- Attacker fund consolidation paths

## Phase 3: Attribution and clustering

### 3.1 Wallet graph

- Build directed graph: signer → fee payer → destination ATAs → CEX deposit addresses.
- Cluster by common funding source, shared program invocation patterns, and idle period synchronization.
- Label clusters: `attacker_deployer`, `sweeper`, `victim`, `infrastructure`.

### 3.2 Program provenance

- `solana program show <PROGRAM_ID>` for upgrade authority and last deploy slot.
- Compare on-chain ELF hash to verified builds (Ellipsis Labs verify, Squads verified deployments).
- If source available, diff against prior audited commit.

### 3.3 Off-chain correlation

- WHOIS and certificate transparency for phishing domains.
- Archive.org snapshots of malicious claim pages.
- Cross-reference threat intel feeds for drainer kit signatures.

## Phase 4: Root cause analysis

### 4.1 Map to vulnerability class

Use [TAXONOMY.md](TAXONOMY.md) to assign tactic and technique. Document:

| Question | Rationale |
|----------|-----------|
| Which account validation failed? | Signer missing, wrong owner, PDA bump |
| Was state read before or after CPI? | Reentrancy class |
| What price source was trusted? | Oracle manipulation |
| Was upgrade authority involved? | Supply chain |

### 4.2 Reproduce in lab

Follow `reproduction_notes` in the matching corpus entry on local validator:

```bash
solana-test-validator --reset
# deploy programs, execute failing path, capture logs
```

**Never replay live exploitation on mainnet.** Lab reproduction confirms hypothesis for post mortem accuracy.

### 4.3 Blast radius

- Enumerate all accounts sharing the same misconfiguration (e.g. all mints using same authority PDA seed bug).
- Estimate maximum extractable value remaining at risk.

## Phase 5: Reporting

### 5.1 Post mortem structure

1. **Executive summary**: Impact, status, user actions required
2. **Timeline**: Slots, signatures, team response times
3. **Technical root cause**: Code path, missing invariant
4. **Indicators of compromise**: Program IDs, wallet clusters, domains
5. **Remediation**: Patches, parameter changes, monitoring rules
6. **Lessons learned**: Test gaps, audit scope misses

### 5.2 Corpus update

If the incident introduces a novel technique:

1. Add YAML entry under `attacks/`.
2. Cross-link related entries.
3. Run `python scripts/validate_corpus.py`.
4. Update TAXONOMY if new tactic or technique is warranted.

## Detection engineering checklist

Translate corpus `detection_queries` into production monitors:

- [ ] Real-time Geyser stream on SPL `Approve` / `SetAuthority` for treasury mints
- [ ] Program upgrade alerts for protocol allowlist
- [ ] Oracle deviation vs off-chain index
- [ ] Governance vote + flash loan pattern in same transaction
- [ ] NFT metadata authority changes for monitored collections
- [ ] New program deployments receiving user signatures within 24h of deploy

## Legal and coordination

- Coordinate with affected protocol security contact before public disclosure when actively exploited.
- Document chain of custody for evidence shared with law enforcement or exchanges.
- Freeze or label CEX deposits only through official exchange law enforcement channels.

## References

- Solana transaction format: https://docs.solana.com/developing/programming-model/transactions
- SPL Token program: https://spl.solana.com/token
- Solana security best practices: https://docs.solana.com/developing/on-chain-programs/developing-rust#security
- Corpus entries: `../attacks/`

## Methodology version

**1.0**: Initial release aligned with eight corpus entries. Future revisions will add MEV-specific flows, bridge compromise playbooks, and Token 2022 transfer hook abuse.
