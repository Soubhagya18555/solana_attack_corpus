# Solana Attack Taxonomy

Classification framework for the solana_attack_corpus. Aligns adversary behavior to **tactics** (why), **techniques** (how), and **attack surface** tags (where). Inspired by MITRE ATT&CK but specialized for Solana's account model, CPI semantics, and BPF loader architecture.

## Design principles

1. **Transaction atomicity**: Adversaries chain multiple instructions in one transaction; tactics may span inner instructions and CPI depth.
2. **Account-centric trust**: Most techniques exploit incorrect signer, writable, or owner checks on account metas.
3. **Program upgradeability**: Loader-level persistence is a first-class tactic, not an afterthought.
4. **Off-chain coupling**: Wallet phishing and fake airdrops are initial access vectors equal to on-chain logic bugs.

## Tactics

Tactics describe adversary objectives. Each corpus entry declares one primary `tactic`.

| Tactic ID | Definition | Solana-specific notes |
|-----------|------------|----------------------|
| `initial_access` | Obtain user signature or protocol foothold | Phishing sites, fake airdrops, malicious dApp connect |
| `execution` | Run attacker-controlled instructions on ledger | Direct invocation of drainer or exploit program |
| `persistence` | Maintain long-term control | Upgrade authority hijack, metadata updateAuthority capture |
| `privilege_escalation` | Gain capabilities beyond intended role | Mint authority abuse, governance vote inflation |
| `defense_evasion` | Avoid detection or bypass checks | CPI reentrancy, account substitution, simulation mismatch |
| `credential_access` | Steal signing capability or delegation | Unlimited Approve, session key abuse |
| `discovery` | Map vaults, oracles, admin PDAs | On-chain account enumeration (often prerequisite) |
| `lateral_movement` | Pivot across programs via CPI | Malicious CPI into victim with shared writable accounts |
| `collection` | Aggregate stolen assets | Sweeper bots consolidating ATAs |
| `impact` | Manipulate markets or drain value | Oracle manipulation, vault drain, NFT exfiltration |

### Tactic mapping for current corpus

| Entry ID | Primary tactic |
|----------|----------------|
| authority_drain | privilege_escalation |
| unlimited_approve | credential_access |
| cpi_reentrancy | defense_evasion |
| fake_airdrop | initial_access |
| program_upgrade_hijack | persistence |
| oracle_manipulation | impact |
| flash_loan_governance | privilege_escalation |
| nft_phishing_signature | initial_access |

## Techniques

Techniques are stable `technique` field values within the corpus. They may refine into sub-techniques in future schema versions.

| Technique ID | Description | Example entries |
|--------------|-------------|-----------------|
| `token_authority_abuse` | Exploit mint, freeze, or close authority misconfiguration | authority_drain |
| `delegate_approval_abuse` | Abuse SPL delegate to move funds without owner signer | unlimited_approve |
| `cpi_reentrancy` | Reenter victim logic while account state is inconsistent | cpi_reentrancy |
| `airdrop_lure` | Dust or fake tokens lure users to malicious claim | fake_airdrop |
| `bpf_loader_upgrade_abuse` | Replace program bytecode via upgrade authority | program_upgrade_hijack |
| `oracle_twap_distortion` | Move manipulable price feed within guard window | oracle_manipulation |
| `governance_flash_loan` | Temporarily inflate vote weight via flash liquidity | flash_loan_governance |
| `signature_phishing` | User signs harmful tx believing benign UI label | nft_phishing_signature |

## Attack surface tags

Optional `attack_surface` array on each entry. Used for coverage matrices in audits.

| Tag | Scope |
|-----|-------|
| `instruction_handler` | Rust/Anchor entrypoint logic |
| `cpi_boundary` | Cross-program invocation trust boundaries |
| `account_validation` | Signer, owner, PDA bump, discriminator checks |
| `pda_derivation` | Seed collisions or stale seed constants |
| `upgrade_authority` | BPF loader upgrade signer |
| `token_authority` | SPL mint/freeze/delegate authorities |
| `oracle_feed` | Pyth, Switchboard, or bespoke spot price |
| `governance_vote` | DAO tallying and escrow semantics |
| `off_chain_signature` | User wallet signing workflow |
| `client_ui` | Wallet or dApp presentation layer |
| `rpc_simulation_gap` | Difference between simulate and execute |

## Severity rubric

| Level | Criteria |
|-------|----------|
| **critical** | Direct fund loss, unlimited mint, or full program logic compromise at scale |
| **high** | Significant asset risk or widespread phishing with proven drainers |
| **medium** | Conditional exploit requiring uncommon config or moderate capital |
| **low** | Information disclosure or griefing with limited financial impact |
| **informational** | Educational pattern without demonstrated mainnet harm |

Severity reflects **maximum plausible impact** against an unmitigated deployment, not historical dollar loss.

## Program role taxonomy

`affected_programs[].role` standardizes how each pubkey participates:

| Role | Meaning |
|------|---------|
| victim | Protocol or user asset directly harmed |
| attacker_controlled | Drainer, exploit, or phishing program |
| dependency | DEX, router, or infra invoked in attack path |
| oracle | Price or external data feed |
| token_program | SPL Token or Token 2022 |
| system_program | Native System Program |
| loader | BPF Loader or Upgradeable Loader |
| governance | DAO or Realms program |
| nft_marketplace | Listing or auction program |
| lending | Lending / flash loan protocol |
| bridge | Cross-chain bridge program |
| other | Does not fit above |

## Indicator classes

### On-chain indicators

Observable without user cooperation: instruction logs, account state diffs, graph clustering on signers and fee payers.

### Off-chain indicators

Domains, social engineering scripts, wallet pop-up text, fake brand assets.

### Account layout indicators

Suspicious ordering of account metas, missing expected protocol accounts, writable flags on authority accounts.

### Instruction discriminators

Anchor 8-byte SHA256 prefixes or SPL opcodes that fingerprint malicious flows in indexers.

## Detection query convention

`detection_queries` use pseudocode meant for translation into:

- Geyser plugins and custom indexers
- SQL over decoded instruction tables
- SIEM correlation rules

Example: `Approve.amount == MAX_U64 AND delegate NOT IN known_routers`

## Extending the taxonomy

When adding entries:

1. Prefer an existing tactic; propose new tactics only for novel adversary goals.
2. Add a new `technique` slug only when mechanism differs materially from existing techniques.
3. Tag all applicable `attack_surface` values for audit coverage tracking.
4. Link bidirectional `related_entries` for attack chains (e.g. fake_airdrop → unlimited_approve).

## Versioning

Taxonomy version **1.0** ships with the initial eight entries. Schema evolution will use optional fields to preserve backward compatibility with validated YAML files.
