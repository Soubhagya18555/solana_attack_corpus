# solana_attack_corpus

Structured knowledge base of Solana on-chain attack techniques, incident patterns, and forensic indicators. Modeled after MITRE ATT&CK: each entry maps tactics, techniques, observable indicators, reproduction lab notes, and mitigations for defenders, auditors, and investigators.

**Author:** Soubhagya  
**License:** MIT  
**Chain focus:** Solana mainnet and devnet program semantics (BPF, SPL Token, Metaplex, governance)

## Purpose

This corpus supports:

- **Threat modeling** for Anchor and native Rust programs before deployment
- **Detection engineering** for indexers, wallet sandboxes, and runtime monitors
- **Incident response** triage when correlating transaction graphs and account state diffs
- **Security research** with reproducible, schema-validated entries

All reproduction guidance targets **local validators and devnet** only. Entries document public incidents and well-known vulnerability classes; they do not provide operational exploit kits.

## Repository layout

```
solana_attack_corpus/
├── README.md                 # This index
├── LICENSE                   # MIT
├── .gitignore
├── schema/
│   └── attack_entry.schema.json
├── attacks/                  # One YAML file per technique (filename == id)
│   ├── authority_drain.yaml
│   ├── unlimited_approve.yaml
│   ├── cpi_reentrancy.yaml
│   ├── fake_airdrop.yaml
│   ├── program_upgrade_hijack.yaml
│   ├── oracle_manipulation.yaml
│   ├── flash_loan_governance.yaml
│   └── nft_phishing_signature.yaml
├── scripts/
│   └── validate_corpus.py
└── docs/
    ├── TAXONOMY.md           # ATT&CK-style classification
    └── METHODOLOGY.md        # Forensic investigation playbook
```

## Quick start

### Validate the corpus

```bash
pip install pyyaml jsonschema
python scripts/validate_corpus.py --verbose
```

### Add a new entry

1. Copy an existing file in `attacks/` and assign a unique `id` (snake_case).
2. Rename the file to `{id}.yaml`.
3. Fill all required schema fields (see `schema/attack_entry.schema.json`).
4. Cross-link `related_entries` to existing ids.
5. Run `python scripts/validate_corpus.py`.

## Attack index

| ID | Title | Severity | Primary tactic | Key programs |
|----|-------|----------|----------------|--------------|
| [authority_drain](attacks/authority_drain.yaml) | SPL Token Mint or Freeze Authority Drain | critical | privilege_escalation | `TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA` |
| [unlimited_approve](attacks/unlimited_approve.yaml) | Unlimited SPL Token Delegate Approval Drain | critical | credential_access | `TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA` |
| [cpi_reentrancy](attacks/cpi_reentrancy.yaml) | CPI Reentrancy via Shared Account Mutation | critical | defense_evasion | `4ryvWnLkVcrfs8DTFbEMgTMqDcqj9iqMqACbTdwNLpug` (Cashio) |
| [fake_airdrop](attacks/fake_airdrop.yaml) | Fake Token Airdrop with Malicious Claim Contract | high | initial_access | `TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA` |
| [program_upgrade_hijack](attacks/program_upgrade_hijack.yaml) | Upgradable Program Authority Hijack | critical | persistence | `BPFLoaderUpgradeab1e11111111111111111111111` |
| [oracle_manipulation](attacks/oracle_manipulation.yaml) | Oracle Price Manipulation via Thin Liquidity | critical | impact | `4MangoMjqJ2firMokCjjGgoK8sd4tpVLo1EFyu6v9` |
| [flash_loan_governance](attacks/flash_loan_governance.yaml) | Flash Loan Governance Vote Manipulation | critical | privilege_escalation | `So1endDq2YkqhipRh3bAQrvHpuBGbfGasCA8DLMCaou` |
| [nft_phishing_signature](attacks/nft_phishing_signature.yaml) | NFT Marketplace Phishing via Blind Signing | high | initial_access | `M2mx93ekt1fmXSVkTrUL9xVFHkmME8HTUi5Cyc5aF7K` |

## Schema overview

Each attack entry is a YAML document validated against `attack_entry.schema.json`.

| Field | Description |
|-------|-------------|
| `id` | Stable snake_case identifier; must match filename |
| `title` | Human-readable technique name |
| `severity` | critical \| high \| medium \| low \| informational |
| `tactic` | High-level adversary goal (see [docs/TAXONOMY.md](docs/TAXONOMY.md)) |
| `technique` | Corpus-specific technique slug |
| `affected_programs` | List of `{ program_id, role, name?, notes? }` |
| `indicators` | `on_chain`, `off_chain`, optional `account_layout`, `instruction_discriminators` |
| `reproduction_notes` | Lab-only reproduction narrative (min 100 chars) |
| `mitigation` | Ordered defensive controls |
| `references` | Typed citations: post_mortem, audit, tx_signature, program_source, etc. |

Optional fields: `prerequisites`, `attack_surface`, `detection_queries`, `related_entries`, `tags`, `first_observed`, `chain`.

## Reference program IDs

Public, frequently cited Solana programs referenced across entries:

| Program | Base58 ID | Role |
|---------|-----------|------|
| System Program | `11111111111111111111111111111111` | Native transfers, account creation |
| SPL Token | `TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA` | Fungible token operations |
| Token 2022 | `TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb` | Extended token features |
| BPF Upgradeable Loader | `BPFLoaderUpgradeab1e11111111111111111111111` | Program upgrades |
| Metaplex Metadata | `metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s` | NFT metadata |
| Mango Markets v3 | `4MangoMjqJ2firMokCjjGgoK8sd4tpVLo1EFyu6v9` | Lending / perps (historical) |
| Magic Eden v2 | `M2mx93ekt1fmXSVkTrUL9xVFHkmME8HTUi5Cyc5aF7K` | NFT marketplace |
| Jupiter v6 | `JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4` | Swap aggregation |
| Pyth Oracle | `FsJ3A3u2vn5cTVofAjvy6y5kwABJAqYWpe4975bi2epH` | Price feeds |

## Documentation

- **[TAXONOMY.md](docs/TAXONOMY.md)**: Tactics, techniques, attack surface tags, severity rubric
- **[METHODOLOGY.md](docs/METHODOLOGY.md)**: End-to-end forensic methodology for Solana incidents

## Contributing

1. Ground entries in public post mortems, audits, or reproducible lab findings.
2. Use real program IDs when documenting known incidents; mark speculative fields in `notes`.
3. No hyphens in new filenames (underscores only).
4. Run validation before opening a pull request.

## Disclaimer

This corpus is for defensive security research and education. Techniques describe historical and architectural risk classes on Solana. The maintainer does not encourage unauthorized access to systems or funds.
